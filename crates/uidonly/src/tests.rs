//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::collections::VecDeque;
use std::io;
use std::num::{NonZeroU32, NonZeroUsize};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

use super::*;

#[derive(Debug)]
struct ScriptedIo {
    read_bytes: Vec<u8>,
    read_position: usize,
    chunk_plan: VecDeque<usize>,
    pending_plan: VecDeque<bool>,
    inject_pending: bool,
    pending_next: bool,
    stall_at_eof: bool,
    stall_writes: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
    observed_read_position: Arc<AtomicUsize>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl ScriptedIo {
    fn new(read_bytes: Vec<u8>) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                read_bytes,
                read_position: 0,
                chunk_plan: VecDeque::new(),
                pending_plan: VecDeque::new(),
                inject_pending: false,
                pending_next: false,
                stall_at_eof: false,
                stall_writes: Arc::new(AtomicBool::new(false)),
                dropped: Arc::new(AtomicBool::new(false)),
                observed_read_position: Arc::new(AtomicUsize::new(0)),
                written: Arc::clone(&written),
            },
            written,
        )
    }

    fn with_plan(mut self, plan: impl IntoIterator<Item = usize>) -> Self {
        self.chunk_plan = plan.into_iter().collect();
        self
    }

    fn with_pending(mut self) -> Self {
        self.inject_pending = true;
        self.pending_next = true;
        self
    }

    fn with_pending_plan(mut self, plan: impl IntoIterator<Item = bool>) -> Self {
        self.pending_plan = plan.into_iter().collect();
        self
    }

    fn with_stalled_eof(mut self) -> Self {
        self.stall_at_eof = true;
        self
    }

    fn read_position_observer(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.observed_read_position)
    }

    fn drop_observer(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.dropped)
    }

    fn write_stall_control(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stall_writes)
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending_plan.pop_front().unwrap_or(false) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.inject_pending && self.pending_next {
            self.pending_next = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.pending_next = self.inject_pending;

        if self.read_position == self.read_bytes.len() {
            if self.stall_at_eof {
                return Poll::Pending;
            }
            return Poll::Ready(Ok(()));
        }
        let planned = self.chunk_plan.pop_front().unwrap_or(usize::MAX);
        let count = planned
            .min(output.remaining())
            .min(self.read_bytes.len() - self.read_position);
        if count == 0 {
            return Poll::Ready(Err(io::Error::other("zero-length scripted read")));
        }
        let end = self.read_position + count;
        output.put_slice(&self.read_bytes[self.read_position..end]);
        self.read_position = end;
        self.observed_read_position
            .store(self.read_position, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stall_writes.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        self.written
            .lock()
            .expect("written mutex poisoned")
            .extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for ScriptedIo {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

fn fixture_with_after_enable(after_enable: &[u8]) -> Vec<u8> {
    let mut transcript =
        b"* OK synthetic ready\r\nA0001 OK LOGIN completed\r\n* ENABLED UIDONLY\r\nA0002 OK ENABLE completed\r\n"
            .to_vec();
    transcript.extend_from_slice(after_enable);
    transcript
}

async fn activated_session(
    transcript: Vec<u8>,
    adapter_limits: AdapterLimits,
    command_limits: CommandLimits,
) -> (
    UidOnlySession<ScriptedIo>,
    AdapterHandle,
    Arc<Mutex<Vec<u8>>>,
) {
    let (io, written) = ScriptedIo::new(transcript);
    activate_io(io, written, adapter_limits, command_limits).await
}

async fn activate_io(
    io: ScriptedIo,
    written: Arc<Mutex<Vec<u8>>>,
    adapter_limits: AdapterLimits,
    command_limits: CommandLimits,
) -> (
    UidOnlySession<ScriptedIo>,
    AdapterHandle,
    Arc<Mutex<Vec<u8>>>,
) {
    let (adapter, handle) = UidOnlyAdapter::new(io, adapter_limits).unwrap();
    let mut client = async_imap::Client::new(adapter);
    let greeting = client.read_response().await.unwrap().unwrap();
    assert!(matches!(
        greeting.parsed(),
        Response::Data {
            status: Status::Ok,
            ..
        }
    ));
    let session = client
        .login("synthetic-user", "synthetic-password")
        .await
        .unwrap();
    let session = UidOnlySession::enable(session, handle.clone(), command_limits)
        .await
        .unwrap();
    assert!(handle.is_active());
    assert_eq!(handle.provenance_len(), 0);
    (session, handle, written)
}

fn nz(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("test value is nonzero")
}

#[tokio::test]
async fn coalesced_enable_and_uidfetch_preserve_provenance() {
    let transcript = fixture_with_after_enable(
        b"* 42 uIdFeTcH (UID 42 FLAGS (\\Seen))\r\nA0003 OK NOOP completed\r\n",
    );
    let (session, handle, written) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;

    let (_session, notifications) = session.noop().await.unwrap();
    assert_eq!(
        notifications,
        vec![Notification::Flags {
            uid: nz(42),
            flags: vec!["\\Seen".to_string()],
        }]
    );
    assert_eq!(handle.poison_reason(), None);
    let written =
        String::from_utf8(written.lock().expect("written mutex poisoned").clone()).unwrap();
    assert!(written.contains("A0002 ENABLE UIDONLY\r\n"));
    assert!(written.contains("A0003 NOOP\r\n"));
}

#[tokio::test]
async fn examine_returns_fixed_read_only_snapshot_including_empty_mailbox() {
    let transcript = fixture_with_after_enable(
        b"* FLAGS (\\Seen)\r\n* 0 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 42]\r\n* OK [UIDNEXT 1]\r\nA0003 OK [READ-ONLY] EXAMINE completed\r\n",
    );
    let (session, _, _) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;

    let (_session, snapshot) = session.examine("INBOX").await.unwrap();
    assert_eq!(
        snapshot,
        MailboxSnapshot {
            exists: 0,
            uid_validity: nz(42),
            uid_next: nz(1),
            snapshot_high_uid: None,
            notifications: vec![Notification::Recent(0)],
        }
    );
}

#[tokio::test]
async fn examine_rejects_ambiguous_snapshot_identity() {
    for (response, expected) in [
        (
            b"* 0 EXISTS\r\n* 1 EXISTS\r\n* OK [UIDVALIDITY 42]\r\n* OK [UIDNEXT 1]\r\nA0003 OK [READ-ONLY] EXAMINE completed\r\n"
                .as_slice(),
            "more than one EXISTS",
        ),
        (
            b"* 0 EXISTS\r\n* OK [UIDVALIDITY 42]\r\n* OK [UIDVALIDITY 43]\r\n* OK [UIDNEXT 1]\r\nA0003 OK [READ-ONLY] EXAMINE completed\r\n"
                .as_slice(),
            "more than one UIDVALIDITY",
        ),
        (
            b"* 0 EXISTS\r\n* OK [UIDVALIDITY 42]\r\n* OK [UIDNEXT 1]\r\n* OK [UIDNEXT 2]\r\nA0003 OK [READ-ONLY] EXAMINE completed\r\n"
                .as_slice(),
            "more than one UIDNEXT",
        ),
        (
            b"* 1 EXISTS\r\n* OK [UIDVALIDITY 42]\r\n* OK [UIDNEXT 1]\r\nA0003 OK [READ-ONLY] EXAMINE completed\r\n"
                .as_slice(),
            "inconsistent with UIDNEXT",
        ),
    ] {
        let transcript = fixture_with_after_enable(response);
        let (session, _, _) = activated_session(
            transcript,
            AdapterLimits::default(),
            CommandLimits::default(),
        )
        .await;
        let error = session.examine("INBOX").await.unwrap_err();
        assert!(error.to_string().contains(expected));
    }
}

#[tokio::test]
async fn enable_without_exact_enabled_uidonly_fails_closed() {
    let transcript =
        b"* OK synthetic ready\r\nA0001 OK LOGIN completed\r\nA0002 OK ENABLE completed\r\n"
            .to_vec();
    let (io, _) = ScriptedIo::new(transcript);
    let (adapter, handle) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
    let mut client = async_imap::Client::new(adapter);
    client.read_response().await.unwrap().unwrap();
    let session = client.login("user", "pass").await.unwrap();

    let error = UidOnlySession::enable(session, handle.clone(), CommandLimits::default())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("without ENABLED UIDONLY"));
    assert!(!handle.is_active());

    let transcript = fixture_with_after_enable(b"");
    let (io, _) = ScriptedIo::new(transcript);
    let (adapter, handle) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
    let mut client = async_imap::Client::new(adapter);
    client.read_response().await.unwrap().unwrap();
    let session = client.login("user", "pass").await.unwrap();
    let limits = CommandLimits {
        max_wire_bytes: NonZeroUsize::new(45).unwrap(),
        ..CommandLimits::default()
    };
    let error = UidOnlySession::enable(session, handle, limits)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("wire bytes"));
}

#[tokio::test]
async fn uidfetch_before_matching_enable_completion_fails_closed() {
    let transcript =
        b"* OK synthetic ready\r\nA0001 OK LOGIN completed\r\n* ENABLED UIDONLY\r\n* 7 UIDFETCH (FLAGS ())\r\nA0002 OK ENABLE completed\r\n"
            .to_vec();
    let (io, _) = ScriptedIo::new(transcript);
    let (adapter, handle) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
    let mut client = async_imap::Client::new(adapter);
    client.read_response().await.unwrap().unwrap();
    let session = client.login("user", "pass").await.unwrap();

    let error = UidOnlySession::enable(session, handle.clone(), CommandLimits::default())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("before UIDONLY activation"));
    assert!(!handle.is_active());
}

#[tokio::test]
async fn literal_bytes_survive_fragmentation_pending_and_tiny_output_buffers() {
    let body = b"line 1\r\n* 777 UIDFETCH (UID 777)\r\n{999}\r\nline 4";
    let mut active = format!("* 42 UIDFETCH (UID 42 BODY[] {{{}}}\r\n", body.len()).into_bytes();
    active.extend_from_slice(body);
    active.extend_from_slice(b")\r\n");
    let transcript = b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n"
        .iter()
        .copied()
        .chain(active.iter().copied())
        .collect::<Vec<_>>();
    let expected = transcript
        .windows(8)
        .position(|window| window.eq_ignore_ascii_case(b"UIDFETCH"))
        .map(|start| {
            let mut bytes = transcript.clone();
            bytes.splice(start..start + 8, b"FETCH".iter().copied());
            bytes
        })
        .unwrap();

    for split in 1..transcript.len() {
        for output_size in 1..=8 {
            let (io, _) = ScriptedIo::new(transcript.clone());
            let io = io
                .with_plan([split, transcript.len() - split])
                .with_pending();
            let (mut adapter, handle) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
            handle.arm_enable(&RequestId("A0009".to_string())).unwrap();

            let mut observed = Vec::new();
            let mut output = vec![0_u8; output_size];
            loop {
                let read = adapter.read(&mut output).await.unwrap();
                if read == 0 {
                    break;
                }
                observed.extend_from_slice(&output[..read]);
            }
            assert_eq!(observed, expected, "split={split}, output={output_size}");
            assert!(matches!(
                handle.take_provenance(),
                Some(Provenance::TranslatedUidFetch {
                    leading_uid: 42,
                    wire_bytes,
                }) if wire_bytes > body.len()
            ));
            let marker = format!("{{{}}}\r\n", body.len());
            let literal_start = observed
                .windows(marker.len())
                .position(|window| window == marker.as_bytes())
                .unwrap()
                + marker.len();
            assert_eq!(&observed[literal_start..literal_start + body.len()], body);
        }
    }
}

#[tokio::test]
async fn ordinary_pass_through_frames_non_fetch_literals_byte_for_byte() {
    let payload = vec![b'x'; 70_000];
    let mut transcript = format!("* LIST () \"/\" {{{}}}\r\n", payload.len()).into_bytes();
    transcript.extend_from_slice(&payload);
    transcript.extend_from_slice(b"\r\nA0001 OK LIST completed\r\n");
    let (io, _) = ScriptedIo::new(transcript.clone());
    let (mut adapter, _) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
    let mut observed = Vec::new();
    adapter.read_to_end(&mut observed).await.unwrap();
    assert_eq!(observed, transcript);

    let status = b"* OK synthetic status {5}\r\n".to_vec();
    let (io, _) = ScriptedIo::new(status.clone());
    let (mut adapter, _) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
    let mut observed = Vec::new();
    adapter.read_to_end(&mut observed).await.unwrap();
    assert_eq!(observed, status);
}

#[tokio::test]
async fn multi_literal_and_randomized_pending_fragmentation_preserve_bytes() {
    let transcript = b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n* 42 UIDFETCH (UID 42 BODY[1] {3}\r\nabc BODY[2] {3}\r\ndef)\r\n"
        .to_vec();
    let expected = b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n* 42 FETCH (UID 42 BODY[1] {3}\r\nabc BODY[2] {3}\r\ndef)\r\n";

    let mut plans = vec![(
        vec![1; transcript.len()],
        (0..transcript.len() * 2)
            .map(|index| index % 2 == 0)
            .collect(),
    )];
    for seed in 1..=64_u64 {
        let mut state = seed;
        let mut remaining = transcript.len();
        let mut chunks = Vec::new();
        while remaining > 0 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let chunk = ((state >> 32) as usize % 17 + 1).min(remaining);
            chunks.push(chunk);
            remaining -= chunk;
        }
        let mut pending = Vec::with_capacity(chunks.len() * 3);
        for _ in 0..chunks.len() * 3 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            pending.push((state >> 63) != 0);
        }
        plans.push((chunks, pending));
    }

    for (case, (chunks, pending)) in plans.into_iter().enumerate() {
        let (io, _) = ScriptedIo::new(transcript.clone());
        let io = io.with_plan(chunks).with_pending_plan(pending);
        let (mut adapter, handle) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
        handle.arm_enable(&RequestId("A0009".to_string())).unwrap();
        let output_size = case % 32 + 1;
        let mut output = vec![0_u8; output_size];
        let mut observed = Vec::new();
        loop {
            let read = adapter.read(&mut output).await.unwrap();
            if read == 0 {
                break;
            }
            observed.extend_from_slice(&output[..read]);
        }
        assert_eq!(observed, expected, "randomized case {case}");
        assert!(matches!(
            handle.take_provenance(),
            Some(Provenance::TranslatedUidFetch {
                leading_uid: 42,
                ..
            })
        ));
    }
}

#[tokio::test]
async fn raw_fetch_after_activation_is_rejected() {
    let transcript =
        fixture_with_after_enable(b"* 42 FETCH (UID 42 FLAGS ())\r\nA0003 OK NOOP\r\n");
    let (session, handle, _) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;
    let error = session.noop().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "UIDONLY IMAP response read or parse failed"
    );
    assert!(handle
        .poison_reason()
        .is_some_and(|reason| reason.contains("raw FETCH")));
}

#[tokio::test]
async fn provenance_is_visible_before_response_and_queue_backpressures() {
    let transcript = b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n* 1 UIDFETCH (FLAGS ())\r\n* 2 UIDFETCH (FLAGS ())\r\n".to_vec();
    let (io, _) = ScriptedIo::new(transcript);
    let limits = AdapterLimits {
        provenance_capacity: NonZeroUsize::new(1).unwrap(),
        ..AdapterLimits::default()
    };
    let (mut adapter, handle) = UidOnlyAdapter::new(io, limits).unwrap();
    handle.arm_enable(&RequestId("A0009".to_string())).unwrap();

    let prefix_len = b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n".len();
    let mut prefix = vec![0_u8; prefix_len];
    adapter.read_exact(&mut prefix).await.unwrap();
    assert!(handle.is_active());

    let first_line = b"* 1 FETCH (FLAGS ())\r\n";
    let mut first = vec![0_u8; first_line.len()];
    adapter.read_exact(&mut first[..1]).await.unwrap();
    assert_eq!(handle.provenance_len(), 1);
    adapter.read_exact(&mut first[1..]).await.unwrap();
    assert_eq!(first, first_line);

    let mut next_byte = [0_u8; 1];
    assert!(
        timeout(Duration::from_millis(20), adapter.read(&mut next_byte))
            .await
            .is_err()
    );
    assert!(matches!(
        handle.take_provenance(),
        Some(Provenance::TranslatedUidFetch { leading_uid: 1, .. })
    ));
    let mut second = vec![0_u8; b"* 2 FETCH (FLAGS ())\r\n".len()];
    adapter.read_exact(&mut second).await.unwrap();
    assert_eq!(second, b"* 2 FETCH (FLAGS ())\r\n");
}

#[tokio::test]
async fn full_provenance_queue_stops_transport_reads() {
    let mut transcript = b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n".to_vec();
    for uid in 1..=5_000_u32 {
        transcript.extend_from_slice(format!("* {uid} UIDFETCH (FLAGS ())\r\n").as_bytes());
    }
    let (io, _) = ScriptedIo::new(transcript);
    let read_position = io.read_position_observer();
    let limits = AdapterLimits {
        provenance_capacity: NonZeroUsize::new(1).unwrap(),
        ..AdapterLimits::default()
    };
    let (mut adapter, handle) = UidOnlyAdapter::new(io, limits).unwrap();
    handle.arm_enable(&RequestId("A0009".to_string())).unwrap();

    let prefix = b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n";
    let mut observed_prefix = vec![0_u8; prefix.len()];
    adapter.read_exact(&mut observed_prefix).await.unwrap();
    let first_line = b"* 1 FETCH (FLAGS ())\r\n";
    let mut first = vec![0_u8; first_line.len()];
    adapter.read_exact(&mut first).await.unwrap();
    let before = read_position.load(Ordering::SeqCst);

    let mut byte = [0_u8; 1];
    assert!(timeout(Duration::from_millis(20), adapter.read(&mut byte))
        .await
        .is_err());
    assert_eq!(read_position.load(Ordering::SeqCst), before);
    assert!(handle.take_provenance().is_some());
}

#[tokio::test]
async fn oversized_or_over_budget_literal_marker_is_never_forwarded() {
    for (limits, expected) in [
        (
            AdapterLimits {
                max_literal_bytes: NonZeroUsize::new(1_024).unwrap(),
                ..AdapterLimits::default()
            },
            "literal exceeds configured byte limit",
        ),
        (
            AdapterLimits {
                max_control_line_bytes: NonZeroUsize::new(128).unwrap(),
                max_literal_bytes: NonZeroUsize::new(1_024).unwrap(),
                max_response_bytes: NonZeroUsize::new(256).unwrap(),
                ..AdapterLimits::default()
            },
            "announced literal exceeds remaining response budget",
        ),
    ] {
        let marker = if expected.starts_with("literal exceeds") {
            2_048
        } else {
            512
        };
        let transcript = format!(
            "* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n* 42 UIDFETCH (UID 42 BODY[] {{{marker}}}\r\nbody"
        )
        .into_bytes();
        let (io, _) = ScriptedIo::new(transcript);
        let (mut adapter, handle) = UidOnlyAdapter::new(io, limits).unwrap();
        handle.arm_enable(&RequestId("A0009".to_string())).unwrap();

        let mut observed = Vec::new();
        let error = adapter.read_to_end(&mut observed).await.unwrap_err();
        assert!(error.to_string().contains(expected));
        let marker = format!("{{{marker}}}\r\n");
        assert!(!observed
            .windows(marker.len())
            .any(|window| window == marker.as_bytes()));
    }
}

#[tokio::test]
async fn unsupported_and_overflowing_active_literal_markers_fail_before_forwarding() {
    for marker in ["{1+}", "~{1}", "{999999999999999999999999999999999999}"] {
        let transcript = format!(
            "* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n* 42 UIDFETCH (UID 42 BODY[] {marker}\r\nx)"
        )
        .into_bytes();
        let (io, _) = ScriptedIo::new(transcript);
        let (mut adapter, handle) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
        handle.arm_enable(&RequestId("A0009".to_string())).unwrap();
        let mut observed = Vec::new();
        let error = adapter.read_to_end(&mut observed).await.unwrap_err();
        assert!(
            error.to_string().contains("literal"),
            "marker={marker}, error={error}"
        );
        assert!(!observed
            .windows(marker.len())
            .any(|bytes| bytes == marker.as_bytes()));
    }
}

#[tokio::test]
async fn truncated_literal_long_line_and_ambiguous_brace_text_fail_closed() {
    let cases = [
        (
            b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n* 42 UIDFETCH (UID 42 BODY[] {5}\r\nno"
                .to_vec(),
            AdapterLimits::default(),
            "truncated IMAP response",
            io::ErrorKind::UnexpectedEof,
        ),
        (
            {
                let mut bytes =
                    b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n* OK ".to_vec();
                bytes.extend(std::iter::repeat_n(b'x', 128));
                bytes.extend_from_slice(b"\r\n");
                bytes
            },
            AdapterLimits {
                max_control_line_bytes: NonZeroUsize::new(64).unwrap(),
                ..AdapterLimits::default()
            },
            "control line exceeds configured byte limit",
            io::ErrorKind::InvalidData,
        ),
        (
            b"* ENABLED UIDONLY\r\nA0009 OK ENABLE completed\r\n* OK status {5}\r\nabcde"
                .to_vec(),
            AdapterLimits::default(),
            "outside an active UIDFETCH",
            io::ErrorKind::InvalidData,
        ),
    ];
    for (transcript, limits, expected, expected_kind) in cases {
        let (io, _) = ScriptedIo::new(transcript);
        let (mut adapter, handle) = UidOnlyAdapter::new(io, limits).unwrap();
        handle.arm_enable(&RequestId("A0009".to_string())).unwrap();
        let error = adapter.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert!(error.to_string().contains(expected));
        assert_eq!(error.kind(), expected_kind);
    }
}

#[tokio::test]
async fn bounded_inventory_returns_complete_metadata_and_ignores_flags_event() {
    let transcript = fixture_with_after_enable(
        b"* 5 UIDFETCH (UID 5 FLAGS (\\Seen))\r\n* 7 UIDFETCH (UID 7 RFC822.SIZE 10 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\")\r\nA0003 OK FETCH completed\r\n",
    );
    let (session, _, written) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;
    let request = InventoryRequest {
        start: nz(1),
        end: nz(10),
        page_size: nz(10),
    };
    let (_session, page) = session.inventory(request).await.unwrap();
    assert_eq!(
        page.items,
        vec![InventoryItem {
            uid: nz(7),
            rfc822_size: 10,
            internal_date: "01-Jan-2020 00:00:00 +0000".to_string(),
        }]
    );
    assert_eq!(
        page.notifications,
        vec![Notification::Flags {
            uid: nz(5),
            flags: vec!["\\Seen".to_string()],
        }]
    );
    let written =
        String::from_utf8(written.lock().expect("written mutex poisoned").clone()).unwrap();
    assert!(
        written.contains("A0003 UID FETCH 1:10 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:10)\r\n")
    );
}

#[tokio::test]
async fn inventory_rejects_uid_mismatch_missing_items_and_overfull_page() {
    let cases = [
        (
            b"* 7 UIDFETCH (UID 8 RFC822.SIZE 1 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\")\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "leading and inner UID differ",
        ),
        (
            b"* 7 UIDFETCH (UID 7 RFC822.SIZE 1)\r\nA0003 OK FETCH completed\r\n".as_slice(),
            "exactly UID, RFC822.SIZE, and INTERNALDATE",
        ),
        (
            b"* 7 UIDFETCH (UID 7 RFC822.SIZE 1 internaldate nil)\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "INTERNALDATE NIL",
        ),
        (
            b"* 1 UIDFETCH (UID 1 RFC822.SIZE 1 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\")\r\n* 2 UIDFETCH (UID 2 RFC822.SIZE 1 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\")\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "more results than requested",
        ),
        (
            b"* 7 UIDFETCH (UID 7 RFC822.SIZE 1 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\" MODSEQ (9))\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "unrequested attribute",
        ),
        (
            b"* VANISHED 7\r\n* 7 UIDFETCH (UID 7 RFC822.SIZE 1 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\")\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "item and VANISHED",
        ),
    ];
    for (response, expected_adapter_invariant) in cases {
        let transcript = fixture_with_after_enable(response);
        let (session, _, _) = activated_session(
            transcript,
            AdapterLimits::default(),
            CommandLimits::default(),
        )
        .await;
        let error = session
            .inventory(InventoryRequest {
                start: nz(1),
                end: nz(10),
                page_size: nz(1),
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let surface = error.to_string();
        assert!(
            surface.contains(expected_adapter_invariant)
                || surface == "UIDONLY IMAP response read or parse failed",
            "unexpected safe error surface: {surface}"
        );
    }
}

#[tokio::test]
async fn exact_body_chunk_returns_literal_and_rejects_adjacent_uid_or_wrong_origin() {
    let raw = b"synthetic raw bytes\r\n";
    let transcript = fixture_with_after_enable(
        format!(
            "* 42 UIDFETCH (UID 42 RFC822.SIZE {} BODY[]<0> {{{}}}\r\n{})\r\nA0003 OK FETCH completed\r\n",
            raw.len(),
            raw.len(),
            String::from_utf8_lossy(raw)
        )
        .as_bytes(),
    );
    let (session, _, written) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;
    let (_session, result) = session
        .fetch_body_chunk(nz(42), 0, nz(1_024))
        .await
        .unwrap();
    assert_eq!(
        result,
        ExactFetchOutcome::Chunk(BodyChunk {
            uid: nz(42),
            rfc822_size: raw.len() as u32,
            offset: 0,
            bytes: raw.to_vec(),
            notifications: Vec::new(),
        })
    );
    let written =
        String::from_utf8(written.lock().expect("written mutex poisoned").clone()).unwrap();
    assert!(written.contains("A0003 UID FETCH 42 (UID RFC822.SIZE BODY.PEEK[]<0.1024>)\r\n"));

    for (response, expected) in [
        (
            b"* 43 UIDFETCH (UID 43 RFC822.SIZE 1 BODY[]<0> {1}\r\nx)\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "exact requested UID",
        ),
        (
            b"* 42 UIDFETCH (UID 42 RFC822.SIZE 1 BODY[]<1> {1}\r\nx)\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "origin does not match",
        ),
        (
            b"* 42 UIDFETCH (UID 42 RFC822.SIZE 1 BODY[] {1}\r\nx)\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "origin does not match",
        ),
        (
            b"* 42 UIDFETCH (UID 42 RFC822.SIZE 10 BODY[]<0> {0}\r\n)\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "literal length is inconsistent",
        ),
        (
            b"* 42 UIDFETCH (UID 42 RFC822.SIZE 1 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\" BODY[]<0> {1}\r\nx)\r\nA0003 OK FETCH completed\r\n"
                .as_slice(),
            "unrequested attribute",
        ),
    ] {
        let transcript = fixture_with_after_enable(response);
        let (session, _, _) = activated_session(
            transcript,
            AdapterLimits::default(),
            CommandLimits::default(),
        )
        .await;
        let error = session
            .fetch_body_chunk(nz(42), 0, nz(1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected));
    }
}

#[tokio::test]
async fn literal_meter_charges_body_octets_before_truncated_command_completion() {
    let raw = b"received before eof";
    let transcript = fixture_with_after_enable(
        format!(
            "* 42 UIDFETCH (UID 42 RFC822.SIZE {} BODY[]<0> {{{}}}\r\n{})\r\n",
            raw.len(),
            raw.len(),
            String::from_utf8_lossy(raw)
        )
        .as_bytes(),
    );
    let (session, handle, _) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;
    let before = handle.literal_bytes_received();
    let error = session
        .fetch_body_chunk(nz(42), 0, nz(raw.len() as u32))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(handle.literal_bytes_received() - before, raw.len() as u64);
}

#[tokio::test]
async fn parser_failures_do_not_echo_literal_bytes() {
    let transcript = fixture_with_after_enable(
        b"* 42 UIDFETCH (UID 42 RFC822.SIZE 6 BODY[]<0> {6}\r\nSECRET BROKEN\r\n",
    );
    let (session, _, _) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;
    let error = session
        .fetch_body_chunk(nz(42), 0, nz(6))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "UIDONLY IMAP response read or parse failed"
    );
    assert!(!error.to_string().contains("SECRET"));
}

#[tokio::test]
async fn exact_body_fetch_distinguishes_missing_and_vanished() {
    for (response, expected_vanished) in [
        (b"A0003 OK FETCH completed\r\n".as_slice(), false),
        (
            b"* VANISHED 42\r\nA0003 OK FETCH completed\r\n".as_slice(),
            true,
        ),
    ] {
        let transcript = fixture_with_after_enable(response);
        let (session, _, _) = activated_session(
            transcript,
            AdapterLimits::default(),
            CommandLimits::default(),
        )
        .await;
        let (_session, outcome) = session.fetch_body_chunk(nz(42), 0, nz(1)).await.unwrap();
        assert_eq!(
            matches!(outcome, ExactFetchOutcome::Vanished { .. }),
            expected_vanished
        );
        assert_eq!(
            matches!(outcome, ExactFetchOutcome::Missing { .. }),
            !expected_vanished
        );
    }
}

#[tokio::test]
async fn cancellation_timeout_and_resource_budgets_drop_connection_owner() {
    let transcript = fixture_with_after_enable(b"");
    let (io, _) = ScriptedIo::new(transcript);
    let stall_writes = io.write_stall_control();
    let dropped = io.drop_observer();
    let (adapter, handle) = UidOnlyAdapter::new(io, AdapterLimits::default()).unwrap();
    let mut client = async_imap::Client::new(adapter);
    client.read_response().await.unwrap().unwrap();
    let ordinary = client.login("user", "pass").await.unwrap();
    stall_writes.store(true, Ordering::SeqCst);
    let limits = CommandLimits {
        timeout: Duration::from_millis(20),
        ..CommandLimits::default()
    };
    let error = UidOnlySession::enable(ordinary, handle, limits)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(dropped.load(Ordering::SeqCst));

    let transcript = fixture_with_after_enable(b"");
    let (io, written) = ScriptedIo::new(transcript);
    let dropped = io.drop_observer();
    let io = io.with_stalled_eof();
    let limits = CommandLimits {
        timeout: Duration::from_millis(20),
        ..CommandLimits::default()
    };
    let (session, _, _) = activate_io(io, written, AdapterLimits::default(), limits).await;
    let error = session.noop().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(dropped.load(Ordering::SeqCst));

    let mut after_enable = Vec::new();
    for uid in 1..=4_u32 {
        after_enable.extend_from_slice(format!("* {uid} UIDFETCH (FLAGS ())\r\n").as_bytes());
    }
    let transcript = fixture_with_after_enable(&after_enable);
    let limits = CommandLimits {
        max_responses: NonZeroUsize::new(3).unwrap(),
        ..CommandLimits::default()
    };
    let (session, _, _) = activated_session(transcript, AdapterLimits::default(), limits).await;
    let error = session.noop().await.unwrap_err();
    assert!(error.to_string().contains("response count"));

    let transcript = fixture_with_after_enable(
        b"* 1 UIDFETCH (FLAGS ())\r\n* 2 UIDFETCH (FLAGS ())\r\nA0003 OK NOOP completed\r\n",
    );
    let limits = CommandLimits {
        max_events: NonZeroUsize::new(1).unwrap(),
        ..CommandLimits::default()
    };
    let (session, _, _) = activated_session(transcript, AdapterLimits::default(), limits).await;
    let error = session.noop().await.unwrap_err();
    assert!(error.to_string().contains("event count"));

    let transcript = fixture_with_after_enable(b"* VANISHED 1,3,5\r\nA0003 OK NOOP completed\r\n");
    let limits = CommandLimits {
        max_vanished_ranges: NonZeroUsize::new(2).unwrap(),
        ..CommandLimits::default()
    };
    let (session, _, _) = activated_session(transcript, AdapterLimits::default(), limits).await;
    let error = session.noop().await.unwrap_err();
    assert!(error.to_string().contains("VANISHED range count"));

    let transcript =
        fixture_with_after_enable(b"* OK 12345678901234567890\r\nA0003 OK NOOP completed\r\n");
    let limits = CommandLimits {
        max_wire_bytes: NonZeroUsize::new(50).unwrap(),
        ..CommandLimits::default()
    };
    let (session, _, _) = activated_session(transcript, AdapterLimits::default(), limits).await;
    let error = session.noop().await.unwrap_err();
    assert!(error.to_string().contains("wire bytes"));
}

#[tokio::test]
async fn sequence_expunge_untagged_failure_and_unexpected_tag_fail_closed() {
    for (response, expected) in [
        (
            b"* 1 EXPUNGE\r\nA0003 OK NOOP completed\r\n".as_slice(),
            "sequence EXPUNGE",
        ),
        (
            b"* NO synthetic failure\r\nA0003 OK NOOP completed\r\n".as_slice(),
            "unexpected untagged status",
        ),
        (
            b"A0999 OK NOOP completed\r\n".as_slice(),
            "unexpected tagged",
        ),
        (
            b"* 1 UIDFETCH (UID 1 FLAGS () MODSEQ (9))\r\nA0003 OK NOOP completed\r\n".as_slice(),
            "flags allowlist",
        ),
    ] {
        let transcript = fixture_with_after_enable(response);
        let (session, _, _) = activated_session(
            transcript,
            AdapterLimits::default(),
            CommandLimits::default(),
        )
        .await;
        let error = session.noop().await.unwrap_err();
        assert!(error.to_string().contains(expected));
    }
}

#[tokio::test]
async fn logout_requires_bye_and_matching_completion() {
    let transcript = fixture_with_after_enable(b"* BYE logout\r\nA0003 OK LOGOUT completed\r\n");
    let (session, _, _) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;
    session.logout().await.unwrap();

    let transcript = fixture_with_after_enable(b"A0003 OK LOGOUT completed\r\n");
    let (session, _, _) = activated_session(
        transcript,
        AdapterLimits::default(),
        CommandLimits::default(),
    )
    .await;
    assert!(session
        .logout()
        .await
        .unwrap_err()
        .to_string()
        .contains("omitted BYE"));
}

#[test]
fn typed_command_builder_quotes_mailbox_and_rejects_injection() {
    let limits = CommandLimits::default();
    assert_eq!(
        UidOnlyCommand::Examine {
            encoded_mailbox: "Project \\\\ \"Archive\" &AMk-".to_string(),
        }
        .render(&limits)
        .unwrap(),
        "EXAMINE \"Project \\\\\\\\ \\\"Archive\\\" &AMk-\""
    );
    for invalid in [
        "bad\r\nNOOP",
        "bad\nNOOP",
        "bad\0name",
        "bad\tname",
        "收件箱",
    ] {
        assert!(UidOnlyCommand::Examine {
            encoded_mailbox: invalid.to_string(),
        }
        .render(&limits)
        .is_err());
    }
    let escaped_boundary = UidOnlyCommand::Examine {
        encoded_mailbox: "\\\\".to_string(),
    };
    let exact_limits = CommandLimits {
        max_mailbox_wire_bytes: NonZeroUsize::new(6).unwrap(),
        ..CommandLimits::default()
    };
    assert_eq!(
        escaped_boundary.render(&exact_limits).unwrap(),
        "EXAMINE \"\\\\\\\\\""
    );
    let too_small = CommandLimits {
        max_mailbox_wire_bytes: NonZeroUsize::new(5).unwrap(),
        ..CommandLimits::default()
    };
    assert!(escaped_boundary.render(&too_small).is_err());
    assert_eq!(
        UidOnlyCommand::Inventory(InventoryRequest {
            start: nz(1),
            end: nz(50_000),
            page_size: nz(1_000),
        })
        .render(&limits)
        .unwrap(),
        "UID FETCH 1:50000 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:1000)"
    );
    assert_eq!(
        UidOnlyCommand::BodyChunk {
            uid: nz(42),
            offset: 1_024,
            count: nz(4_096),
        }
        .render(&limits)
        .unwrap(),
        "UID FETCH 42 (UID RFC822.SIZE BODY.PEEK[]<1024.4096>)"
    );
}

fn inventory_page(request: InventoryRequest, uids: &[u32]) -> InventoryPage {
    InventoryPage {
        request,
        items: uids
            .iter()
            .map(|uid| InventoryItem {
                uid: nz(*uid),
                rfc822_size: *uid,
                internal_date: "01-Jan-2020 00:00:00 +0000".to_string(),
            })
            .collect(),
        notifications: Vec::new(),
    }
}

#[test]
fn sparse_inventory_planner_requires_commit_and_short_page_is_not_completion() {
    let mut planner = InventoryPlanner::new(Some(nz(4_000_000_000)), nz(1_000), Some(nz(3)));
    let first = planner.next_request().unwrap();
    assert_eq!(first.page_size, nz(3));
    let validated = planner
        .validate_page(inventory_page(first, &[2_000_000_001, 3_000_000_000]))
        .unwrap();
    assert!(!validated.completes_inventory());
    assert_eq!(
        planner.next_request(),
        Some(first),
        "validation alone must not advance the cursor"
    );
    planner.commit_page(validated).unwrap();
    let second = planner.next_request().unwrap();
    assert_eq!(second.start, nz(3_000_000_001));

    let terminal = planner.validate_page(inventory_page(second, &[])).unwrap();
    assert!(terminal.completes_inventory());
    planner.commit_page(terminal).unwrap();
    assert!(planner.is_complete());
    assert_eq!(planner.next_request(), None);
}

#[test]
fn inventory_planner_accepts_fixed_upper_boundary_and_rejects_stale_page() {
    let mut planner = InventoryPlanner::new(Some(nz(10)), nz(5), None);
    let request = planner.next_request().unwrap();
    let mut page = inventory_page(request, &[2, 10]);
    page.notifications.push(Notification::Vanished {
        earlier: false,
        uids: vec![3..=4],
    });
    let validated = planner.validate_page(page).unwrap();
    assert!(validated.completes_inventory());
    assert_eq!(validated.notifications().len(), 1);
    let stale = validated.clone();
    planner.commit_page(validated).unwrap();
    assert!(planner.commit_page(stale).is_err());
}

#[test]
fn verified_diff_is_linear_sparse_and_preserves_logical_duplicates_by_uid() {
    let remote = [nz(1), nz(7), nz(42), nz(4_000_000_000)];
    let local = [nz(1), nz(42)];
    assert_eq!(
        missing_verified_uids(&remote, &local).unwrap(),
        vec![nz(7), nz(4_000_000_000)]
    );
    assert!(missing_verified_uids(&[nz(2), nz(1)], &local).is_err());
    assert!(missing_verified_uids(&remote, &[nz(1), nz(1)]).is_err());
}

#[tokio::test]
async fn loopback_fake_server_observes_exact_read_only_command_order() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let commands = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&commands);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        writer.write_all(b"* OK synthetic ready\r\n").await.unwrap();
        loop {
            let mut line = String::new();
            if tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line)
                .await
                .unwrap()
                == 0
            {
                break;
            }
            let command = line.trim_end().to_string();
            observed.lock().unwrap().push(command.clone());
            let tag = command.split_whitespace().next().unwrap();
            let response = if command.contains(" LOGIN ") {
                format!("{tag} OK LOGIN completed\r\n")
            } else if command.contains(" ENABLE UIDONLY") {
                format!("* ENABLED UIDONLY\r\n{tag} OK ENABLE completed\r\n")
            } else if command.contains(" EXAMINE ") {
                format!(
                    "* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 42]\r\n* OK [UIDNEXT 8]\r\n{tag} OK [READ-ONLY] EXAMINE completed\r\n"
                )
            } else if command.contains("UID FETCH 1:7") {
                format!(
                    "* 7 UIDFETCH (UID 7 RFC822.SIZE 5 INTERNALDATE \"01-Jan-2020 00:00:00 +0000\")\r\n{tag} OK FETCH completed\r\n"
                )
            } else if command.contains("UID FETCH 7 ") {
                format!(
                    "* 7 UIDFETCH (UID 7 RFC822.SIZE 5 BODY[]<0> {{5}}\r\nhello)\r\n{tag} OK FETCH completed\r\n"
                )
            } else if command.contains(" LOGOUT") {
                format!("* BYE logout\r\n{tag} OK LOGOUT completed\r\n")
            } else {
                panic!("unexpected command: {command}");
            };
            writer.write_all(response.as_bytes()).await.unwrap();
            if command.contains(" LOGOUT") {
                break;
            }
        }
    });

    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (adapter, handle) = UidOnlyAdapter::new(stream, AdapterLimits::default()).unwrap();
    let mut client = async_imap::Client::new(adapter);
    client.read_response().await.unwrap().unwrap();
    let session = client.login("user", "password").await.unwrap();
    let session = UidOnlySession::enable(session, handle, CommandLimits::default())
        .await
        .unwrap();
    let (session, snapshot) = session.examine("INBOX").await.unwrap();
    assert_eq!(snapshot.snapshot_high_uid, Some(nz(7)));
    let (session, page) = session
        .inventory(InventoryRequest {
            start: nz(1),
            end: nz(7),
            page_size: nz(1),
        })
        .await
        .unwrap();
    assert_eq!(page.items[0].uid, nz(7));
    let (session, body) = session.fetch_body_chunk(nz(7), 0, nz(5)).await.unwrap();
    assert!(matches!(
        body,
        ExactFetchOutcome::Chunk(BodyChunk { ref bytes, .. }) if bytes == b"hello"
    ));
    session.logout().await.unwrap();
    server.await.unwrap();

    let commands = commands.lock().unwrap();
    assert_eq!(commands.len(), 6);
    assert!(commands[0].contains(" LOGIN "));
    assert!(commands[1].contains(" ENABLE UIDONLY"));
    assert!(commands[2].contains(" EXAMINE "));
    assert!(commands[3].contains("UID FETCH 1:7"));
    assert!(commands[4].contains("UID FETCH 7 "));
    assert!(commands[5].contains(" LOGOUT"));
}
