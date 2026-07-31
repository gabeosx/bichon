//
// Copyright (c) 2025-2026 rustmailer.com (https://rustmailer.com)
//
// This file is part of the Bichon Email Archiving Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![deny(dead_code)]
#![forbid(unsafe_code)]

//! No-fork UIDONLY protocol compatibility and sparse inventory planning.
//!
//! The adapter must wrap the final transport before `async_imap::Client` is
//! constructed. After authentication, [`UidOnlySession::enable`] performs the
//! exact activation transition and consumes the ordinary session so callers
//! cannot use sequence-number helpers on an enabled connection.

use std::collections::VecDeque;
use std::io;
use std::num::{NonZeroU32, NonZeroUsize};
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::task::AtomicWaker;
use imap_proto::{AttributeValue, RequestId, Response, ResponseCode, Status};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const READ_CHUNK: usize = 8 * 1024;

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Resource ceilings enforced before bytes reach `imap-proto`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterLimits {
    pub max_input_bytes: NonZeroUsize,
    pub max_control_line_bytes: NonZeroUsize,
    pub max_literal_bytes: NonZeroUsize,
    pub max_response_bytes: NonZeroUsize,
    pub provenance_capacity: NonZeroUsize,
}

impl Default for AdapterLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: NonZeroUsize::new(64 * 1024).expect("constant is nonzero"),
            max_control_line_bytes: NonZeroUsize::new(64 * 1024).expect("constant is nonzero"),
            max_literal_bytes: NonZeroUsize::new(1024 * 1024).expect("constant is nonzero"),
            max_response_bytes: NonZeroUsize::new(2 * 1024 * 1024).expect("constant is nonzero"),
            provenance_capacity: NonZeroUsize::new(64).expect("constant is nonzero"),
        }
    }
}

impl AdapterLimits {
    fn validate(&self) -> io::Result<()> {
        if self.max_control_line_bytes.get() < 2
            || self.max_response_bytes < self.max_control_line_bytes
            || self.provenance_capacity.get() > 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid UIDONLY adapter limits",
            ));
        }
        Ok(())
    }
}

/// Per-command ceilings for the private post-enable dispatcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandLimits {
    pub timeout: Duration,
    pub max_responses: NonZeroUsize,
    pub max_wire_bytes: NonZeroUsize,
    pub max_events: NonZeroUsize,
    pub max_vanished_ranges: NonZeroUsize,
    pub max_inventory_page: NonZeroU32,
    pub max_body_chunk_bytes: NonZeroU32,
    pub max_mailbox_wire_bytes: NonZeroUsize,
}

impl Default for CommandLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_responses: NonZeroUsize::new(2_048).expect("constant is nonzero"),
            max_wire_bytes: NonZeroUsize::new(4 * 1024 * 1024).expect("constant is nonzero"),
            max_events: NonZeroUsize::new(2_048).expect("constant is nonzero"),
            max_vanished_ranges: NonZeroUsize::new(2_048).expect("constant is nonzero"),
            max_inventory_page: NonZeroU32::new(1_000).expect("constant is nonzero"),
            max_body_chunk_bytes: NonZeroU32::new(1024 * 1024).expect("constant is nonzero"),
            max_mailbox_wire_bytes: NonZeroUsize::new(4_096).expect("constant is nonzero"),
        }
    }
}

impl CommandLimits {
    fn validate(&self) -> io::Result<()> {
        if self.timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command timeout must be nonzero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Provenance {
    TranslatedUidFetch { leading_uid: u32, wire_bytes: usize },
    Unchanged { wire_bytes: usize },
}

impl Provenance {
    fn wire_bytes(&self) -> usize {
        match self {
            Self::TranslatedUidFetch { wire_bytes, .. } | Self::Unchanged { wire_bytes } => {
                *wire_bytes
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Mode {
    PassThrough,
    PendingEnable {
        tag: Vec<u8>,
        saw_enabled_uidonly: bool,
    },
    Active,
    Poisoned,
}

#[derive(Debug)]
struct SharedState {
    mode: Mode,
    provenance: VecDeque<Provenance>,
    reserved: usize,
    provenance_capacity: usize,
    activation_wire_bytes: usize,
    literal_bytes_received: u64,
    poison_reason: Option<String>,
    waker: AtomicWaker,
}

/// Control handle paired with one [`UidOnlyAdapter`].
#[derive(Clone, Debug)]
pub struct AdapterHandle {
    shared: Arc<Mutex<SharedState>>,
}

impl AdapterHandle {
    fn arm_enable(&self, request_id: &RequestId) -> io::Result<()> {
        let mut shared = self.shared.lock().expect("adapter mutex poisoned");
        match shared.mode {
            Mode::PassThrough => {
                shared.activation_wire_bytes = 0;
                shared.mode = Mode::PendingEnable {
                    tag: request_id.as_bytes().to_vec(),
                    saw_enabled_uidonly: false,
                };
                Ok(())
            }
            _ => Err(io::Error::other(
                "UIDONLY adapter is not in pass-through mode",
            )),
        }
    }

    fn take_provenance(&self) -> Option<Provenance> {
        let mut shared = self.shared.lock().expect("adapter mutex poisoned");
        let result = shared.provenance.pop_front();
        if result.is_some() {
            shared.waker.wake();
        }
        result
    }

    fn provenance_len(&self) -> usize {
        self.shared
            .lock()
            .expect("adapter mutex poisoned")
            .provenance
            .len()
    }

    fn activation_wire_bytes(&self) -> usize {
        self.shared
            .lock()
            .expect("adapter mutex poisoned")
            .activation_wire_bytes
    }

    /// Returns the cumulative literal octets accepted by this adapter.
    ///
    /// The counter advances before command completion, so callers can charge
    /// truncated literals even when the connection closes before tagged OK.
    pub fn literal_bytes_received(&self) -> u64 {
        self.shared
            .lock()
            .expect("adapter mutex poisoned")
            .literal_bytes_received
    }

    /// Returns whether the exact `ENABLE UIDONLY` activation boundary passed.
    pub fn is_active(&self) -> bool {
        matches!(
            self.shared.lock().expect("adapter mutex poisoned").mode,
            Mode::Active
        )
    }

    /// Returns the fail-closed adapter reason, if the connection was poisoned.
    pub fn poison_reason(&self) -> Option<String> {
        self.shared
            .lock()
            .expect("adapter mutex poisoned")
            .poison_reason
            .clone()
    }
}

#[derive(Debug)]
enum ActiveResponseKind {
    TranslatedUidFetch { leading_uid: u32 },
    Unchanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessInput {
    Emitted,
    NeedInput,
    Backpressured,
}

/// Literal-aware `AsyncRead` adapter for released-parser UIDONLY compatibility.
#[derive(Debug)]
pub struct UidOnlyAdapter<T> {
    inner: T,
    shared: Arc<Mutex<SharedState>>,
    limits: AdapterLimits,
    input: VecDeque<u8>,
    emit: VecDeque<u8>,
    line: Vec<u8>,
    literal_remaining: usize,
    response_bytes: usize,
    in_response: bool,
    first_line: bool,
    reserved_provenance: bool,
    active_kind: Option<ActiveResponseKind>,
    pass_through_literal_context: bool,
    eof: bool,
}

impl<T> UidOnlyAdapter<T> {
    /// Wraps a final TCP/TLS stream before `async_imap::Client` reads from it.
    pub fn new(inner: T, limits: AdapterLimits) -> io::Result<(Self, AdapterHandle)> {
        limits.validate()?;
        let shared = Arc::new(Mutex::new(SharedState {
            mode: Mode::PassThrough,
            provenance: VecDeque::new(),
            reserved: 0,
            provenance_capacity: limits.provenance_capacity.get(),
            activation_wire_bytes: 0,
            literal_bytes_received: 0,
            poison_reason: None,
            waker: AtomicWaker::new(),
        }));
        let handle = AdapterHandle {
            shared: Arc::clone(&shared),
        };
        Ok((
            Self {
                inner,
                shared,
                limits,
                input: VecDeque::new(),
                emit: VecDeque::new(),
                line: Vec::new(),
                literal_remaining: 0,
                response_bytes: 0,
                in_response: false,
                first_line: true,
                reserved_provenance: false,
                active_kind: None,
                pass_through_literal_context: false,
                eof: false,
            },
            handle,
        ))
    }

    /// Recovers the wrapped transport only at an empty pass-through boundary.
    ///
    /// This is used for STARTTLS: the pre-TLS greeting and command response are
    /// bounded by one adapter, then a fresh adapter is installed around the
    /// final TLS transport before authentication and UIDONLY activation.
    pub fn into_inner(self) -> io::Result<T> {
        let shared = self.shared.lock().expect("adapter mutex poisoned");
        if !matches!(shared.mode, Mode::PassThrough)
            || !shared.provenance.is_empty()
            || shared.reserved != 0
            || !self.input.is_empty()
            || !self.emit.is_empty()
            || !self.line.is_empty()
            || self.literal_remaining != 0
            || self.in_response
            || self.reserved_provenance
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UIDONLY adapter can only be unwrapped at an empty pass-through boundary",
            ));
        }
        drop(shared);
        Ok(self.inner)
    }

    fn poison(&mut self, message: impl Into<String>) -> io::Error {
        self.poison_with_kind(io::ErrorKind::InvalidData, message)
    }

    fn poison_with_kind(&mut self, kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
        let message = message.into();
        let mut shared = self.shared.lock().expect("adapter mutex poisoned");
        shared.mode = Mode::Poisoned;
        shared.poison_reason = Some(message.clone());
        io::Error::new(kind, message)
    }

    fn ensure_response_started(&mut self, cx: &Context<'_>) -> io::Result<bool> {
        if self.in_response {
            return Ok(true);
        }

        let mut shared = self.shared.lock().expect("adapter mutex poisoned");
        if matches!(shared.mode, Mode::Poisoned) {
            return Err(invalid_data(
                shared
                    .poison_reason
                    .clone()
                    .unwrap_or_else(|| "UIDONLY adapter poisoned".to_string()),
            ));
        }

        if matches!(shared.mode, Mode::Active) {
            if shared.provenance.len() + shared.reserved >= shared.provenance_capacity {
                shared.waker.register(cx.waker());
                return Ok(false);
            }
            shared.reserved += 1;
            self.reserved_provenance = true;
        }

        self.in_response = true;
        self.first_line = true;
        self.response_bytes = 0;
        self.active_kind = None;
        self.pass_through_literal_context = false;
        Ok(true)
    }

    fn add_response_bytes(&mut self, count: usize) -> io::Result<()> {
        self.response_bytes = self
            .response_bytes
            .checked_add(count)
            .ok_or_else(|| self.poison("response byte count overflow"))?;
        if self.response_bytes > self.limits.max_response_bytes.get() {
            return Err(self.poison("response exceeds configured byte limit"));
        }
        Ok(())
    }

    fn add_literal_bytes(&mut self, count: usize) -> io::Result<()> {
        let count =
            u64::try_from(count).map_err(|_| self.poison("literal byte count does not fit u64"))?;
        let mut shared = self.shared.lock().expect("adapter mutex poisoned");
        let Some(total) = shared.literal_bytes_received.checked_add(count) else {
            drop(shared);
            return Err(self.poison("literal byte counter overflow"));
        };
        shared.literal_bytes_received = total;
        Ok(())
    }

    fn handle_complete_line(&mut self) -> io::Result<()> {
        let mut wire_line = std::mem::take(&mut self.line);
        debug_assert!(wire_line.ends_with(b"\r\n"));

        if self.first_line {
            self.classify_first_line(&mut wire_line)?;
            self.first_line = false;
        }

        let line_without_crlf = &wire_line[..wire_line.len() - 2];
        let marker_candidate = line_without_crlf.ends_with(b"}");
        let active_uidfetch = matches!(
            self.active_kind,
            Some(ActiveResponseKind::TranslatedUidFetch { .. })
        );
        if active_uidfetch && contains_internaldate_nil(line_without_crlf) {
            return Err(self.poison("UIDFETCH INTERNALDATE NIL is invalid"));
        }
        let mode = self
            .shared
            .lock()
            .expect("adapter mutex poisoned")
            .mode
            .clone();
        if marker_candidate && matches!(mode, Mode::Active) && !active_uidfetch {
            return Err(self.poison("literal-like marker outside an active UIDFETCH response"));
        }
        if marker_candidate && matches!(mode, Mode::PendingEnable { .. }) {
            return Err(self.poison("literal response is forbidden during UIDONLY activation"));
        }

        let literal = if marker_candidate && active_uidfetch {
            Some(
                parse_literal_len(line_without_crlf)
                    .map_err(|error| self.poison(error.to_string()))?,
            )
        } else if marker_candidate
            && matches!(mode, Mode::PassThrough)
            && self.pass_through_literal_context
        {
            parse_pass_through_literal_len(line_without_crlf)
                .map_err(|error| self.poison(error.to_string()))?
        } else {
            None
        };

        if let Some(length) = literal {
            if length > self.limits.max_literal_bytes.get() {
                return Err(self.poison("literal exceeds configured byte limit"));
            }
            let projected_response_bytes = self
                .response_bytes
                .checked_add(length)
                .ok_or_else(|| self.poison("response byte count overflow"))?;
            if projected_response_bytes > self.limits.max_response_bytes.get() {
                return Err(self.poison("announced literal exceeds remaining response budget"));
            }
            self.literal_remaining = length;
            self.emit.extend(wire_line);
            return Ok(());
        }

        self.finish_response_before_emit(&wire_line)?;
        self.emit.extend(wire_line);
        Ok(())
    }

    fn classify_first_line(&mut self, wire_line: &mut Vec<u8>) -> io::Result<()> {
        let mode = self
            .shared
            .lock()
            .expect("adapter mutex poisoned")
            .mode
            .clone();

        match mode {
            Mode::PassThrough => {
                let numeric = classify_numeric_response(wire_line)
                    .map_err(|error| self.poison(error.to_string()))?;
                self.pass_through_literal_context = matches!(numeric, NumericResponse::Fetch)
                    || pass_through_untagged_may_contain_literal(wire_line);
                if matches!(numeric, NumericResponse::Fetch) {
                    self.active_kind = Some(ActiveResponseKind::Unchanged);
                }
                Ok(())
            }
            Mode::PendingEnable { .. } => {
                if matches!(
                    classify_numeric_response(wire_line)
                        .map_err(|error| self.poison(error.to_string()))?,
                    NumericResponse::UidFetch { .. }
                ) {
                    return Err(self.poison("UIDFETCH arrived before UIDONLY activation"));
                }
                Ok(())
            }
            Mode::Active => {
                match classify_numeric_response(wire_line)
                    .map_err(|error| self.poison(error.to_string()))?
                {
                    NumericResponse::UidFetch {
                        leading_uid,
                        atom_start,
                        atom_end,
                    } => {
                        let mut rewritten = Vec::with_capacity(wire_line.len() - 3);
                        rewritten.extend_from_slice(&wire_line[..atom_start]);
                        rewritten.extend_from_slice(b"FETCH");
                        rewritten.extend_from_slice(&wire_line[atom_end..]);
                        *wire_line = rewritten;
                        self.active_kind =
                            Some(ActiveResponseKind::TranslatedUidFetch { leading_uid });
                        Ok(())
                    }
                    NumericResponse::Fetch => {
                        Err(self.poison("raw FETCH is forbidden after UIDONLY activation"))
                    }
                    NumericResponse::Other => {
                        self.active_kind = Some(ActiveResponseKind::Unchanged);
                        Ok(())
                    }
                }
            }
            Mode::Poisoned => Err(self.poison("UIDONLY adapter already poisoned")),
        }
    }

    fn finish_response_before_emit(&mut self, wire_line: &[u8]) -> io::Result<()> {
        let mut shared = self.shared.lock().expect("adapter mutex poisoned");
        if matches!(shared.mode, Mode::PendingEnable { .. }) {
            let Some(total) = shared
                .activation_wire_bytes
                .checked_add(self.response_bytes)
            else {
                drop(shared);
                return Err(self.poison("ENABLE UIDONLY wire byte count overflow"));
            };
            shared.activation_wire_bytes = total;
        }
        match &mut shared.mode {
            Mode::PassThrough => {}
            Mode::PendingEnable {
                tag,
                saw_enabled_uidonly,
            } => {
                if is_enabled_uidonly(wire_line) {
                    *saw_enabled_uidonly = true;
                } else if let Some(status) = tagged_status(wire_line, tag) {
                    match status {
                        TaggedStatus::Ok if *saw_enabled_uidonly => shared.mode = Mode::Active,
                        TaggedStatus::Ok => {
                            drop(shared);
                            return Err(self.poison("ENABLE completed OK without ENABLED UIDONLY"));
                        }
                        TaggedStatus::NoOrBad => {
                            drop(shared);
                            return Err(self.poison("ENABLE UIDONLY was rejected"));
                        }
                    }
                }
            }
            Mode::Active => {
                if !self.reserved_provenance || shared.reserved == 0 {
                    drop(shared);
                    return Err(self.poison("missing reserved provenance slot"));
                }
                let record = match self.active_kind {
                    Some(ActiveResponseKind::TranslatedUidFetch { leading_uid }) => {
                        Provenance::TranslatedUidFetch {
                            leading_uid,
                            wire_bytes: self.response_bytes,
                        }
                    }
                    Some(ActiveResponseKind::Unchanged) => Provenance::Unchanged {
                        wire_bytes: self.response_bytes,
                    },
                    None => {
                        drop(shared);
                        return Err(self.poison("missing active response classification"));
                    }
                };
                shared.reserved -= 1;
                shared.provenance.push_back(record);
                self.reserved_provenance = false;
            }
            Mode::Poisoned => return Err(invalid_data("UIDONLY adapter poisoned")),
        }

        self.in_response = false;
        self.first_line = true;
        self.response_bytes = 0;
        self.active_kind = None;
        self.pass_through_literal_context = false;
        Ok(())
    }

    fn copy_emit(&mut self, output: &mut ReadBuf<'_>) {
        let count = output.remaining().min(self.emit.len());
        if count == 0 {
            return;
        }
        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            bytes.push(self.emit.pop_front().expect("emit length checked"));
        }
        output.put_slice(&bytes);
    }

    fn process_input(&mut self, cx: &Context<'_>) -> io::Result<ProcessInput> {
        if !self.emit.is_empty() {
            return Ok(ProcessInput::Emitted);
        }
        if !self.in_response && self.input.is_empty() {
            return Ok(ProcessInput::NeedInput);
        }
        if !self.ensure_response_started(cx)? {
            return Ok(ProcessInput::Backpressured);
        }

        if self.literal_remaining > 0 {
            if self.input.is_empty() {
                return Ok(ProcessInput::NeedInput);
            }
            let count = self.literal_remaining.min(self.input.len()).min(READ_CHUNK);
            self.add_response_bytes(count)?;
            self.add_literal_bytes(count)?;
            for _ in 0..count {
                self.emit
                    .push_back(self.input.pop_front().expect("input length checked"));
            }
            self.literal_remaining -= count;
            return Ok(ProcessInput::Emitted);
        }

        while let Some(byte) = self.input.pop_front() {
            self.line.push(byte);
            self.add_response_bytes(1)?;
            if self.line.len() > self.limits.max_control_line_bytes.get() {
                return Err(self.poison("control line exceeds configured byte limit"));
            }
            if self.line.ends_with(b"\r\n") {
                self.handle_complete_line()?;
                return Ok(ProcessInput::Emitted);
            }
        }
        Ok(ProcessInput::NeedInput)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for UidOnlyAdapter<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !this.emit.is_empty() {
                this.copy_emit(output);
                return Poll::Ready(Ok(()));
            }

            match this.process_input(cx) {
                Ok(ProcessInput::Emitted) => continue,
                Ok(ProcessInput::NeedInput) => {}
                Ok(ProcessInput::Backpressured) => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }

            if this.eof {
                if !this.input.is_empty() && !this.in_response {
                    this.shared
                        .lock()
                        .expect("adapter mutex poisoned")
                        .waker
                        .register(cx.waker());
                    return Poll::Pending;
                }
                if this.in_response || !this.line.is_empty() || this.literal_remaining > 0 {
                    return Poll::Ready(Err(this.poison_with_kind(
                        io::ErrorKind::UnexpectedEof,
                        "truncated IMAP response",
                    )));
                }
                return Poll::Ready(Ok(()));
            }

            if this.input.len() >= this.limits.max_input_bytes.get() {
                return Poll::Ready(Err(this.poison("input buffer limit reached")));
            }

            let remaining_capacity = this.limits.max_input_bytes.get() - this.input.len();
            let mut storage = [0_u8; READ_CHUNK];
            let read_len = remaining_capacity.min(storage.len());
            let mut inner_buf = ReadBuf::new(&mut storage[..read_len]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut inner_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let read = inner_buf.filled();
                    if read.is_empty() {
                        this.eof = true;
                    } else {
                        this.input.extend(read);
                    }
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for UidOnlyAdapter<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Debug, Eq, PartialEq)]
enum NumericResponse {
    UidFetch {
        leading_uid: u32,
        atom_start: usize,
        atom_end: usize,
    },
    Fetch,
    Other,
}

fn classify_numeric_response(line: &[u8]) -> io::Result<NumericResponse> {
    if !line.starts_with(b"* ") {
        return Ok(NumericResponse::Other);
    }
    let mut index = 2;
    let digit_start = index;
    while index < line.len() && line[index].is_ascii_digit() {
        index += 1;
    }
    if index == digit_start || line.get(index) != Some(&b' ') {
        return Ok(NumericResponse::Other);
    }
    let leading_digits = &line[digit_start..index];
    index += 1;
    let atom_start = index;
    while index < line.len() && line[index].is_ascii_alphabetic() {
        index += 1;
    }
    if line.get(index) != Some(&b' ') {
        return Ok(NumericResponse::Other);
    }
    let atom = &line[atom_start..index];
    if atom.eq_ignore_ascii_case(b"UIDFETCH") {
        let leading_uid = std::str::from_utf8(leading_digits)
            .map_err(|_| invalid_data("invalid leading UID"))?
            .parse::<u32>()
            .map_err(|_| invalid_data("invalid leading UID"))?;
        if leading_uid == 0 {
            return Err(invalid_data("UID 0 is invalid"));
        }
        Ok(NumericResponse::UidFetch {
            leading_uid,
            atom_start,
            atom_end: index,
        })
    } else if atom.eq_ignore_ascii_case(b"FETCH") {
        Ok(NumericResponse::Fetch)
    } else {
        Ok(NumericResponse::Other)
    }
}

fn parse_literal_len(line: &[u8]) -> io::Result<usize> {
    let open = line
        .iter()
        .rposition(|byte| *byte == b'{')
        .ok_or_else(|| invalid_data("invalid literal marker"))?;
    if open > 0 && line[open - 1] == b'~' {
        return Err(invalid_data("literal8 is unsupported"));
    }
    let digits = &line[open + 1..line.len() - 1];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(invalid_data("invalid literal marker"));
    }
    std::str::from_utf8(digits)
        .map_err(|_| invalid_data("invalid literal marker"))?
        .parse::<usize>()
        .map_err(|_| invalid_data("invalid literal marker"))
}

fn contains_internaldate_nil(line: &[u8]) -> bool {
    let mut index = 0;
    let mut saw_internal_date = false;
    while index < line.len() {
        if line[index] == b'"' {
            index += 1;
            while index < line.len() {
                match line[index] {
                    b'\\' if index + 1 < line.len() => index += 2,
                    b'"' => {
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
            continue;
        }
        if !line[index].is_ascii_alphanumeric() && line[index] != b'-' {
            index += 1;
            continue;
        }
        let start = index;
        while index < line.len() && (line[index].is_ascii_alphanumeric() || line[index] == b'-') {
            index += 1;
        }
        let token = &line[start..index];
        if saw_internal_date {
            return token.eq_ignore_ascii_case(b"NIL");
        }
        saw_internal_date = token.eq_ignore_ascii_case(b"INTERNALDATE");
    }
    false
}

fn parse_pass_through_literal_len(line: &[u8]) -> io::Result<Option<usize>> {
    let Some(open) = line.iter().rposition(|byte| *byte == b'{') else {
        return Ok(None);
    };
    let mut digits = &line[open + 1..line.len() - 1];
    if let Some(without_plus) = digits.strip_suffix(b"+") {
        digits = without_plus;
    }
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Ok(None);
    }
    let length = std::str::from_utf8(digits)
        .map_err(|_| invalid_data("invalid pass-through literal marker"))?
        .parse::<usize>()
        .map_err(|_| invalid_data("pass-through literal length overflow"))?;
    Ok(Some(length))
}

fn pass_through_untagged_may_contain_literal(line: &[u8]) -> bool {
    let Some(rest) = line.strip_prefix(b"* ") else {
        return false;
    };
    let atom_end = rest
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(rest.len());
    let atom = &rest[..atom_end];
    !atom.is_empty()
        && !atom.iter().all(u8::is_ascii_digit)
        && ![
            b"OK".as_slice(),
            b"NO".as_slice(),
            b"BAD".as_slice(),
            b"PREAUTH".as_slice(),
            b"BYE".as_slice(),
        ]
        .iter()
        .any(|status| atom.eq_ignore_ascii_case(status))
}

fn is_enabled_uidonly(line: &[u8]) -> bool {
    let Some(line) = line.strip_suffix(b"\r\n") else {
        return false;
    };
    let mut fields = line.split(|byte| *byte == b' ');
    fields.next() == Some(b"*".as_slice())
        && fields
            .next()
            .is_some_and(|atom| atom.eq_ignore_ascii_case(b"ENABLED"))
        && fields.any(|atom| atom.eq_ignore_ascii_case(b"UIDONLY"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaggedStatus {
    Ok,
    NoOrBad,
}

fn tagged_status(line: &[u8], expected_tag: &[u8]) -> Option<TaggedStatus> {
    let line = line.strip_suffix(b"\r\n")?;
    let rest = line.strip_prefix(expected_tag)?.strip_prefix(b" ")?;
    let atom_end = rest
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(rest.len());
    let status = &rest[..atom_end];
    if status.eq_ignore_ascii_case(b"OK") {
        Some(TaggedStatus::Ok)
    } else if status.eq_ignore_ascii_case(b"NO") || status.eq_ignore_ascii_case(b"BAD") {
        Some(TaggedStatus::NoOrBad)
    } else {
        None
    }
}

/// Fixed UID inventory request generated by [`InventoryPlanner`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryRequest {
    start: NonZeroU32,
    end: NonZeroU32,
    page_size: NonZeroU32,
}

impl InventoryRequest {
    /// Creates one bounded fixed-range request. Production callers normally
    /// obtain requests from `InventoryPlanner`; restartable acquisition may
    /// reconstruct the next persisted cursor directly through this validator.
    pub fn new(start: NonZeroU32, end: NonZeroU32, page_size: NonZeroU32) -> io::Result<Self> {
        if start > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inventory range is reversed",
            ));
        }
        Ok(Self {
            start,
            end,
            page_size,
        })
    }

    pub fn start(&self) -> NonZeroU32 {
        self.start
    }

    pub fn end(&self) -> NonZeroU32 {
        self.end
    }

    pub fn page_size(&self) -> NonZeroU32 {
        self.page_size
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum UidOnlyCommand {
    Examine {
        encoded_mailbox: String,
    },
    Inventory(InventoryRequest),
    BodyChunk {
        uid: NonZeroU32,
        offset: u32,
        count: NonZeroU32,
    },
    Noop,
    Logout,
}

impl UidOnlyCommand {
    fn render(&self, limits: &CommandLimits) -> io::Result<String> {
        match self {
            Self::Examine { encoded_mailbox } => {
                if encoded_mailbox.len() > limits.max_mailbox_wire_bytes.get() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "mailbox name exceeds configured wire limit",
                    ));
                }
                if !encoded_mailbox.is_ascii() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "mailbox must use Bichon's ASCII wire encoding",
                    ));
                }
                if encoded_mailbox.bytes().any(|byte| byte.is_ascii_control()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "mailbox contains a forbidden control byte",
                    ));
                }
                let quoted = encoded_mailbox.replace('\\', "\\\\").replace('"', "\\\"");
                let quoted_wire_bytes = quoted
                    .len()
                    .checked_add(2)
                    .ok_or_else(|| io::Error::other("mailbox wire byte count overflow"))?;
                if quoted_wire_bytes > limits.max_mailbox_wire_bytes.get() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "escaped mailbox exceeds configured wire limit",
                    ));
                }
                Ok(format!("EXAMINE \"{quoted}\""))
            }
            Self::Inventory(request) => {
                if request.start > request.end {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "inventory range is reversed",
                    ));
                }
                if request.page_size > limits.max_inventory_page {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "inventory page exceeds configured limit",
                    ));
                }
                Ok(format!(
                    "UID FETCH {}:{} (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:{})",
                    request.start, request.end, request.page_size
                ))
            }
            Self::BodyChunk { uid, offset, count } => {
                if count > &limits.max_body_chunk_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "body chunk exceeds configured limit",
                    ));
                }
                offset.checked_add(count.get()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "body chunk range overflows")
                })?;
                // Keep an explicit one-result bound on exact-UID body reads. Some
                // UIDONLY servers require the PARTIAL result modifier on FETCH.
                Ok(format!(
                    "UID FETCH {} (UID RFC822.SIZE BODY.PEEK[]<{}.{}>) (PARTIAL 1:1)",
                    uid, offset, count
                ))
            }
            Self::Noop => Ok("NOOP".to_string()),
            Self::Logout => Ok("LOGOUT".to_string()),
        }
    }
}

/// Validated read-only mailbox boundary for one UIDVALIDITY epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxSnapshot {
    pub exists: u32,
    pub uid_validity: NonZeroU32,
    pub uid_next: NonZeroU32,
    pub snapshot_high_uid: Option<NonZeroU32>,
    pub notifications: Vec<Notification>,
}

/// One solicited metadata record from a bounded inventory page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryItem {
    pub uid: NonZeroU32,
    pub rfc822_size: u32,
    pub internal_date: String,
}

/// Allowlisted unsolicited state observed while draining a command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Notification {
    Exists(u32),
    Recent(u32),
    Flags {
        uid: NonZeroU32,
        flags: Vec<String>,
    },
    Status,
    Vanished {
        earlier: bool,
        uids: Vec<RangeInclusive<u32>>,
    },
}

/// A complete, tagged-OK bounded inventory result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryPage {
    pub request: InventoryRequest,
    pub items: Vec<InventoryItem>,
    pub notifications: Vec<Notification>,
}

/// Exact raw body chunk returned for one UID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyChunk {
    pub uid: NonZeroU32,
    pub rfc822_size: u32,
    pub offset: u32,
    pub bytes: Vec<u8>,
    pub notifications: Vec<Notification>,
}

/// Explicit result for an exact-UID body command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactFetchOutcome {
    Chunk(BodyChunk),
    Missing {
        uid: NonZeroU32,
        notifications: Vec<Notification>,
    },
    Vanished {
        uid: NonZeroU32,
        notifications: Vec<Notification>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Solicited {
    Inventory(InventoryItem),
    Body {
        uid: NonZeroU32,
        rfc822_size: u32,
        offset: u32,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Default)]
struct Accumulator {
    exists: Option<u32>,
    uid_validity: Option<NonZeroU32>,
    uid_next: Option<NonZeroU32>,
    read_only: bool,
    solicited: Vec<Solicited>,
    notifications: Vec<Notification>,
    vanished_ranges: usize,
    saw_bye: bool,
}

#[derive(Debug)]
enum CommandOutput {
    Examine(MailboxSnapshot),
    Inventory(InventoryPage),
    Body(ExactFetchOutcome),
    Noop(Vec<Notification>),
    Logout,
}

/// Private post-enable session with no sequence-number or arbitrary-command API.
#[derive(Debug)]
pub struct UidOnlySession<T>
where
    T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug,
{
    session: async_imap::Session<UidOnlyAdapter<T>>,
    handle: AdapterHandle,
    limits: CommandLimits,
}

impl<T> UidOnlySession<T>
where
    T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    /// Returns a cloneable meter that survives a failed consuming command.
    pub fn literal_byte_meter(&self) -> AdapterHandle {
        self.handle.clone()
    }

    /// Enables UIDONLY and consumes the ordinary session at the clean boundary.
    pub async fn enable(
        mut session: async_imap::Session<UidOnlyAdapter<T>>,
        handle: AdapterHandle,
        limits: CommandLimits,
    ) -> io::Result<Self> {
        limits.validate()?;
        if handle.is_active() || handle.provenance_len() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UIDONLY enable requires a clean pass-through boundary",
            ));
        }

        let response_limit = limits.max_responses.get();
        let enable = async {
            let request_id = session
                .run_command("ENABLE UIDONLY")
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
            handle.arm_enable(&request_id)?;
            for _ in 0..response_limit {
                let response = session
                    .read_response()
                    .await?
                    .ok_or_else(|| invalid_data("connection closed during ENABLE UIDONLY"))?;
                if handle.activation_wire_bytes() > limits.max_wire_bytes.get() {
                    return Err(invalid_data(
                        "ENABLE UIDONLY wire bytes exceed configured limit",
                    ));
                }
                match response.parsed() {
                    Response::Capabilities(_) => {}
                    Response::Done { tag, status, .. } => {
                        if tag != &request_id {
                            return Err(invalid_data("unexpected ENABLE completion tag"));
                        }
                        if status != &Status::Ok || !handle.is_active() {
                            return Err(invalid_data("UIDONLY did not activate"));
                        }
                        if handle.provenance_len() != 0 {
                            return Err(invalid_data(
                                "UIDONLY activation left unexpected provenance",
                            ));
                        }
                        return Ok(());
                    }
                    _ => return Err(invalid_data("unexpected ENABLE UIDONLY response")),
                }
            }
            Err(invalid_data(
                "ENABLE UIDONLY response count exceeds configured limit",
            ))
        };
        tokio::time::timeout(limits.timeout, enable)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ENABLE UIDONLY timed out"))??;
        Ok(Self {
            session,
            handle,
            limits,
        })
    }

    /// Examines one safely encoded mailbox in read-only mode.
    pub async fn examine(
        self,
        encoded_mailbox: impl Into<String>,
    ) -> io::Result<(Self, MailboxSnapshot)> {
        let command = UidOnlyCommand::Examine {
            encoded_mailbox: encoded_mailbox.into(),
        };
        let (session, output) = self.execute(command).await?;
        let CommandOutput::Examine(snapshot) = output else {
            unreachable!("command and output variants are paired");
        };
        Ok((session, snapshot))
    }

    /// Retrieves one bounded UID metadata page.
    pub async fn inventory(self, request: InventoryRequest) -> io::Result<(Self, InventoryPage)> {
        let (session, output) = self.execute(UidOnlyCommand::Inventory(request)).await?;
        let CommandOutput::Inventory(page) = output else {
            unreachable!("command and output variants are paired");
        };
        Ok((session, page))
    }

    /// Fetches one bounded raw-message octet chunk by one exact UID.
    pub async fn fetch_body_chunk(
        self,
        uid: NonZeroU32,
        offset: u32,
        count: NonZeroU32,
    ) -> io::Result<(Self, ExactFetchOutcome)> {
        let command = UidOnlyCommand::BodyChunk { uid, offset, count };
        let (session, output) = self.execute(command).await?;
        let CommandOutput::Body(outcome) = output else {
            unreachable!("command and output variants are paired");
        };
        Ok((session, outcome))
    }

    /// Drains a bounded NOOP through its exact tagged completion.
    pub async fn noop(self) -> io::Result<(Self, Vec<Notification>)> {
        let (session, output) = self.execute(UidOnlyCommand::Noop).await?;
        let CommandOutput::Noop(notifications) = output else {
            unreachable!("command and output variants are paired");
        };
        Ok((session, notifications))
    }

    /// Sends LOGOUT, requires BYE plus the matching tagged OK, then drops.
    pub async fn logout(self) -> io::Result<()> {
        let (_, output) = self.execute(UidOnlyCommand::Logout).await?;
        debug_assert!(matches!(output, CommandOutput::Logout));
        Ok(())
    }

    async fn execute(mut self, command: UidOnlyCommand) -> io::Result<(Self, CommandOutput)> {
        let rendered = command.render(&self.limits)?;
        let timeout = self.limits.timeout;
        let output = tokio::time::timeout(timeout, self.execute_rendered(&command, rendered))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UIDONLY command timed out"))??;
        Ok((self, output))
    }

    async fn execute_rendered(
        &mut self,
        command: &UidOnlyCommand,
        rendered: String,
    ) -> io::Result<CommandOutput> {
        let request_id = self
            .session
            .run_command(rendered)
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut accumulator = Accumulator::default();
        let mut response_count = 0_usize;
        let mut command_wire_bytes = 0_usize;

        loop {
            let response = self
                .session
                .read_response()
                .await
                .map_err(|error| {
                    io::Error::new(error.kind(), "UIDONLY IMAP response read or parse failed")
                })?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed before command completion",
                    )
                })?;
            response_count = response_count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("command response count overflow"))?;
            if response_count > self.limits.max_responses.get() {
                return Err(invalid_data(
                    "command response count exceeds configured limit",
                ));
            }
            let provenance = self
                .handle
                .take_provenance()
                .ok_or_else(|| invalid_data("parsed response has no provenance"))?;
            command_wire_bytes = command_wire_bytes
                .checked_add(provenance.wire_bytes())
                .ok_or_else(|| io::Error::other("command wire byte count overflow"))?;
            if command_wire_bytes > self.limits.max_wire_bytes.get() {
                return Err(invalid_data("command wire bytes exceed configured limit"));
            }

            match response.parsed() {
                Response::Done {
                    tag, status, code, ..
                } => {
                    require_unchanged(provenance)?;
                    if tag != &request_id {
                        return Err(invalid_data("unexpected tagged response"));
                    }
                    if status != &Status::Ok {
                        let failure = match status {
                            Status::No => "UIDONLY command completed with tagged NO",
                            Status::Bad => "UIDONLY command completed with tagged BAD",
                            _ => "UIDONLY command completed with unexpected tagged status",
                        };
                        return Err(invalid_data(failure));
                    }
                    match code {
                        Some(ResponseCode::ReadOnly)
                            if matches!(command, UidOnlyCommand::Examine { .. }) =>
                        {
                            accumulator.read_only = true;
                        }
                        Some(_) => {
                            return Err(invalid_data(
                                "tagged response code is not allowlisted for this command",
                            ))
                        }
                        None => {}
                    }
                    return finalize_command(command, accumulator);
                }
                Response::Fetch(leading_uid, attributes) => {
                    let Provenance::TranslatedUidFetch {
                        leading_uid: wire_uid,
                        ..
                    } = provenance
                    else {
                        return Err(invalid_data("parsed FETCH did not originate as UIDFETCH"));
                    };
                    if wire_uid != *leading_uid {
                        return Err(invalid_data("parsed and wire leading UIDs differ"));
                    }
                    classify_uidfetch(
                        command,
                        *leading_uid,
                        attributes,
                        &self.limits,
                        &mut accumulator,
                    )?;
                }
                Response::MailboxData(datum) => {
                    require_unchanged(provenance)?;
                    match datum {
                        imap_proto::types::MailboxDatum::Exists(count) => {
                            if matches!(command, UidOnlyCommand::Examine { .. }) {
                                if accumulator.exists.replace(*count).is_some() {
                                    return Err(invalid_data(
                                        "EXAMINE returned more than one EXISTS response",
                                    ));
                                }
                            } else {
                                push_notification(
                                    &self.limits,
                                    &mut accumulator,
                                    Notification::Exists(*count),
                                )?;
                            }
                        }
                        imap_proto::types::MailboxDatum::Recent(count) => push_notification(
                            &self.limits,
                            &mut accumulator,
                            Notification::Recent(*count),
                        )?,
                        imap_proto::types::MailboxDatum::Flags(_) => {}
                        _ => {
                            return Err(invalid_data(
                                "mailbox response is not allowlisted in UIDONLY mode",
                            ))
                        }
                    }
                }
                Response::Data {
                    status: Status::Ok,
                    code,
                    ..
                } => {
                    require_unchanged(provenance)?;
                    match code {
                        Some(ResponseCode::UidValidity(value)) => {
                            if !matches!(command, UidOnlyCommand::Examine { .. }) {
                                return Err(invalid_data(
                                    "UIDVALIDITY is only valid during EXAMINE",
                                ));
                            }
                            let value = NonZeroU32::new(*value)
                                .ok_or_else(|| invalid_data("UIDVALIDITY 0 is invalid"))?;
                            if accumulator.uid_validity.replace(value).is_some() {
                                return Err(invalid_data(
                                    "EXAMINE returned more than one UIDVALIDITY",
                                ));
                            }
                        }
                        Some(ResponseCode::UidNext(value)) => {
                            if !matches!(command, UidOnlyCommand::Examine { .. }) {
                                return Err(invalid_data("UIDNEXT is only valid during EXAMINE"));
                            }
                            let value = NonZeroU32::new(*value)
                                .ok_or_else(|| invalid_data("UIDNEXT 0 is invalid"))?;
                            if accumulator.uid_next.replace(value).is_some() {
                                return Err(invalid_data("EXAMINE returned more than one UIDNEXT"));
                            }
                        }
                        Some(ResponseCode::ReadOnly)
                            if matches!(command, UidOnlyCommand::Examine { .. }) =>
                        {
                            accumulator.read_only = true;
                        }
                        Some(
                            ResponseCode::PermanentFlags(_)
                            | ResponseCode::HighestModSeq(_)
                            | ResponseCode::Unseen(_)
                            | ResponseCode::Alert,
                        )
                        | None => {
                            push_notification(&self.limits, &mut accumulator, Notification::Status)?
                        }
                        Some(_) => {
                            return Err(invalid_data(
                                "response code is not allowlisted in UIDONLY mode",
                            ))
                        }
                    }
                }
                Response::Data {
                    status: Status::Bye,
                    ..
                } if matches!(command, UidOnlyCommand::Logout) => {
                    require_unchanged(provenance)?;
                    accumulator.saw_bye = true;
                }
                Response::Vanished { earlier, uids } => {
                    require_unchanged(provenance)?;
                    accumulator.vanished_ranges = accumulator
                        .vanished_ranges
                        .checked_add(uids.len())
                        .ok_or_else(|| invalid_data("VANISHED range count overflow"))?;
                    if accumulator.vanished_ranges > self.limits.max_vanished_ranges.get() {
                        return Err(invalid_data(
                            "VANISHED range count exceeds configured limit",
                        ));
                    }
                    push_notification(
                        &self.limits,
                        &mut accumulator,
                        Notification::Vanished {
                            earlier: *earlier,
                            uids: uids.clone(),
                        },
                    )?;
                }
                Response::Expunge(_) => {
                    return Err(invalid_data(
                        "sequence EXPUNGE is forbidden in UIDONLY mode",
                    ))
                }
                Response::Data { .. } => {
                    return Err(invalid_data("unexpected untagged status response"))
                }
                _ => {
                    return Err(invalid_data(
                        "response is not allowlisted for UIDONLY commands",
                    ))
                }
            }
        }
    }
}

fn require_unchanged(provenance: Provenance) -> io::Result<()> {
    if matches!(provenance, Provenance::Unchanged { .. }) {
        Ok(())
    } else {
        Err(invalid_data("non-FETCH response has UIDFETCH provenance"))
    }
}

fn push_notification(
    limits: &CommandLimits,
    accumulator: &mut Accumulator,
    notification: Notification,
) -> io::Result<()> {
    if accumulator.notifications.len() >= limits.max_events.get() {
        return Err(invalid_data("command event count exceeds configured limit"));
    }
    accumulator.notifications.push(notification);
    Ok(())
}

fn classify_uidfetch(
    command: &UidOnlyCommand,
    leading_uid: u32,
    attributes: &[AttributeValue<'_>],
    limits: &CommandLimits,
    accumulator: &mut Accumulator,
) -> io::Result<()> {
    let leading_uid =
        NonZeroU32::new(leading_uid).ok_or_else(|| invalid_data("UID 0 is invalid"))?;
    let inner_uids = attributes
        .iter()
        .filter_map(|attribute| match attribute {
            AttributeValue::Uid(uid) => Some(*uid),
            _ => None,
        })
        .collect::<Vec<_>>();
    if inner_uids.len() > 1 {
        return Err(invalid_data("UIDFETCH contains multiple inner UID items"));
    }
    let inner_uid = inner_uids.first().copied();
    if inner_uid.is_some_and(|inner| inner != leading_uid.get()) {
        return Err(invalid_data("leading and inner UID differ"));
    }

    let flags = attributes
        .iter()
        .filter_map(|attribute| match attribute {
            AttributeValue::Flags(flags) => Some(
                flags
                    .iter()
                    .map(|flag| flag.to_string())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .collect::<Vec<_>>();
    let size = attributes
        .iter()
        .filter_map(|attribute| match attribute {
            AttributeValue::Rfc822Size(size) => Some(*size),
            _ => None,
        })
        .collect::<Vec<_>>();
    let internal_dates = attributes
        .iter()
        .filter_map(|attribute| match attribute {
            AttributeValue::InternalDate(date) => Some(date.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let body_sections = attributes
        .iter()
        .filter_map(|attribute| match attribute {
            AttributeValue::BodySection {
                section,
                index,
                data,
            } => Some((section, index, data)),
            _ => None,
        })
        .collect::<Vec<_>>();

    let requested_shape_present =
        !size.is_empty() || !internal_dates.is_empty() || !body_sections.is_empty();
    if !requested_shape_present {
        if attributes.iter().any(|attribute| {
            !matches!(attribute, AttributeValue::Uid(_) | AttributeValue::Flags(_))
        }) {
            return Err(invalid_data(
                "unsolicited UIDFETCH contains an attribute outside the flags allowlist",
            ));
        }
        if flags.len() != 1 {
            return Err(invalid_data("unclassified unsolicited UIDFETCH response"));
        }
        push_notification(
            limits,
            accumulator,
            Notification::Flags {
                uid: leading_uid,
                flags: flags.into_iter().next().expect("length checked"),
            },
        )?;
        return Ok(());
    }
    if !flags.is_empty() {
        return Err(invalid_data(
            "solicited UIDFETCH mixed requested data with unsolicited flags",
        ));
    }
    if inner_uid != Some(leading_uid.get()) {
        return Err(invalid_data(
            "solicited UIDFETCH omitted the requested inner UID",
        ));
    }

    match command {
        UidOnlyCommand::Inventory(request) => {
            if attributes.iter().any(|attribute| {
                !matches!(
                    attribute,
                    AttributeValue::Uid(_)
                        | AttributeValue::Rfc822Size(_)
                        | AttributeValue::InternalDate(_)
                )
            }) {
                return Err(invalid_data(
                    "inventory result contains an unrequested attribute",
                ));
            }
            if leading_uid < request.start || leading_uid > request.end {
                return Err(invalid_data("inventory UID is outside requested range"));
            }
            if size.len() != 1 || internal_dates.len() != 1 || !body_sections.is_empty() {
                return Err(invalid_data(
                    "inventory result does not contain exactly UID, RFC822.SIZE, and INTERNALDATE",
                ));
            }
            accumulator
                .solicited
                .push(Solicited::Inventory(InventoryItem {
                    uid: leading_uid,
                    rfc822_size: size[0],
                    internal_date: internal_dates[0].clone(),
                }));
        }
        UidOnlyCommand::BodyChunk { uid, offset, count } => {
            if attributes.iter().any(|attribute| {
                !matches!(
                    attribute,
                    AttributeValue::Uid(_)
                        | AttributeValue::Rfc822Size(_)
                        | AttributeValue::BodySection { .. }
                )
            }) {
                return Err(invalid_data(
                    "body result contains an unrequested attribute",
                ));
            }
            if leading_uid != *uid {
                return Err(invalid_data(
                    "body result does not match the exact requested UID",
                ));
            }
            if size.len() != 1 || !internal_dates.is_empty() || body_sections.len() != 1 {
                return Err(invalid_data(
                    "body result does not contain exactly UID, RFC822.SIZE, and one body section",
                ));
            }
            let (section, returned_offset, data) = body_sections[0];
            if section.is_some() || returned_offset != &Some(*offset) {
                return Err(invalid_data(
                    "body section origin does not match requested full-message chunk",
                ));
            }
            let bytes = data
                .as_ref()
                .ok_or_else(|| invalid_data("body response omitted literal data"))?;
            let remaining = size[0]
                .checked_sub(*offset)
                .ok_or_else(|| invalid_data("body response offset exceeds RFC822.SIZE"))?;
            let expected = remaining.min(count.get()) as usize;
            if bytes.len() != expected {
                return Err(invalid_data(
                    "body literal length is inconsistent with request and RFC822.SIZE",
                ));
            }
            accumulator.solicited.push(Solicited::Body {
                uid: leading_uid,
                rfc822_size: size[0],
                offset: *offset,
                bytes: bytes.to_vec(),
            });
        }
        UidOnlyCommand::Examine { .. } | UidOnlyCommand::Noop | UidOnlyCommand::Logout => {
            return Err(invalid_data(
                "non-fetch command received solicited UIDFETCH data",
            ))
        }
    }
    Ok(())
}

fn finalize_command(
    command: &UidOnlyCommand,
    accumulator: Accumulator,
) -> io::Result<CommandOutput> {
    match command {
        UidOnlyCommand::Examine { .. } => {
            if !accumulator.solicited.is_empty() {
                return Err(invalid_data("EXAMINE returned solicited UID data"));
            }
            let exists = accumulator
                .exists
                .ok_or_else(|| invalid_data("EXAMINE omitted EXISTS"))?;
            let uid_validity = accumulator
                .uid_validity
                .ok_or_else(|| invalid_data("EXAMINE omitted UIDVALIDITY"))?;
            let uid_next = accumulator
                .uid_next
                .ok_or_else(|| invalid_data("EXAMINE omitted UIDNEXT"))?;
            if !accumulator.read_only {
                return Err(invalid_data("EXAMINE did not confirm read-only mode"));
            }
            let snapshot_high_uid = NonZeroU32::new(uid_next.get() - 1);
            if snapshot_high_uid
                .map(|high_uid| exists > high_uid.get())
                .unwrap_or(exists != 0)
            {
                return Err(invalid_data("EXAMINE EXISTS is inconsistent with UIDNEXT"));
            }
            Ok(CommandOutput::Examine(MailboxSnapshot {
                exists,
                uid_validity,
                uid_next,
                snapshot_high_uid,
                notifications: accumulator.notifications,
            }))
        }
        UidOnlyCommand::Inventory(request) => {
            let mut items = Vec::with_capacity(accumulator.solicited.len());
            for solicited in accumulator.solicited {
                let Solicited::Inventory(item) = solicited else {
                    return Err(invalid_data("inventory returned body data"));
                };
                items.push(item);
            }
            if items.len() > request.page_size.get() as usize {
                return Err(invalid_data(
                    "inventory returned more results than requested",
                ));
            }
            if items.windows(2).any(|pair| pair[0].uid >= pair[1].uid) {
                return Err(invalid_data(
                    "inventory results are duplicated or out of order",
                ));
            }
            if items.iter().any(|item| {
                accumulator.notifications.iter().any(|notification| {
                    matches!(
                        notification,
                        Notification::Vanished { uids, .. }
                            if uids.iter().any(|range| range.contains(&item.uid.get()))
                    )
                })
            }) {
                return Err(invalid_data(
                    "inventory item and VANISHED notification overlap",
                ));
            }
            Ok(CommandOutput::Inventory(InventoryPage {
                request: *request,
                items,
                notifications: accumulator.notifications,
            }))
        }
        UidOnlyCommand::BodyChunk { uid, .. } => {
            if accumulator.solicited.len() > 1 {
                return Err(invalid_data(
                    "body command returned more than one solicited result",
                ));
            }
            let vanished = accumulator.notifications.iter().any(|notification| {
                matches!(
                    notification,
                    Notification::Vanished { uids, .. }
                        if uids.iter().any(|range| range.contains(&uid.get()))
                )
            });
            match accumulator.solicited.into_iter().next() {
                Some(Solicited::Body {
                    uid,
                    rfc822_size,
                    offset,
                    bytes,
                }) => {
                    if vanished {
                        return Err(invalid_data(
                            "body result and target VANISHED were both reported",
                        ));
                    }
                    Ok(CommandOutput::Body(ExactFetchOutcome::Chunk(BodyChunk {
                        uid,
                        rfc822_size,
                        offset,
                        bytes,
                        notifications: accumulator.notifications,
                    })))
                }
                Some(Solicited::Inventory(_)) => {
                    Err(invalid_data("body command returned inventory metadata"))
                }
                None if vanished => Ok(CommandOutput::Body(ExactFetchOutcome::Vanished {
                    uid: *uid,
                    notifications: accumulator.notifications,
                })),
                None => Ok(CommandOutput::Body(ExactFetchOutcome::Missing {
                    uid: *uid,
                    notifications: accumulator.notifications,
                })),
            }
        }
        UidOnlyCommand::Noop => {
            if !accumulator.solicited.is_empty() {
                return Err(invalid_data("NOOP returned solicited UID data"));
            }
            Ok(CommandOutput::Noop(accumulator.notifications))
        }
        UidOnlyCommand::Logout => {
            if !accumulator.solicited.is_empty() || !accumulator.saw_bye {
                return Err(invalid_data("LOGOUT omitted BYE or returned UID data"));
            }
            Ok(CommandOutput::Logout)
        }
    }
}

/// A validated page which must be persisted before cursor advancement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedInventoryPage {
    request: InventoryRequest,
    items: Vec<InventoryItem>,
    notifications: Vec<Notification>,
    complete_after_commit: bool,
    next_cursor: Option<NonZeroU32>,
}

impl ValidatedInventoryPage {
    /// Records that the caller must persist before calling
    /// [`InventoryPlanner::commit_page`].
    pub fn items(&self) -> &[InventoryItem] {
        &self.items
    }

    /// Allowlisted state changes observed while reading this page.
    pub fn notifications(&self) -> &[Notification] {
        &self.notifications
    }

    pub fn completes_inventory(&self) -> bool {
        self.complete_after_commit
    }
}

/// Two-phase sparse UID inventory state bound to one fixed high UID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryPlanner {
    snapshot_high_uid: Option<NonZeroU32>,
    cursor: Option<NonZeroU32>,
    page_size: NonZeroU32,
    complete: bool,
}

impl InventoryPlanner {
    pub fn new(
        snapshot_high_uid: Option<NonZeroU32>,
        configured_page_size: NonZeroU32,
        advertised_message_limit: Option<NonZeroU32>,
    ) -> Self {
        let page_size = advertised_message_limit
            .map(|limit| configured_page_size.min(limit))
            .unwrap_or(configured_page_size);
        Self {
            snapshot_high_uid,
            cursor: snapshot_high_uid.map(|_| NonZeroU32::MIN),
            page_size,
            complete: snapshot_high_uid.is_none(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn next_request(&self) -> Option<InventoryRequest> {
        if self.complete {
            return None;
        }
        Some(InventoryRequest {
            start: self.cursor.expect("incomplete planner has a cursor"),
            end: self
                .snapshot_high_uid
                .expect("incomplete planner has a fixed high UID"),
            page_size: self.page_size,
        })
    }

    /// Validates without advancing. Persist `validated.items()` durably first.
    pub fn validate_page(&self, page: InventoryPage) -> io::Result<ValidatedInventoryPage> {
        let request = self
            .next_request()
            .ok_or_else(|| invalid_data("inventory is already complete"))?;
        if page.request != request {
            return Err(invalid_data(
                "inventory page does not match the outstanding request",
            ));
        }
        if page.items.windows(2).any(|pair| pair[0].uid >= pair[1].uid)
            || page
                .items
                .iter()
                .any(|item| item.uid < request.start || item.uid > request.end)
        {
            return Err(invalid_data(
                "inventory page is not unique, increasing, and in range",
            ));
        }
        if page.items.len() > request.page_size.get() as usize {
            return Err(invalid_data(
                "inventory page exceeds requested result count",
            ));
        }

        let last = page.items.last().map(|item| item.uid);
        let complete_after_commit = last.is_none() || last == Some(request.end);
        let next_cursor = if complete_after_commit {
            None
        } else {
            NonZeroU32::new(
                last.expect("nonempty incomplete page has a last UID")
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("inventory cursor overflow"))?,
            )
        };
        Ok(ValidatedInventoryPage {
            request,
            items: page.items,
            notifications: page.notifications,
            complete_after_commit,
            next_cursor,
        })
    }

    /// Advances only after the caller has durably persisted the validated page.
    pub fn commit_page(&mut self, validated: ValidatedInventoryPage) -> io::Result<()> {
        if self.next_request() != Some(validated.request) {
            return Err(invalid_data(
                "validated inventory page is stale or belongs to another planner state",
            ));
        }
        self.complete = validated.complete_after_commit;
        self.cursor = validated.next_cursor;
        Ok(())
    }
}

/// Computes `remote - locally_verified` for strict, increasing UID lists.
pub fn missing_verified_uids(
    remote: &[NonZeroU32],
    locally_verified: &[NonZeroU32],
) -> io::Result<Vec<NonZeroU32>> {
    validate_uid_list(remote, "remote")?;
    validate_uid_list(locally_verified, "local")?;
    let mut missing = Vec::new();
    let mut local_index = 0;
    for remote_uid in remote {
        while locally_verified
            .get(local_index)
            .is_some_and(|local_uid| local_uid < remote_uid)
        {
            local_index += 1;
        }
        if locally_verified.get(local_index) != Some(remote_uid) {
            missing.push(*remote_uid);
        }
    }
    Ok(missing)
}

fn validate_uid_list(uids: &[NonZeroU32], label: &str) -> io::Result<()> {
    if uids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} UID list must be strictly increasing and unique"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
