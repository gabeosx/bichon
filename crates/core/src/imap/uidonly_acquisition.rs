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

//! UID-safe, restartable mailbox acquisition.
//!
//! This module is intentionally separate from Bichon's legacy sequence-number
//! downloader. A UIDONLY session never reaches code which can issue ordinary
//! FETCH, SEARCH, STORE, COPY, or MOVE commands.

use crate::account::migration::AccountModel;
use crate::cache::imap::mailbox::MailBox;
use crate::envelope::extractor::{
    project_uidonly_message, reattach_eml_content, rollback_uidonly_message, CanonicalProjection,
};
use crate::error::code::ErrorCode;
use crate::error::{BichonError, BichonResult};
use crate::imap::manager::{AcquisitionConnection, ImapConnectionManager};
use crate::imap::session::SessionStream;
use crate::message::content::AttachmentInfo;
use crate::raise_error;
use crate::store::tantivy::attachment::{CanonicalAttachmentRecord, ATTACHMENT_MANAGER};
use crate::store::tantivy::dedup::UIDONLY_SHARD_ID;
use crate::store::tantivy::envelope::ENVELOPE_MANAGER;
use crate::utils::compute_content_hash;
use async_imap::types::{PartialRange, ResponseLimits, UidOnlyUnsolicitedResponse};
use async_imap::Session;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    LazyLock,
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const BODY_QUERY: &str = "(UID RFC822.SIZE BODY.PEEK[])";
const INVENTORY_QUERY: &str = "(UID RFC822.SIZE)";
const MAX_NETWORK_RETRIES: u32 = 3;
#[cfg(not(test))]
const CANONICAL_CLEANUP_GRACE: Duration = Duration::from_secs(5);
#[cfg(test)]
const CANONICAL_CLEANUP_GRACE: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AcquisitionLimits {
    pub max_messages: usize,
    pub max_total_bytes: u64,
    pub max_literal_bytes: u64,
    pub max_response_bytes: u64,
    pub max_runtime: Duration,
    pub max_disk_bytes: u64,
    pub page_size: u32,
}

impl AcquisitionLimits {
    pub fn for_account(account: &AccountModel) -> Self {
        let literal = account.max_email_size_bytes.unwrap_or(100 * 1024 * 1024);
        Self {
            max_messages: 1_000_000,
            max_total_bytes: 100 * 1024 * 1024 * 1024,
            max_literal_bytes: literal,
            max_response_bytes: literal.saturating_add(1024 * 1024),
            max_runtime: Duration::from_secs(6 * 60 * 60),
            max_disk_bytes: 120 * 1024 * 1024 * 1024,
            page_size: account.download_batch_size.unwrap_or(30).max(1),
        }
    }

    pub fn response_limits(self) -> BichonResult<ResponseLimits> {
        let response = usize::try_from(self.max_response_bytes).map_err(|_| {
            raise_error!(
                "response ceiling does not fit usize".into(),
                ErrorCode::InvalidParameter
            )
        })?;
        let literal = usize::try_from(self.max_literal_bytes).map_err(|_| {
            raise_error!(
                "literal ceiling does not fit usize".into(),
                ErrorCode::InvalidParameter
            )
        })?;
        if literal == 0 || response < literal {
            return Err(raise_error!(
                "UIDONLY response limits must be nonzero and response >= literal".into(),
                ErrorCode::InvalidParameter
            ));
        }
        Ok(ResponseLimits::new(response, literal))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AcquisitionIdentity {
    pub endpoint: String,
    pub account_id: u64,
    pub canonical_mailbox: String,
}

impl AcquisitionIdentity {
    pub fn from_account(account: &AccountModel, mailbox: &MailBox) -> BichonResult<Self> {
        let imap = account.imap.as_ref().ok_or_else(|| {
            raise_error!(
                "IMAP account has no endpoint".into(),
                ErrorCode::MissingConfiguration
            )
        })?;
        Ok(Self {
            endpoint: format!("{}:{}", imap.host.to_ascii_lowercase(), imap.port),
            account_id: account.id,
            canonical_mailbox: mailbox.name.clone(),
        })
    }

    fn storage_key(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.endpoint.as_bytes());
        hasher.update(&[0]);
        hasher.update(&self.account_id.to_be_bytes());
        hasher.update(&[0]);
        hasher.update(self.canonical_mailbox.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum UidState {
    Missing,
    Pending,
    Projecting {
        blob_hash: String,
        bytes: u64,
        canonical_bytes: u64,
    },
    Committed {
        blob_hash: String,
        bytes: u64,
        #[serde(default)]
        canonical_bytes: u64,
        #[serde(default)]
        envelope_id: Option<String>,
    },
    Vanished,
    Failed {
        reason: String,
    },
    Oversized {
        declared: u64,
        limit: u64,
    },
}

impl UidState {
    fn reconciled(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Vanished)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct UidEntry {
    pub declared_size: Option<u64>,
    pub state: UidState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AcquisitionLedger {
    pub identity: AcquisitionIdentity,
    pub uid_validity: u32,
    pub snapshot_end: u32,
    pub checkpoint: Option<u32>,
    pub entries: BTreeMap<u32, UidEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub uid_validity: u32,
    pub uid_next: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventoryItem {
    pub uid: u32,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventoryPage {
    pub items: Vec<InventoryItem>,
    pub vanished: Vec<RangeInclusive<u32>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FetchOutcome {
    Message {
        declared_size: Option<u64>,
        raw: Vec<u8>,
    },
    Vanished,
    Missing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportFailure {
    pub message: String,
    pub network: bool,
}

impl TransportFailure {
    fn command(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            network: false,
        }
    }
}

#[allow(async_fn_in_trait)]
pub(crate) trait UidOnlyTransport {
    async fn snapshot(&mut self, mailbox: &str) -> Result<Snapshot, TransportFailure>;
    async fn inventory_page(
        &mut self,
        first_uid: u32,
        snapshot_end: u32,
        page_size: u32,
    ) -> Result<InventoryPage, TransportFailure>;
    async fn fetch_uid(&mut self, uid: u32) -> Result<FetchOutcome, TransportFailure>;
    async fn reconnect(&mut self) -> Result<(), TransportFailure>;
}

#[allow(async_fn_in_trait)]
trait CanonicalArchive {
    fn disk_budget(&self, raw: &[u8]) -> BichonResult<u64>;

    async fn project(
        &mut self,
        uid: u32,
        raw: &[u8],
        declared_size: Option<u64>,
        shutdown: CancellationToken,
    ) -> BichonResult<CanonicalProjection>;

    async fn verify(&self, uid: u32, blob_hash: &str, envelope_id: &str) -> BichonResult<bool>;
    async fn rollback(
        &mut self,
        uid: u32,
        content_hash: &str,
        envelope_id: Option<&str>,
    ) -> BichonResult<()>;
}

struct BichonCanonicalArchive {
    account_id: u64,
    mailbox_id: u64,
}

static UIDONLY_CANONICAL_WRITE_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

fn canonical_attachment_records(
    attachments: Vec<AttachmentInfo>,
) -> Vec<CanonicalAttachmentRecord> {
    let mut records: Vec<_> = attachments
        .into_iter()
        .filter(|attachment| !attachment.is_inline())
        .map(|attachment| CanonicalAttachmentRecord {
            content_hash: attachment.content_hash,
            name: attachment.filename,
            size: attachment.size as u64,
            content_type: attachment.file_type,
        })
        .collect();
    records.sort();
    records
}

impl BichonCanonicalArchive {
    fn new(account_id: u64, mailbox_id: u64) -> Self {
        Self {
            account_id,
            mailbox_id,
        }
    }

    fn envelope_id(&self, uid: u32, content_hash: &str) -> String {
        Self::envelope_id_for(self.account_id, self.mailbox_id, uid, content_hash)
    }

    fn envelope_id_for(account_id: u64, mailbox_id: u64, uid: u32, content_hash: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bichon-uidonly-envelope-v1");
        hasher.update(&account_id.to_be_bytes());
        hasher.update(&mailbox_id.to_be_bytes());
        hasher.update(&uid.to_be_bytes());
        hasher.update(content_hash.as_bytes());
        format!("uidonly-{}", hasher.finalize().to_hex())
    }

    fn reuse_projection(
        uid: u32,
        expected_hash: &str,
        existing: crate::store::tantivy::envelope::CanonicalProjectionRecord,
    ) -> BichonResult<CanonicalProjection> {
        if existing.shard_id != UIDONLY_SHARD_ID {
            return Err(raise_error!(
                format!(
                    "UID {uid} is occupied by a non-UIDONLY canonical record (shard {})",
                    existing.shard_id
                ),
                ErrorCode::Incompatible
            ));
        }
        if existing.content_hash != expected_hash {
            return Err(raise_error!(
                format!(
                    "canonical UID {uid} has content hash {}, expected {expected_hash}",
                    existing.content_hash
                ),
                ErrorCode::Incompatible
            ));
        }
        Ok(CanonicalProjection {
            envelope_id: existing.envelope_id,
            content_hash: existing.content_hash,
        })
    }
}

impl CanonicalArchive for BichonCanonicalArchive {
    fn disk_budget(&self, raw: &[u8]) -> BichonResult<u64> {
        (raw.len() as u64)
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or_else(|| {
                raise_error!(
                    "canonical projection disk budget overflow".into(),
                    ErrorCode::PayloadTooLarge
                )
            })
    }

    async fn project(
        &mut self,
        uid: u32,
        raw: &[u8],
        _declared_size: Option<u64>,
        shutdown: CancellationToken,
    ) -> BichonResult<CanonicalProjection> {
        let account_id = self.account_id;
        let mailbox_id = self.mailbox_id;
        let body = raw.to_vec();
        let task = tokio::spawn(async move {
            // The task owns the body, shutdown token, and serialization guard.
            // Dropping its JoinHandle detaches a self-cleaning operation; it
            // does not drop the projection future around spawn_blocking I/O.
            let _write_guard = UIDONLY_CANONICAL_WRITE_LOCK.lock().await;
            if shutdown.is_cancelled() {
                return Err(raise_error!(
                    "UIDONLY canonical projection cancelled".into(),
                    ErrorCode::InternalError
                ));
            }
            let expected_hash = compute_content_hash(&body);
            if let Some(existing) =
                ENVELOPE_MANAGER.get_projection_by_uid(account_id, mailbox_id, uid)?
            {
                return Self::reuse_projection(uid, &expected_hash, existing);
            }
            let size = u32::try_from(body.len()).map_err(|_| {
                raise_error!(
                    format!("UID {uid} literal length does not fit Bichon's envelope size field"),
                    ErrorCode::PayloadTooLarge
                )
            })?;
            let envelope_id = Self::envelope_id_for(account_id, mailbox_id, uid, &expected_hash);
            project_uidonly_message(
                &body,
                uid,
                size,
                0,
                account_id,
                mailbox_id,
                envelope_id,
                shutdown,
            )
            .await
        });
        task.await
            .map_err(|error| raise_error!(format!("{error:#?}"), ErrorCode::InternalError))?
    }

    async fn verify(&self, uid: u32, blob_hash: &str, envelope_id: &str) -> BichonResult<bool> {
        let Some(record) =
            ENVELOPE_MANAGER.get_projection_by_uid(self.account_id, self.mailbox_id, uid)?
        else {
            return Ok(false);
        };
        if record.envelope_id != envelope_id || record.content_hash != blob_hash {
            return Ok(false);
        }
        if record.shard_id != UIDONLY_SHARD_ID {
            return Ok(false);
        }
        let expected_attachments = canonical_attachment_records(record.attachments);
        if ATTACHMENT_MANAGER.canonical_records_by_envelope(self.account_id, envelope_id)?
            != expected_attachments
        {
            return Ok(false);
        }
        let (envelope, raw) = match reattach_eml_content(self.account_id, envelope_id.to_string()) {
            Ok(value) => value,
            Err(error) if error.code() == ErrorCode::ResourceNotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if expected_attachments.len() != envelope.regular_attachment_count {
            return Ok(false);
        }
        Ok(compute_content_hash(&raw) == blob_hash)
    }

    async fn rollback(
        &mut self,
        uid: u32,
        content_hash: &str,
        envelope_id: Option<&str>,
    ) -> BichonResult<()> {
        let _write_guard = UIDONLY_CANONICAL_WRITE_LOCK.lock().await;
        let envelope_id = envelope_id
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| self.envelope_id(uid, content_hash));
        rollback_uidonly_message(self.account_id, &envelope_id, content_hash).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquisitionReport {
    pub uid_validity: u32,
    pub planned: u64,
    pub processed: u64,
    pub checkpoint: Option<u32>,
    pub success: bool,
    pub states: BTreeMap<u32, UidState>,
    #[cfg(test)]
    state_bytes_written: u64,
}

struct DurableArchive {
    epoch_dir: PathBuf,
    ledger_path: PathBuf,
    ledger_entries_dir: PathBuf,
    limits: AcquisitionLimits,
    disk_bytes: AtomicU64,
    #[cfg(test)]
    state_bytes_written: AtomicU64,
}

#[derive(Serialize, Deserialize)]
struct LedgerMetadata {
    identity: AcquisitionIdentity,
    uid_validity: u32,
    snapshot_end: u32,
    checkpoint: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct StagingRecord {
    identity: AcquisitionIdentity,
    uid_validity: u32,
    uid: u32,
    blob_hash: String,
    bytes: u64,
}

impl DurableArchive {
    fn open(
        root: &Path,
        identity: &AcquisitionIdentity,
        uid_validity: u32,
        limits: AcquisitionLimits,
    ) -> BichonResult<Self> {
        let identity_dir = root.join(identity.storage_key());
        fs::create_dir_all(&identity_dir).map_err(io_error)?;
        let epoch_marker = identity_dir.join("current-uidvalidity");
        if epoch_marker.exists() {
            let existing = fs::read_to_string(&epoch_marker).map_err(io_error)?;
            if existing.trim() != uid_validity.to_string() {
                // The download flow performs Bichon's Message-ID based
                // UIDVALIDITY reconciliation before entering acquisition. A
                // new epoch must not reuse the prior UID ledger, but it also
                // must not replace that existing reconciliation with a
                // campaign-specific terminal error.
                atomic_write(&epoch_marker, uid_validity.to_string().as_bytes())?;
            }
        } else {
            atomic_write(&epoch_marker, uid_validity.to_string().as_bytes())?;
        }

        let epoch_dir = identity_dir.join(uid_validity.to_string());
        fs::create_dir_all(epoch_dir.join("blobs")).map_err(io_error)?;
        fs::create_dir_all(epoch_dir.join("records")).map_err(io_error)?;
        let ledger_entries_dir = epoch_dir.join("ledger-entries");
        fs::create_dir_all(&ledger_entries_dir).map_err(io_error)?;
        let ledger_path = epoch_dir.join("ledger.json");
        let disk_bytes = directory_size(&identity_dir)?;
        if disk_bytes > limits.max_disk_bytes {
            return Err(raise_error!(
                format!(
                    "UIDONLY disk ceiling {} bytes already exceeded",
                    limits.max_disk_bytes
                ),
                ErrorCode::PayloadTooLarge
            ));
        }
        Ok(Self {
            epoch_dir,
            ledger_path,
            ledger_entries_dir,
            limits,
            disk_bytes: AtomicU64::new(disk_bytes),
            #[cfg(test)]
            state_bytes_written: AtomicU64::new(0),
        })
    }

    fn reserve_disk(&self, additional: u64) -> BichonResult<()> {
        self.disk_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let next = current.checked_add(additional)?;
                (next <= self.limits.max_disk_bytes).then_some(next)
            })
            .map(|_| ())
            .map_err(|_| {
                raise_error!(
                    format!(
                        "UIDONLY disk ceiling {} bytes exceeded",
                        self.limits.max_disk_bytes
                    ),
                    ErrorCode::PayloadTooLarge
                )
            })
    }

    fn release_disk(&self, bytes: u64) {
        self.disk_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    fn load_or_create(
        &self,
        identity: AcquisitionIdentity,
        uid_validity: u32,
        snapshot_end: u32,
    ) -> BichonResult<AcquisitionLedger> {
        if self.ledger_path.exists() {
            let bytes = fs::read(&self.ledger_path).map_err(io_error)?;
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
                raise_error!(
                    format!("invalid UIDONLY ledger: {e}"),
                    ErrorCode::InternalError
                )
            })?;
            let mut ledger = if value.get("entries").is_some() {
                let legacy: AcquisitionLedger = serde_json::from_value(value).map_err(|e| {
                    raise_error!(
                        format!("invalid legacy UIDONLY ledger: {e}"),
                        ErrorCode::InternalError
                    )
                })?;
                for (&uid, entry) in &legacy.entries {
                    self.persist_entry(uid, entry)?;
                }
                self.persist_metadata(&legacy)?;
                legacy
            } else {
                let metadata: LedgerMetadata = serde_json::from_value(value).map_err(|e| {
                    raise_error!(
                        format!("invalid UIDONLY ledger metadata: {e}"),
                        ErrorCode::InternalError
                    )
                })?;
                AcquisitionLedger {
                    identity: metadata.identity,
                    uid_validity: metadata.uid_validity,
                    snapshot_end: metadata.snapshot_end,
                    checkpoint: metadata.checkpoint,
                    entries: BTreeMap::new(),
                }
            };
            for file in fs::read_dir(&self.ledger_entries_dir).map_err(io_error)? {
                let file = file.map_err(io_error)?;
                if !file.file_type().map_err(io_error)?.is_file() {
                    continue;
                }
                let uid = file
                    .path()
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .and_then(|stem| stem.parse::<u32>().ok())
                    .ok_or_else(|| {
                        raise_error!(
                            "invalid UIDONLY ledger entry filename".into(),
                            ErrorCode::InternalError
                        )
                    })?;
                let entry =
                    serde_json::from_slice::<UidEntry>(&fs::read(file.path()).map_err(io_error)?)
                        .map_err(|e| {
                        raise_error!(
                            format!("invalid UIDONLY ledger entry for UID {uid}: {e}"),
                            ErrorCode::InternalError
                        )
                    })?;
                ledger.entries.insert(uid, entry);
            }
            if ledger.identity != identity || ledger.uid_validity != uid_validity {
                return Err(raise_error!(
                    "UIDONLY ledger identity mismatch".into(),
                    ErrorCode::Incompatible
                ));
            }
            return Ok(ledger);
        }
        let ledger = AcquisitionLedger {
            identity,
            uid_validity,
            snapshot_end,
            checkpoint: None,
            entries: BTreeMap::new(),
        };
        self.persist_metadata(&ledger)?;
        Ok(ledger)
    }

    fn persist_metadata(&self, ledger: &AcquisitionLedger) -> BichonResult<()> {
        let bytes = serde_json::to_vec(&LedgerMetadata {
            identity: ledger.identity.clone(),
            uid_validity: ledger.uid_validity,
            snapshot_end: ledger.snapshot_end,
            checkpoint: ledger.checkpoint,
        })
        .map_err(|e| {
            raise_error!(
                format!("cannot serialize UIDONLY ledger metadata: {e}"),
                ErrorCode::InternalError
            )
        })?;
        let previous = fs::metadata(&self.ledger_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        self.reserve_disk((bytes.len() as u64).saturating_sub(previous))?;
        self.record_state_write(bytes.len() as u64);
        atomic_write(&self.ledger_path, &bytes)
    }

    fn persist_entry(&self, uid: u32, entry: &UidEntry) -> BichonResult<()> {
        #[cfg(test)]
        if matches!(entry.state, UidState::Committed { .. }) {
            let failpoint = self.epoch_dir.join("fail-next-committed-entry-persist");
            if failpoint.exists() {
                fs::remove_file(failpoint).map_err(io_error)?;
                return Err(raise_error!(
                    "synthetic committed ledger persist failure".into(),
                    ErrorCode::InternalError
                ));
            }
        }
        let path = self.ledger_entries_dir.join(format!("{uid}.json"));
        let bytes = serde_json::to_vec(entry).map_err(|e| {
            raise_error!(
                format!("cannot serialize UIDONLY ledger entry {uid}: {e}"),
                ErrorCode::InternalError
            )
        })?;
        let previous = fs::metadata(&path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        self.reserve_disk((bytes.len() as u64).saturating_sub(previous))?;
        self.record_state_write(bytes.len() as u64);
        atomic_write(&path, &bytes)
    }

    #[cfg(test)]
    fn record_state_write(&self, bytes: u64) {
        self.state_bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    #[cfg(not(test))]
    fn record_state_write(&self, _bytes: u64) {}

    fn commit_raw(
        &self,
        ledger: &AcquisitionLedger,
        uid: u32,
        raw: &[u8],
    ) -> BichonResult<(String, u64)> {
        let hash = blake3::hash(raw).to_hex().to_string();
        let blob_path = self.epoch_dir.join("blobs").join(&hash);
        let record_path = self.epoch_dir.join("records").join(format!("{uid}.json"));
        let blob_was_present = blob_path.exists();
        if !blob_was_present {
            self.reserve_disk(raw.len() as u64)?;
        }

        if blob_was_present {
            let mut existing = Vec::new();
            File::open(&blob_path)
                .and_then(|mut f| f.read_to_end(&mut existing))
                .map_err(io_error)?;
            if blake3::hash(&existing).to_hex().as_str() != hash || existing != raw {
                return Err(raise_error!(
                    format!("stored blob verification failed for UID {uid}"),
                    ErrorCode::InternalError
                ));
            }
        } else {
            atomic_write(&blob_path, raw)?;
            let stored = fs::read(&blob_path).map_err(io_error)?;
            if stored.len() != raw.len() || blake3::hash(&stored).to_hex().as_str() != hash {
                return Err(raise_error!(
                    format!("durable blob readback failed for UID {uid}"),
                    ErrorCode::InternalError
                ));
            }
        }

        let record = serde_json::to_vec_pretty(&StagingRecord {
            identity: ledger.identity.clone(),
            uid_validity: ledger.uid_validity,
            uid,
            blob_hash: hash.clone(),
            bytes: raw.len() as u64,
        })
        .map_err(|e| {
            raise_error!(
                format!("cannot serialize logical record: {e}"),
                ErrorCode::InternalError
            )
        })?;
        let previous_record = fs::metadata(&record_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let record_additional = (record.len() as u64).saturating_sub(previous_record);
        self.reserve_disk(record_additional)?;
        atomic_write(&record_path, &record)?;

        Ok((hash, raw.len() as u64))
    }

    fn reclaim_committed_staging(&self, ledger: &AcquisitionLedger) -> BichonResult<()> {
        for (&uid, entry) in &ledger.entries {
            if matches!(entry.state, UidState::Committed { .. }) {
                let path = self.epoch_dir.join("records").join(format!("{uid}.json"));
                if let Ok(metadata) = fs::metadata(&path) {
                    fs::remove_file(&path).map_err(io_error)?;
                    self.disk_bytes.fetch_sub(metadata.len(), Ordering::AcqRel);
                }
            }
        }

        let mut referenced = BTreeSet::new();
        for entry in fs::read_dir(self.epoch_dir.join("records")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if !entry.file_type().map_err(io_error)?.is_file() {
                continue;
            }
            let record: StagingRecord = serde_json::from_slice(
                &fs::read(entry.path()).map_err(io_error)?,
            )
            .map_err(|error| {
                raise_error!(
                    format!("invalid UIDONLY staging record: {error}"),
                    ErrorCode::InternalError
                )
            })?;
            referenced.insert(record.blob_hash);
        }

        for entry in fs::read_dir(self.epoch_dir.join("blobs")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if !entry.file_type().map_err(io_error)?.is_file() {
                continue;
            }
            let hash = entry.file_name().to_string_lossy().to_string();
            if !referenced.contains(&hash) {
                let metadata = entry.metadata().map_err(io_error)?;
                fs::remove_file(entry.path()).map_err(io_error)?;
                self.disk_bytes.fetch_sub(metadata.len(), Ordering::AcqRel);
            }
        }
        File::open(&self.epoch_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)
    }
}

fn io_error(error: std::io::Error) -> crate::error::BichonError {
    raise_error!(
        format!("UIDONLY durable I/O failed: {error}"),
        ErrorCode::InternalError
    )
}

fn atomic_write(path: &Path, bytes: &[u8]) -> BichonResult<()> {
    let parent = path.parent().ok_or_else(|| {
        raise_error!(
            "atomic write path has no parent".into(),
            ErrorCode::InternalError
        )
    })?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(io_error)?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(io_error)
}

fn directory_size(path: &Path) -> BichonResult<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let metadata = entry.metadata().map_err(io_error)?;
        total = total.saturating_add(if metadata.is_dir() {
            directory_size(&entry.path())?
        } else {
            metadata.len()
        });
    }
    Ok(total)
}

fn cleanup_uidonly_state(
    root: &Path,
    matches: impl Fn(&AcquisitionIdentity) -> bool,
) -> BichonResult<usize> {
    if !root.exists() {
        return Ok(0);
    }
    let mut remove = Vec::new();
    for identity_dir in fs::read_dir(root).map_err(io_error)? {
        let identity_dir = identity_dir.map_err(io_error)?;
        if !identity_dir.file_type().map_err(io_error)?.is_dir() {
            continue;
        }
        let mut identity = None;
        for epoch in fs::read_dir(identity_dir.path()).map_err(io_error)? {
            let epoch = epoch.map_err(io_error)?;
            if !epoch.file_type().map_err(io_error)?.is_dir() {
                continue;
            }
            let ledger = epoch.path().join("ledger.json");
            if !ledger.exists() {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(&ledger).map_err(io_error)?).map_err(|error| {
                    raise_error!(
                        format!(
                            "invalid UIDONLY cleanup ledger {}: {error}",
                            ledger.display()
                        ),
                        ErrorCode::InternalError
                    )
                })?;
            identity = Some(
                serde_json::from_value::<AcquisitionIdentity>(
                    value.get("identity").cloned().ok_or_else(|| {
                        raise_error!(
                            format!(
                                "UIDONLY cleanup ledger {} has no identity",
                                ledger.display()
                            ),
                            ErrorCode::InternalError
                        )
                    })?,
                )
                .map_err(|error| {
                    raise_error!(
                        format!(
                            "invalid UIDONLY cleanup identity {}: {error}",
                            ledger.display()
                        ),
                        ErrorCode::InternalError
                    )
                })?,
            );
            break;
        }
        if identity.as_ref().map(&matches).unwrap_or(false) {
            remove.push(identity_dir.path());
        }
    }
    for path in &remove {
        fs::remove_dir_all(path).map_err(io_error)?;
    }
    if !remove.is_empty() {
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
    }
    Ok(remove.len())
}

pub(crate) fn cleanup_uidonly_account_state(root: &Path, account_id: u64) -> BichonResult<usize> {
    cleanup_uidonly_state(root, |identity| identity.account_id == account_id)
}

pub(crate) fn cleanup_uidonly_mailbox_state(
    root: &Path,
    account_id: u64,
    canonical_mailboxes: &BTreeSet<String>,
) -> BichonResult<usize> {
    cleanup_uidonly_state(root, |identity| {
        identity.account_id == account_id
            && canonical_mailboxes.contains(&identity.canonical_mailbox)
    })
}

fn validate_runtime(
    started: Instant,
    limits: AcquisitionLimits,
    token: &CancellationToken,
) -> BichonResult<()> {
    if token.is_cancelled() {
        return Err(raise_error!(
            "UIDONLY acquisition cancelled".into(),
            ErrorCode::InternalError
        ));
    }
    if started.elapsed() > limits.max_runtime {
        return Err(raise_error!(
            "UIDONLY acquisition runtime ceiling exceeded".into(),
            ErrorCode::RequestTimeout
        ));
    }
    Ok(())
}

async fn bounded_transport<F, T>(
    operation: F,
    started: Instant,
    limits: AcquisitionLimits,
    token: &CancellationToken,
) -> BichonResult<T>
where
    F: Future<Output = Result<T, TransportFailure>>,
{
    validate_runtime(started, limits, token)?;
    let remaining = limits
        .max_runtime
        .checked_sub(started.elapsed())
        .ok_or_else(|| {
            raise_error!(
                "UIDONLY acquisition runtime ceiling exceeded".into(),
                ErrorCode::RequestTimeout
            )
        })?;
    tokio::select! {
        _ = token.cancelled() => Err(raise_error!(
            "UIDONLY acquisition cancelled".into(),
            ErrorCode::InternalError
        )),
        _ = tokio::time::sleep(remaining) => Err(raise_error!(
            "UIDONLY acquisition runtime ceiling exceeded".into(),
            ErrorCode::RequestTimeout
        )),
        result = operation => result.map_err(transport_error),
    }
}

async fn bounded_canonical<F, T>(
    operation: F,
    started: Instant,
    limits: AcquisitionLimits,
    token: &CancellationToken,
    operation_shutdown: Option<&CancellationToken>,
) -> Result<T, BoundedCanonicalFailure>
where
    F: Future<Output = BichonResult<T>>,
{
    validate_runtime(started, limits, token).map_err(BoundedCanonicalFailure::quiesced)?;
    let remaining = limits
        .max_runtime
        .checked_sub(started.elapsed())
        .ok_or_else(|| {
            BoundedCanonicalFailure::quiesced(raise_error!(
                "UIDONLY acquisition runtime ceiling exceeded".into(),
                ErrorCode::RequestTimeout
            ))
        })?;
    tokio::pin!(operation);
    enum Boundary {
        Cancelled,
        Runtime,
    }
    let boundary = tokio::select! {
        _ = token.cancelled() => Some(Boundary::Cancelled),
        _ = tokio::time::sleep(remaining) => Some(Boundary::Runtime),
        result = &mut operation => return result.map_err(BoundedCanonicalFailure::quiesced),
    };
    if let Some(shutdown) = operation_shutdown {
        shutdown.cancel();
    }
    // The production projection future awaits an owned, self-cleaning task
    // that retains the UIDONLY write lock. Give it a bounded opportunity to
    // finish. If OS-backed blocking I/O does not return, dropping the
    // JoinHandle only detaches that owned task; later projection/rollback is
    // serialized behind it until it observes shutdown and rolls itself back.
    let cleanup_pending = tokio::time::timeout(CANONICAL_CLEANUP_GRACE, &mut operation)
        .await
        .is_err();
    let error = match boundary.unwrap() {
        Boundary::Cancelled => raise_error!(
            "UIDONLY acquisition cancelled during canonical projection".into(),
            ErrorCode::InternalError
        ),
        Boundary::Runtime => raise_error!(
            "UIDONLY acquisition runtime ceiling exceeded during canonical projection".into(),
            ErrorCode::RequestTimeout
        ),
    };
    Err(BoundedCanonicalFailure {
        error,
        cleanup_pending,
    })
}

struct BoundedCanonicalFailure {
    error: BichonError,
    cleanup_pending: bool,
}

impl BoundedCanonicalFailure {
    fn quiesced(error: BichonError) -> Self {
        Self {
            error,
            cleanup_pending: false,
        }
    }
}

impl From<BoundedCanonicalFailure> for BichonError {
    fn from(failure: BoundedCanonicalFailure) -> Self {
        failure.error
    }
}

async fn cleanup_canonical<C: CanonicalArchive>(
    canonical: &mut C,
    uid: u32,
    content_hash: &str,
    envelope_id: Option<&str>,
) -> BichonResult<()> {
    tokio::time::timeout(
        CANONICAL_CLEANUP_GRACE,
        canonical.rollback(uid, content_hash, envelope_id),
    )
    .await
    .map_err(|_| {
        raise_error!(
            "UIDONLY canonical rollback timed out".into(),
            ErrorCode::RequestTimeout
        )
    })?
}

async fn run_acquisition<T: UidOnlyTransport, C: CanonicalArchive>(
    transport: &mut T,
    canonical: &mut C,
    mailbox: &str,
    identity: AcquisitionIdentity,
    root: &Path,
    limits: AcquisitionLimits,
    token: CancellationToken,
) -> BichonResult<AcquisitionReport> {
    let started = Instant::now();
    let snapshot = bounded_transport(transport.snapshot(mailbox), started, limits, &token).await?;
    let snapshot_end = snapshot.uid_next.saturating_sub(1);
    let archive = DurableArchive::open(root, &identity, snapshot.uid_validity, limits)?;
    let mut ledger = archive.load_or_create(identity, snapshot.uid_validity, snapshot_end)?;
    let existing_canonical_bytes = ledger
        .entries
        .values()
        .filter_map(|entry| match entry.state {
            UidState::Committed {
                canonical_bytes, ..
            }
            | UidState::Projecting {
                canonical_bytes, ..
            } => Some(canonical_bytes),
            _ => None,
        })
        .fold(0u64, u64::saturating_add);
    archive.reserve_disk(existing_canonical_bytes)?;

    // A Projecting entry proves the reservation was durable before canonical
    // writes started, but not that projection reached its success barrier.
    // Reconcile it idempotently before retrying the UID in this run.
    let interrupted: Vec<_> = ledger
        .entries
        .iter()
        .filter_map(|(&uid, entry)| match &entry.state {
            UidState::Projecting {
                blob_hash,
                canonical_bytes,
                ..
            } => Some((uid, blob_hash.clone(), *canonical_bytes)),
            _ => None,
        })
        .collect();
    for (uid, blob_hash, canonical_bytes) in interrupted {
        cleanup_canonical(canonical, uid, &blob_hash, None).await?;
        archive.release_disk(canonical_bytes);
        ledger.entries.get_mut(&uid).unwrap().state = UidState::Missing;
        archive.persist_entry(uid, &ledger.entries[&uid])?;
        ledger.checkpoint = None;
    }
    if ledger.checkpoint.is_none() {
        archive.persist_metadata(&ledger)?;
    }

    let mut invalid_committed = BTreeSet::new();
    let committed: Vec<_> = ledger
        .entries
        .iter()
        .filter_map(|(&uid, entry)| match &entry.state {
            UidState::Committed {
                blob_hash,
                canonical_bytes,
                envelope_id,
                ..
            } => Some((
                uid,
                blob_hash.clone(),
                *canonical_bytes,
                envelope_id.clone(),
            )),
            _ => None,
        })
        .collect();
    for (uid, blob_hash, canonical_bytes, envelope_id) in committed {
        let valid = match envelope_id.as_deref() {
            Some(envelope_id) => {
                bounded_canonical(
                    canonical.verify(uid, &blob_hash, envelope_id),
                    started,
                    limits,
                    &token,
                    None,
                )
                .await?
            }
            None => false,
        };
        if !valid {
            cleanup_canonical(canonical, uid, &blob_hash, envelope_id.as_deref()).await?;
            archive.release_disk(canonical_bytes);
            ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                reason: "committed canonical record or blob failed restart validation".into(),
            };
            archive.persist_entry(uid, &ledger.entries[&uid])?;
            ledger.checkpoint = None;
            invalid_committed.insert(uid);
        }
    }
    if !invalid_committed.is_empty() {
        archive.persist_metadata(&ledger)?;
    }
    // A restart continues the original fixed snapshot even if UIDNEXT grew.
    let snapshot_end = ledger.snapshot_end;

    let page_size = limits.page_size.max(1);
    let mut first_uid = 1u32;
    while first_uid <= snapshot_end {
        validate_runtime(started, limits, &token)?;
        let page = bounded_transport(
            transport.inventory_page(first_uid, snapshot_end, page_size),
            started,
            limits,
            &token,
        )
        .await?;
        for range in page.vanished {
            let mut changed = Vec::new();
            for (&uid, entry) in ledger.entries.range_mut(range) {
                if !matches!(entry.state, UidState::Committed { .. } | UidState::Vanished) {
                    entry.state = UidState::Vanished;
                    changed.push(uid);
                }
            }
            for uid in changed {
                archive.persist_entry(uid, &ledger.entries[&uid])?;
            }
        }
        if page.items.is_empty() {
            break;
        }
        let mut previous = first_uid.saturating_sub(1);
        for item in page.items {
            if item.uid < first_uid || item.uid > snapshot_end || item.uid <= previous {
                return Err(raise_error!(
                    "UIDONLY inventory was not strictly ascending within the fixed snapshot".into(),
                    ErrorCode::ImapUnexpectedResult
                ));
            }
            previous = item.uid;
            let mut changed = false;
            let entry = ledger.entries.entry(item.uid).or_insert_with(|| {
                changed = true;
                UidEntry {
                    declared_size: item.size,
                    state: UidState::Missing,
                }
            });
            if entry.declared_size.is_none() && item.size.is_some() {
                entry.declared_size = item.size;
                changed = true;
            }
            if changed {
                archive.persist_entry(item.uid, entry)?;
            }
        }
        first_uid = previous.checked_add(1).ok_or_else(|| {
            raise_error!(
                "UID cursor overflow".into(),
                ErrorCode::ImapUnexpectedResult
            )
        })?;
        if ledger.entries.len() > limits.max_messages {
            return Err(raise_error!(
                format!("UIDONLY message ceiling {} exceeded", limits.max_messages),
                ErrorCode::PayloadTooLarge
            ));
        }
    }

    let uids: Vec<u32> = ledger.entries.keys().copied().collect();
    let mut total_bytes = ledger
        .entries
        .values()
        .filter_map(|entry| match entry.state {
            UidState::Committed { bytes, .. } => Some(bytes),
            _ => None,
        })
        .sum::<u64>();

    for uid in uids {
        validate_runtime(started, limits, &token)?;
        if invalid_committed.contains(&uid) {
            continue;
        }
        let current = &ledger.entries[&uid];
        if current.state.reconciled() || matches!(current.state, UidState::Oversized { .. }) {
            continue;
        }
        ledger.entries.get_mut(&uid).unwrap().state = UidState::Pending;
        archive.persist_entry(uid, &ledger.entries[&uid])?;

        let mut retry = 0;
        let outcome = loop {
            match bounded_transport(transport.fetch_uid(uid), started, limits, &token).await {
                Ok(outcome) => break Ok(outcome),
                Err(error)
                    if error.code() == ErrorCode::NetworkError && retry < MAX_NETWORK_RETRIES =>
                {
                    retry += 1;
                    bounded_transport(transport.reconnect(), started, limits, &token).await?;
                    let resumed =
                        bounded_transport(transport.snapshot(mailbox), started, limits, &token)
                            .await?;
                    if resumed.uid_validity != ledger.uid_validity {
                        break Err(raise_error!(
                            format!(
                                "UIDVALIDITY changed during reconnect from {} to {}",
                                ledger.uid_validity, resumed.uid_validity
                            ),
                            ErrorCode::Incompatible
                        ));
                    }
                }
                Err(error) => break Err(error),
            }
        };

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                    reason: error.to_string(),
                };
                archive.persist_entry(uid, &ledger.entries[&uid])?;
                continue;
            }
        };

        match outcome {
            FetchOutcome::Vanished => {
                ledger.entries.get_mut(&uid).unwrap().state = UidState::Vanished;
            }
            FetchOutcome::Missing => {
                ledger.entries.get_mut(&uid).unwrap().state = UidState::Missing;
            }
            FetchOutcome::Message { declared_size, raw } => {
                let bytes = raw.len() as u64;
                let declared = declared_size.or(ledger.entries[&uid].declared_size);
                if bytes > limits.max_literal_bytes {
                    ledger.entries.get_mut(&uid).unwrap().state = UidState::Oversized {
                        declared: bytes,
                        limit: limits.max_literal_bytes,
                    };
                } else if total_bytes.saturating_add(bytes) > limits.max_total_bytes {
                    ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                        reason: format!(
                            "UIDONLY total byte ceiling {} exceeded",
                            limits.max_total_bytes
                        ),
                    };
                } else {
                    match archive.commit_raw(&ledger, uid, &raw) {
                        Ok((blob_hash, bytes)) => {
                            let budget = canonical.disk_budget(&raw)?;
                            if let Err(error) = archive.reserve_disk(budget) {
                                ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                                    reason: error.to_string(),
                                };
                            } else {
                                ledger.entries.get_mut(&uid).unwrap().state =
                                    UidState::Projecting {
                                        blob_hash: blob_hash.clone(),
                                        bytes,
                                        canonical_bytes: budget,
                                    };
                                if let Err(error) =
                                    archive.persist_entry(uid, &ledger.entries[&uid])
                                {
                                    archive.release_disk(budget);
                                    return Err(error);
                                }
                                let projection_shutdown = token.child_token();
                                let projected = bounded_canonical(
                                    canonical.project(
                                        uid,
                                        &raw,
                                        declared,
                                        projection_shutdown.clone(),
                                    ),
                                    started,
                                    limits,
                                    &token,
                                    Some(&projection_shutdown),
                                )
                                .await;
                                match projected {
                                    Ok(projection) => {
                                        let verified = if projection.content_hash == blob_hash {
                                            bounded_canonical(
                                                canonical.verify(
                                                    uid,
                                                    &blob_hash,
                                                    &projection.envelope_id,
                                                ),
                                                started,
                                                limits,
                                                &token,
                                                None,
                                            )
                                            .await
                                        } else {
                                            Ok(false)
                                        };
                                        match verified {
                                            Ok(true) => {
                                                ledger.entries.get_mut(&uid).unwrap().state =
                                                    UidState::Committed {
                                                        blob_hash: blob_hash.clone(),
                                                        bytes,
                                                        canonical_bytes: budget,
                                                        envelope_id: Some(
                                                            projection.envelope_id.clone(),
                                                        ),
                                                    };
                                                if let Err(error) = archive
                                                    .persist_entry(uid, &ledger.entries[&uid])
                                                {
                                                    cleanup_canonical(
                                                        canonical,
                                                        uid,
                                                        &blob_hash,
                                                        Some(&projection.envelope_id),
                                                    )
                                                    .await?;
                                                    archive.release_disk(budget);
                                                    return Err(error);
                                                }
                                                total_bytes = total_bytes.saturating_add(bytes);
                                                continue;
                                            }
                                            Ok(false) => {
                                                cleanup_canonical(
                                                    canonical,
                                                    uid,
                                                    &blob_hash,
                                                    Some(&projection.envelope_id),
                                                )
                                                .await?;
                                                archive.release_disk(budget);
                                                ledger.entries.get_mut(&uid).unwrap().state =
                                                    UidState::Failed {
                                                        reason: "canonical projection verification failed"
                                                            .into(),
                                                    };
                                            }
                                            Err(failure) => {
                                                cleanup_canonical(
                                                    canonical,
                                                    uid,
                                                    &blob_hash,
                                                    Some(&projection.envelope_id),
                                                )
                                                .await?;
                                                archive.release_disk(budget);
                                                return Err(failure.error);
                                            }
                                        }
                                    }
                                    Err(failure) => {
                                        if !failure.cleanup_pending {
                                            cleanup_canonical(canonical, uid, &blob_hash, None)
                                                .await?;
                                        }
                                        archive.release_disk(budget);
                                        let error = failure.error;
                                        if error.code() == ErrorCode::RequestTimeout
                                            || error.to_string().contains("cancelled")
                                        {
                                            return Err(error);
                                        }
                                        ledger.entries.get_mut(&uid).unwrap().state =
                                            UidState::Failed {
                                                reason: error.to_string(),
                                            };
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                                reason: error.to_string(),
                            };
                        }
                    }
                }
            }
        }
        archive.persist_entry(uid, &ledger.entries[&uid])?;
    }

    let final_committed: Vec<_> = ledger
        .entries
        .iter()
        .filter_map(|(&uid, entry)| match &entry.state {
            UidState::Committed {
                blob_hash,
                canonical_bytes,
                envelope_id: Some(envelope_id),
                ..
            } => Some((
                uid,
                blob_hash.clone(),
                *canonical_bytes,
                envelope_id.clone(),
            )),
            _ => None,
        })
        .collect();
    for (uid, blob_hash, canonical_bytes, envelope_id) in final_committed {
        if !bounded_canonical(
            canonical.verify(uid, &blob_hash, &envelope_id),
            started,
            limits,
            &token,
            None,
        )
        .await?
        {
            cleanup_canonical(canonical, uid, &blob_hash, Some(&envelope_id)).await?;
            archive.release_disk(canonical_bytes);
            ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                reason: "canonical record failed final checkpoint revalidation".into(),
            };
            archive.persist_entry(uid, &ledger.entries[&uid])?;
            ledger.checkpoint = None;
        }
    }

    let planned = ledger.entries.len() as u64;
    let processed = ledger
        .entries
        .values()
        .filter(|entry| entry.state.reconciled())
        .count() as u64;
    let success = processed == planned;
    if success {
        ledger.checkpoint = Some(snapshot_end);
        archive.persist_metadata(&ledger)?;
    } else if ledger.checkpoint.is_some() {
        ledger.checkpoint = None;
        archive.persist_metadata(&ledger)?;
    }
    archive.reclaim_committed_staging(&ledger)?;
    #[cfg(test)]
    let state_bytes_written = archive.state_bytes_written.load(Ordering::Relaxed);
    Ok(AcquisitionReport {
        uid_validity: ledger.uid_validity,
        planned,
        processed,
        checkpoint: ledger.checkpoint,
        success,
        states: ledger
            .entries
            .into_iter()
            .map(|(uid, entry)| (uid, entry.state))
            .collect(),
        #[cfg(test)]
        state_bytes_written,
    })
}

fn transport_error(error: TransportFailure) -> crate::error::BichonError {
    raise_error!(
        error.message,
        if error.network {
            ErrorCode::NetworkError
        } else {
            ErrorCode::ImapCommandFailed
        }
    )
}

struct SessionUidOnlyTransport {
    account_id: u64,
    session: Session<Box<dyn SessionStream>>,
    message_limit: Option<u32>,
    response_limits: ResponseLimits,
}

impl SessionUidOnlyTransport {
    fn new(
        account_id: u64,
        session: Session<Box<dyn SessionStream>>,
        message_limit: Option<u32>,
        response_limits: ResponseLimits,
    ) -> Self {
        Self {
            account_id,
            session,
            message_limit,
            response_limits,
        }
    }

    fn drain_vanished(&self) -> Vec<RangeInclusive<u32>> {
        let mut vanished = Vec::new();
        while let Ok(response) = self.session.uidonly_responses.try_recv() {
            if let UidOnlyUnsolicitedResponse::Vanished { uids, .. } = response {
                for range in uids {
                    vanished.push(range);
                }
            }
        }
        vanished
    }
}

fn classify_transport(error: async_imap::error::Error) -> TransportFailure {
    let network = match &error {
        async_imap::error::Error::ConnectionLost => true,
        async_imap::error::Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    };
    TransportFailure {
        message: format!("{error:#?}"),
        network,
    }
}

impl UidOnlyTransport for SessionUidOnlyTransport {
    async fn snapshot(&mut self, mailbox: &str) -> Result<Snapshot, TransportFailure> {
        let selected = self
            .session
            .examine(mailbox)
            .await
            .map_err(classify_transport)?;
        let uid_validity = selected
            .uid_validity
            .ok_or_else(|| TransportFailure::command("selected mailbox omitted UIDVALIDITY"))?;
        let uid_next = selected
            .uid_next
            .ok_or_else(|| TransportFailure::command("selected mailbox omitted UIDNEXT"))?;
        Ok(Snapshot {
            uid_validity,
            uid_next,
        })
    }

    async fn inventory_page(
        &mut self,
        first_uid: u32,
        snapshot_end: u32,
        page_size: u32,
    ) -> Result<InventoryPage, TransportFailure> {
        let page_size = self
            .message_limit
            .map(|limit| limit.min(page_size))
            .unwrap_or(page_size)
            .max(1);
        let partial = PartialRange::first(page_size).map_err(classify_transport)?;
        let uid_set = format!("{first_uid}:{snapshot_end}");
        let mut stream = self
            .session
            .uid_fetch_uidonly_partial(&uid_set, INVENTORY_QUERY, partial)
            .await
            .map_err(classify_transport)?;
        let mut items = Vec::new();
        while let Some(fetch) = stream.try_next().await.map_err(classify_transport)? {
            items.push(InventoryItem {
                uid: fetch.uid,
                size: fetch.size.map(u64::from),
            });
        }
        drop(stream);
        Ok(InventoryPage {
            items,
            vanished: self.drain_vanished(),
        })
    }

    async fn fetch_uid(&mut self, uid: u32) -> Result<FetchOutcome, TransportFailure> {
        let mut stream = self
            .session
            .uid_fetch_uidonly(uid.to_string(), BODY_QUERY)
            .await
            .map_err(classify_transport)?;
        let mut result = None;
        while let Some(fetch) = stream.try_next().await.map_err(classify_transport)? {
            if result.is_some() || fetch.uid != uid {
                return Err(TransportFailure::command(format!(
                    "unexpected UIDFETCH result while fetching UID {uid}"
                )));
            }
            result = Some(FetchOutcome::Message {
                declared_size: fetch.size.map(u64::from),
                raw: fetch
                    .body()
                    .ok_or_else(|| TransportFailure::command(format!("UID {uid} omitted BODY[]")))?
                    .to_vec(),
            });
        }
        drop(stream);
        let vanished = self.drain_vanished();
        Ok(result.unwrap_or_else(|| {
            if vanished.iter().any(|range| range.contains(&uid)) {
                FetchOutcome::Vanished
            } else {
                FetchOutcome::Missing
            }
        }))
    }

    async fn reconnect(&mut self) -> Result<(), TransportFailure> {
        match ImapConnectionManager::build_acquisition(self.account_id, self.response_limits)
            .await
            .map_err(|e| TransportFailure {
                message: e.to_string(),
                network: e.code() == ErrorCode::NetworkError,
            })? {
            AcquisitionConnection::UidOnly {
                session,
                message_limit,
            } => {
                self.session = session;
                self.message_limit = message_limit;
                Ok(())
            }
            AcquisitionConnection::Standard(_) => Err(TransportFailure::command(
                "server stopped advertising UIDONLY after reconnect",
            )),
        }
    }
}

pub(crate) async fn acquire_bichon_mailbox(
    account: &AccountModel,
    mailbox: &MailBox,
    session: Session<Box<dyn SessionStream>>,
    message_limit: Option<u32>,
    root: &Path,
    limits: AcquisitionLimits,
    token: CancellationToken,
) -> BichonResult<AcquisitionReport> {
    let identity = AcquisitionIdentity::from_account(account, mailbox)?;
    let response_limits = limits.response_limits()?;
    let mut transport =
        SessionUidOnlyTransport::new(account.id, session, message_limit, response_limits);
    let mut canonical = BichonCanonicalArchive::new(account.id, mailbox.id);
    run_acquisition(
        &mut transport,
        &mut canonical,
        &mailbox.encoded_name(),
        identity,
        root,
        limits,
        token,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{insert_impl, manager::DB_MANAGER};
    use crate::envelope::extractor::fail_uidonly_after_attachments;
    use crate::imap::mock_server::{examine_response, MockImapServer};
    use crate::store::blob::BLOB_MANAGER;
    use crate::store::tantivy::dedup::dedup_task;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::TcpStream;

    #[derive(Debug)]
    struct TestStream(TcpStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl SessionStream for TestStream {}

    struct FakeTransport {
        snapshot: Snapshot,
        inventory: Vec<InventoryItem>,
        outcomes: BTreeMap<u32, VecDeque<Result<FetchOutcome, TransportFailure>>>,
        vanished_on_inventory: BTreeSet<u32>,
        expunge_after_first_page: Option<u32>,
        reconnects: u32,
        page_requests: Vec<(u32, u32, u32)>,
    }

    impl UidOnlyTransport for FakeTransport {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            Ok(self.snapshot)
        }

        async fn inventory_page(
            &mut self,
            first_uid: u32,
            end: u32,
            page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            self.page_requests.push((first_uid, end, page_size));
            let items = self
                .inventory
                .iter()
                .filter(|item| item.uid >= first_uid && item.uid <= end)
                .take(page_size as usize)
                .cloned()
                .collect();
            if self.page_requests.len() == 1 {
                if let Some(uid) = self.expunge_after_first_page.take() {
                    self.inventory.retain(|item| item.uid != uid);
                }
            }
            Ok(InventoryPage {
                items,
                vanished: std::mem::take(&mut self.vanished_on_inventory)
                    .into_iter()
                    .map(|uid| uid..=uid)
                    .collect(),
            })
        }

        async fn fetch_uid(&mut self, uid: u32) -> Result<FetchOutcome, TransportFailure> {
            self.outcomes
                .get_mut(&uid)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Ok(FetchOutcome::Missing))
        }

        async fn reconnect(&mut self) -> Result<(), TransportFailure> {
            self.reconnects += 1;
            Ok(())
        }
    }

    struct HugeVanishedTransport;

    impl UidOnlyTransport for HugeVanishedTransport {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            Ok(Snapshot {
                uid_validity: 9,
                uid_next: u32::MAX,
            })
        }

        async fn inventory_page(
            &mut self,
            _first_uid: u32,
            _snapshot_end: u32,
            _page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            Ok(InventoryPage {
                items: Vec::new(),
                vanished: vec![1..=u32::MAX],
            })
        }

        async fn fetch_uid(&mut self, _uid: u32) -> Result<FetchOutcome, TransportFailure> {
            panic!("vanished UIDs must not be fetched")
        }

        async fn reconnect(&mut self) -> Result<(), TransportFailure> {
            Ok(())
        }
    }

    struct HangingTransport;

    impl UidOnlyTransport for HangingTransport {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            std::future::pending().await
        }

        async fn inventory_page(
            &mut self,
            _first_uid: u32,
            _snapshot_end: u32,
            _page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            unreachable!()
        }

        async fn fetch_uid(&mut self, _uid: u32) -> Result<FetchOutcome, TransportFailure> {
            unreachable!()
        }

        async fn reconnect(&mut self) -> Result<(), TransportFailure> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeCanonicalArchive {
        records: BTreeMap<u32, CanonicalProjection>,
        corrupt_blobs: BTreeSet<u32>,
        fail_projection: BTreeSet<u32>,
        hang_projection: BTreeSet<u32>,
        disk_budget_override: Option<u64>,
        projected_uids: Vec<u32>,
        fail_verify_on_call: Option<usize>,
        verify_calls: Cell<usize>,
        active_projects: usize,
        quiesced_projects: Vec<u32>,
    }

    impl CanonicalArchive for FakeCanonicalArchive {
        fn disk_budget(&self, raw: &[u8]) -> BichonResult<u64> {
            Ok(self.disk_budget_override.unwrap_or(raw.len() as u64 + 128))
        }

        async fn project(
            &mut self,
            uid: u32,
            raw: &[u8],
            _declared_size: Option<u64>,
            shutdown: CancellationToken,
        ) -> BichonResult<CanonicalProjection> {
            if self.hang_projection.contains(&uid) {
                self.active_projects += 1;
                shutdown.cancelled().await;
                self.active_projects -= 1;
                self.quiesced_projects.push(uid);
                return Err(raise_error!(
                    "synthetic canonical projection cancelled".into(),
                    ErrorCode::InternalError
                ));
            }
            if self.fail_projection.contains(&uid) {
                return Err(raise_error!(
                    "synthetic canonical projection failure".into(),
                    ErrorCode::InternalError
                ));
            }
            self.projected_uids.push(uid);
            let projection = CanonicalProjection {
                envelope_id: format!("envelope-{uid}"),
                content_hash: compute_content_hash(raw),
            };
            self.records.insert(uid, projection.clone());
            Ok(projection)
        }

        async fn verify(&self, uid: u32, blob_hash: &str, envelope_id: &str) -> BichonResult<bool> {
            let call = self.verify_calls.get() + 1;
            self.verify_calls.set(call);
            if self.fail_verify_on_call == Some(call) {
                return Ok(false);
            }
            Ok(!self.corrupt_blobs.contains(&uid)
                && self.records.get(&uid).is_some_and(|record| {
                    record.content_hash == blob_hash && record.envelope_id == envelope_id
                }))
        }

        async fn rollback(
            &mut self,
            uid: u32,
            _content_hash: &str,
            _envelope_id: Option<&str>,
        ) -> BichonResult<()> {
            self.records.remove(&uid);
            Ok(())
        }
    }

    fn limits() -> AcquisitionLimits {
        AcquisitionLimits {
            max_messages: 10_000,
            max_total_bytes: 100 * 1024 * 1024,
            max_literal_bytes: 10 * 1024 * 1024,
            max_response_bytes: 11 * 1024 * 1024,
            max_runtime: Duration::from_secs(600),
            max_disk_bytes: 1024 * 1024 * 1024,
            page_size: 2,
        }
    }

    #[test]
    fn legacy_shard_record_is_never_reused_for_uidonly_projection() {
        let error = BichonCanonicalArchive::reuse_projection(
            7,
            "expected-hash",
            crate::store::tantivy::envelope::CanonicalProjectionRecord {
                envelope_id: "legacy-envelope".into(),
                content_hash: "expected-hash".into(),
                shard_id: 0,
                attachments: Vec::new(),
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Incompatible);
        assert!(error.to_string().contains("non-UIDONLY"));
    }

    #[test]
    fn attachment_verification_rejects_same_count_with_different_metadata() {
        let expected = canonical_attachment_records(vec![AttachmentInfo {
            file_type: "application/octet-stream".into(),
            filename: Some("expected.bin".into()),
            size: 4,
            content_hash: "attachment-hash".into(),
            ..Default::default()
        }]);
        let actual = vec![CanonicalAttachmentRecord {
            content_hash: "attachment-hash".into(),
            name: Some("wrong.bin".into()),
            size: 4,
            content_type: "application/octet-stream".into(),
        }];
        assert_eq!(expected.len(), actual.len());
        assert_ne!(expected, actual);
    }

    fn identity() -> AcquisitionIdentity {
        AcquisitionIdentity {
            endpoint: "imap.invalid:993".into(),
            account_id: 7,
            canonical_mailbox: "INBOX".into(),
        }
    }

    fn identity_for(account_id: u64, mailbox: &str) -> AcquisitionIdentity {
        AcquisitionIdentity {
            endpoint: "imap.invalid:993".into(),
            account_id,
            canonical_mailbox: mailbox.into(),
        }
    }

    fn temp_root(test: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("bichon-uidonly-{test}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn item(uid: u32, size: u64) -> InventoryItem {
        InventoryItem {
            uid,
            size: Some(size),
        }
    }
    fn message(raw: &[u8]) -> Result<FetchOutcome, TransportFailure> {
        Ok(FetchOutcome::Message {
            declared_size: Some(raw.len() as u64),
            raw: raw.to_vec(),
        })
    }

    fn message_with_size(
        raw: &[u8],
        declared_size: Option<u64>,
    ) -> Result<FetchOutcome, TransportFailure> {
        Ok(FetchOutcome::Message {
            declared_size,
            raw: raw.to_vec(),
        })
    }

    #[tokio::test]
    async fn per_uid_ledger_persistence_is_linear_in_total_bytes_written() {
        async fn written_for(count: u32) -> u64 {
            let root = temp_root(&format!("linear-ledger-{count}"));
            let raw = b"mail";
            let inventory: Vec<_> = (1..=count).map(|uid| item(uid, raw.len() as u64)).collect();
            let outcomes = (1..=count)
                .map(|uid| (uid, VecDeque::from([message(raw)])))
                .collect();
            let mut transport = FakeTransport {
                snapshot: Snapshot {
                    uid_validity: 9,
                    uid_next: count + 1,
                },
                inventory,
                outcomes,
                vanished_on_inventory: BTreeSet::new(),
                expunge_after_first_page: None,
                reconnects: 0,
                page_requests: Vec::new(),
            };
            let mut bounded = limits();
            bounded.page_size = count;
            let report = run_acquisition(
                &mut transport,
                &mut FakeCanonicalArchive::default(),
                "INBOX",
                identity(),
                &root,
                bounded,
                CancellationToken::new(),
            )
            .await
            .unwrap();
            assert!(report.success);
            fs::remove_dir_all(root).unwrap();
            report.state_bytes_written
        }

        let forty = written_for(40).await;
        let eighty = written_for(80).await;
        assert!(eighty > forty);
        assert!(
            eighty <= forty.saturating_mul(23) / 10,
            "doubling UIDs must keep durable state bytes linear: 40={forty}, 80={eighty}"
        );
    }

    #[test]
    fn lifecycle_cleanup_removes_only_exact_account_and_mailbox_state() {
        let root = temp_root("lifecycle-cleanup");
        let inbox7 = identity_for(7, "INBOX");
        let sent7 = identity_for(7, "Sent");
        let inbox8 = identity_for(8, "INBOX");
        for identity in [&inbox7, &sent7, &inbox8] {
            DurableArchive::open(&root, identity, 9, limits())
                .unwrap()
                .load_or_create(identity.clone(), 9, 1)
                .unwrap();
        }

        assert_eq!(
            cleanup_uidonly_mailbox_state(&root, 7, &BTreeSet::from(["INBOX".to_string()]))
                .unwrap(),
            1
        );
        assert!(!root.join(inbox7.storage_key()).exists());
        assert!(root.join(sent7.storage_key()).exists());
        assert!(root.join(inbox8.storage_key()).exists());

        assert_eq!(cleanup_uidonly_account_state(&root, 7).unwrap(), 1);
        assert!(!root.join(sent7.storage_key()).exists());
        assert!(root.join(inbox8.storage_key()).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn canonical_disk_budget_is_enforced_before_projection() {
        let root = temp_root("canonical-disk-budget");
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 4)],
            outcomes: [(1, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive {
            disk_budget_override: Some(10_000),
            ..Default::default()
        };
        let mut bounded = limits();
        bounded.max_disk_bytes = 4_096;
        let report = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            bounded,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.success);
        assert_eq!(report.checkpoint, None);
        assert!(canonical.projected_uids.is_empty());
        assert!(matches!(report.states[&1], UidState::Failed { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn checkpoint_final_revalidation_catches_late_canonical_deletion() {
        let root = temp_root("final-revalidation");
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 4)],
            outcomes: [(1, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive {
            fail_verify_on_call: Some(2),
            ..Default::default()
        };
        let report = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.success);
        assert_eq!(report.checkpoint, None);
        assert!(matches!(report.states[&1], UidState::Failed { .. }));
        assert!(canonical.records.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cancellation_interrupts_hanging_canonical_projection_and_rolls_back() {
        let root = temp_root("cancel-canonical");
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 4)],
            outcomes: [(1, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive {
            hang_projection: BTreeSet::from([1]),
            ..Default::default()
        };
        let token = CancellationToken::new();
        let cancel = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });
        let error = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            token,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(canonical.records.is_empty());
        assert_eq!(canonical.active_projects, 0);
        assert_eq!(canonical.quiesced_projects, vec![1]);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn runtime_ceiling_interrupts_hanging_canonical_projection_and_rolls_back() {
        let root = temp_root("runtime-canonical");
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 4)],
            outcomes: [(1, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive {
            hang_projection: BTreeSet::from([1]),
            ..Default::default()
        };
        let mut bounded = limits();
        bounded.max_runtime = Duration::from_millis(200);
        let error = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            bounded,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::RequestTimeout);
        assert!(canonical.records.is_empty());
        assert_eq!(canonical.active_projects, 0);
        assert!(canonical.quiesced_projects.is_empty() || canonical.quiesced_projects == vec![1]);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn bounded_canonical_runtime_waits_for_projection_quiescence() {
        let state = std::sync::Arc::new(AtomicU64::new(0));
        let operation_state = state.clone();
        let operation_shutdown = CancellationToken::new();
        let observed_shutdown = operation_shutdown.clone();
        let acquisition_token = CancellationToken::new();
        let mut bounded = limits();
        bounded.max_runtime = Duration::from_millis(25);
        let error = bounded_canonical::<_, ()>(
            async move {
                operation_state.store(1, Ordering::Release);
                observed_shutdown.cancelled().await;
                operation_state.store(2, Ordering::Release);
                Ok(())
            },
            Instant::now(),
            bounded,
            &acquisition_token,
            Some(&operation_shutdown),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error.code(), ErrorCode::RequestTimeout);
        assert_eq!(state.load(Ordering::Acquire), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn noncooperative_blocking_projection_returns_bounded_and_serializes_late_work() {
        let write_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let state = std::sync::Arc::new(AtomicU64::new(0));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let operation_shutdown = CancellationToken::new();
        let owned_shutdown = operation_shutdown.clone();
        let owned_lock = write_lock.clone();
        let owned_state = state.clone();
        let owned_task = tokio::spawn(async move {
            let _guard = owned_lock.lock().await;
            owned_state.store(1, Ordering::Release);
            // Models a production spawn_blocking Fjall call: shutdown cannot
            // cancel the blocking closure, so the owned task must outlive the
            // bounded caller and retain serialization until it returns.
            tokio::task::spawn_blocking(move || release_rx.recv().unwrap())
                .await
                .unwrap();
            assert!(owned_shutdown.is_cancelled());
            // Self-rollback completes before releasing the serialization
            // guard. A later projection must observe this state first.
            owned_state.store(2, Ordering::Release);
            Err::<(), BichonError>(raise_error!(
                "synthetic owned projection cancelled".into(),
                ErrorCode::InternalError
            ))
        });
        let operation = async move {
            owned_task
                .await
                .map_err(|error| raise_error!(format!("{error:#?}"), ErrorCode::InternalError))?
        };
        let acquisition_token = CancellationToken::new();
        let mut bounded = limits();
        bounded.max_runtime = Duration::from_millis(25);
        let started = Instant::now();
        let failure = bounded_canonical(
            operation,
            started,
            bounded,
            &acquisition_token,
            Some(&operation_shutdown),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.error.code(), ErrorCode::RequestTimeout);
        assert!(failure.cleanup_pending);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(state.load(Ordering::Acquire), 1);

        let later_lock = write_lock.clone();
        let later_state = state.clone();
        let later = tokio::spawn(async move {
            let _guard = later_lock.lock().await;
            assert_eq!(later_state.load(Ordering::Acquire), 2);
            later_state.store(3, Ordering::Release);
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(state.load(Ordering::Acquire), 1);
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), later)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.load(Ordering::Acquire), 3);
    }

    #[tokio::test]
    async fn restart_reaccounts_persisted_canonical_disk_reservation() {
        let root = temp_root("restart-canonical-disk");
        let mut first = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 4)],
            outcomes: [(1, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        let first_report = run_acquisition(
            &mut first,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(first_report.success);
        let canonical_budget = match first_report.states[&1] {
            UidState::Committed {
                canonical_bytes, ..
            } => canonical_bytes,
            _ => unreachable!(),
        };
        let identity_dir = root.join(identity().storage_key());
        let physical = directory_size(&identity_dir).unwrap();
        let mut restart_limits = limits();
        restart_limits.max_disk_bytes = physical + canonical_budget - 1;
        let mut restart = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 4)],
            outcomes: BTreeMap::new(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let error = run_acquisition(
            &mut restart,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            restart_limits,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PayloadTooLarge);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn sparse_uid_cursor_partial_order_and_identical_bodies_are_safe() {
        let root = temp_root("sparse");
        let raw = b"same exact RFC822 bytes";
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 51,
            },
            inventory: vec![
                item(2, raw.len() as u64),
                item(30, raw.len() as u64),
                item(50, raw.len() as u64),
            ],
            outcomes: [
                (2, VecDeque::from([message(raw)])),
                (30, VecDeque::from([message(raw)])),
                (50, VecDeque::from([message(raw)])),
            ]
            .into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        let report = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!(
            (report.planned, report.processed, report.checkpoint),
            (3, 3, Some(50))
        );
        assert_eq!(transport.page_requests, vec![(1, 50, 2), (31, 50, 2)]);
        let epoch = root.join(identity().storage_key()).join("9");
        assert_eq!(canonical.records.len(), 3);
        assert_eq!(
            canonical.records[&2].content_hash,
            canonical.records[&30].content_hash
        );
        assert_eq!(
            canonical.records[&30].content_hash,
            canonical.records[&50].content_hash
        );
        assert_ne!(
            canonical.records[&2].envelope_id,
            canonical.records[&30].envelope_id
        );
        assert_eq!(
            fs::read_dir(epoch.join("blobs")).unwrap().count(),
            0,
            "committed raw bytes are reclaimed from staging"
        );
        assert_eq!(
            fs::read_dir(epoch.join("records")).unwrap().count(),
            0,
            "canonical records, not staging records, own committed identity"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn literal_framing_accepts_equal_different_and_missing_rfc822_size() {
        let root = temp_root("literal-size-metadata");
        let raw = b"From: sender@example.invalid\r\n\r\nbody";
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 4,
            },
            inventory: vec![
                InventoryItem {
                    uid: 1,
                    size: Some(raw.len() as u64),
                },
                InventoryItem {
                    uid: 2,
                    size: Some(999),
                },
                InventoryItem { uid: 3, size: None },
            ],
            outcomes: [
                (
                    1,
                    VecDeque::from([message_with_size(raw, Some(raw.len() as u64))]),
                ),
                (2, VecDeque::from([message_with_size(raw, Some(999))])),
                (3, VecDeque::from([message_with_size(raw, None)])),
            ]
            .into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        let report = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!((report.planned, report.processed), (3, 3));
        assert_eq!(canonical.records.len(), 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn canonical_projection_failure_prevents_success_and_checkpoint() {
        let root = temp_root("projection-failure");
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, 4)],
            outcomes: [(7, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive {
            fail_projection: BTreeSet::from([7]),
            ..Default::default()
        };
        let report = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.success);
        assert_eq!(report.checkpoint, None);
        assert!(matches!(report.states[&7], UidState::Failed { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn committed_ledger_persist_failure_rolls_back_canonical_projection() {
        let root = temp_root("committed-ledger-persist-failure");
        let identity = identity();
        let archive = DurableArchive::open(&root, &identity, 9, limits()).unwrap();
        archive.load_or_create(identity.clone(), 9, 1).unwrap();
        atomic_write(
            &archive.epoch_dir.join("fail-next-committed-entry-persist"),
            b"fail",
        )
        .unwrap();
        let entry_path = archive.ledger_entries_dir.join("1.json");
        drop(archive);

        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 4)],
            outcomes: [(1, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        let error = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity.clone(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("synthetic committed ledger persist failure"));
        assert!(canonical.records.is_empty());
        let persisted: UidEntry = serde_json::from_slice(&fs::read(entry_path).unwrap()).unwrap();
        assert!(matches!(persisted.state, UidState::Projecting { .. }));

        let mut retry = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 4)],
            outcomes: [(1, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut retry,
            &mut canonical,
            "INBOX",
            identity,
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert!(canonical.records.contains_key(&1));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[ignore = "run offline with an isolated BICHON_ROOT_DIR"]
    async fn production_canonical_projection_is_queryable_and_restores_exact_raw() {
        let account_id = 7_000_000_001;
        let mailbox_id = 7_000_000_002;
        let first_uid = 77;
        let second_uid = 78;
        let raw = b"From: sender@example.invalid\r\n\
To: archive@example.invalid\r\n\
Subject: canonical roundtrip\r\n\
Message-ID: <canonical-roundtrip@example.invalid>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=uidonly-boundary\r\n\
\r\n\
--uidonly-boundary\r\n\
Content-Type: text/plain\r\n\
\r\n\
exact body bytes\r\n\
--uidonly-boundary\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=fixture.bin\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AQIDBA==\r\n\
--uidonly-boundary--\r\n";
        insert_impl(
            DB_MANAGER.db(),
            AccountModel {
                id: account_id,
                email: "archive@example.invalid".into(),
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
        MailBox::batch_insert(&[MailBox {
            id: mailbox_id,
            account_id,
            name: "INBOX".into(),
            ..Default::default()
        }])
        .unwrap();
        let mut canonical = BichonCanonicalArchive::new(account_id, mailbox_id);
        let first = canonical
            .project(first_uid, raw, None, CancellationToken::new())
            .await
            .unwrap();
        let second = canonical
            .project(second_uid, raw, None, CancellationToken::new())
            .await
            .unwrap();
        assert_ne!(first.envelope_id, second.envelope_id);

        let mut email_writer = ENVELOPE_MANAGER.index_writer().lock().await;
        let mut attachment_writer = ATTACHMENT_MANAGER.index_writer().lock().await;
        let email_reader = ENVELOPE_MANAGER.create_reader().unwrap();
        dedup_task(&email_reader, &mut email_writer, &mut attachment_writer)
            .await
            .unwrap();
        drop(attachment_writer);
        drop(email_writer);

        for (uid, projection) in [(first_uid, &first), (second_uid, &second)] {
            let queried = ENVELOPE_MANAGER
                .get_projection_by_uid(account_id, mailbox_id, uid)
                .unwrap()
                .expect("distinct UIDONLY projection must survive periodic dedup");
            assert_eq!(queried.envelope_id, projection.envelope_id);
            assert_eq!(queried.content_hash, compute_content_hash(raw));
            assert_eq!(queried.shard_id, UIDONLY_SHARD_ID);
            assert_eq!(
                ATTACHMENT_MANAGER
                    .canonical_records_by_envelope(account_id, &projection.envelope_id)
                    .unwrap(),
                vec![CanonicalAttachmentRecord {
                    content_hash: compute_content_hash(&[1, 2, 3, 4]),
                    name: Some("fixture.bin".into()),
                    size: 4,
                    content_type: "application/octet-stream".into(),
                }]
            );

            let (envelope, restored) =
                reattach_eml_content(account_id, projection.envelope_id.clone()).unwrap();
            assert_eq!(envelope.uid, uid);
            assert_eq!(restored.as_ref(), raw);
            assert!(canonical
                .verify(uid, &projection.content_hash, &projection.envelope_id)
                .await
                .unwrap());
        }

        let failed_uid = 79;
        // The failed writer reuses the exact email and attachment blobs owned
        // by two committed projections. Rollback must remove only its index
        // documents and preserve both shared blob values.
        let failed_raw = raw;
        let failed_hash = compute_content_hash(failed_raw);
        let failed_envelope_id = canonical.envelope_id(failed_uid, &failed_hash);
        fail_uidonly_after_attachments(true);
        let failure = canonical
            .project(failed_uid, failed_raw, None, CancellationToken::new())
            .await;
        fail_uidonly_after_attachments(false);
        assert!(failure.is_err());
        assert!(ENVELOPE_MANAGER
            .get_projection_by_uid(account_id, mailbox_id, failed_uid)
            .unwrap()
            .is_none());
        assert_eq!(
            ATTACHMENT_MANAGER
                .count_by_envelope(account_id, &failed_envelope_id)
                .unwrap(),
            0
        );
        assert!(BLOB_MANAGER.get_email(&failed_hash).unwrap().is_some());
        for projection in [&first, &second] {
            let (_, restored) =
                reattach_eml_content(account_id, projection.envelope_id.clone()).unwrap();
            assert_eq!(restored.as_ref(), raw);
        }
    }

    #[tokio::test]
    async fn committed_record_deletion_blocks_restart_success_without_staging_rebuild() {
        let root = temp_root("rebuild-canonical-missing");
        let mut first = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, 4)],
            outcomes: [(7, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        assert!(
            run_acquisition(
                &mut first,
                &mut canonical,
                "INBOX",
                identity(),
                &root,
                limits(),
                CancellationToken::new(),
            )
            .await
            .unwrap()
            .success
        );
        canonical.records.clear();
        let mut restart = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, 4)],
            outcomes: BTreeMap::new(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut restart,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.success);
        assert_eq!(report.checkpoint, None);
        assert!(matches!(report.states[&7], UidState::Failed { .. }));
        let epoch = root.join(identity().storage_key()).join("9");
        assert_eq!(fs::read_dir(epoch.join("blobs")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(epoch.join("records")).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn committed_blob_corruption_blocks_restart_success_without_staging_rebuild() {
        let root = temp_root("restart-canonical-blob-corrupt");
        let mut first = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, 4)],
            outcomes: [(7, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        assert!(
            run_acquisition(
                &mut first,
                &mut canonical,
                "INBOX",
                identity(),
                &root,
                limits(),
                CancellationToken::new(),
            )
            .await
            .unwrap()
            .success
        );
        canonical.corrupt_blobs.insert(7);
        let mut restart = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, 4)],
            outcomes: BTreeMap::new(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut restart,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.success);
        assert_eq!(report.checkpoint, None);
        assert!(matches!(report.states[&7], UidState::Failed { .. }));
        let epoch = root.join(identity().storage_key()).join("9");
        assert_eq!(fs::read_dir(epoch.join("blobs")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(epoch.join("records")).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn compact_huge_vanished_range_intersects_only_bounded_planned_uids() {
        let root = temp_root("huge-vanished");
        let archive = DurableArchive::open(&root, &identity(), 9, limits()).unwrap();
        let mut ledger = archive.load_or_create(identity(), 9, u32::MAX - 1).unwrap();
        for uid in [2, 30, 50] {
            ledger.entries.insert(
                uid,
                UidEntry {
                    declared_size: None,
                    state: UidState::Missing,
                },
            );
        }
        for uid in [2, 30, 50] {
            archive.persist_entry(uid, &ledger.entries[&uid]).unwrap();
        }
        let report = run_acquisition(
            &mut HugeVanishedTransport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!((report.planned, report.processed), (3, 3));
        assert!(report
            .states
            .values()
            .all(|state| matches!(state, UidState::Vanished)));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_pending_transport_operation() {
        let root = temp_root("cancel-pending");
        let token = CancellationToken::new();
        let cancel = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });
        let error = run_acquisition(
            &mut HangingTransport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            token,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn runtime_ceiling_interrupts_a_pending_transport_operation() {
        let root = temp_root("runtime-pending");
        let mut bounded = limits();
        bounded.max_runtime = Duration::from_millis(10);
        let error = run_acquisition(
            &mut HangingTransport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            bounded,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::RequestTimeout);
        fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn message_total_byte_and_disk_ceilings_prevent_checkpoint() {
        let cases = ["messages", "total-bytes", "disk"];
        for case in cases {
            let root = temp_root(case);
            let raw = b"mail";
            let mut bounded = limits();
            match case {
                "messages" => bounded.max_messages = 1,
                "total-bytes" => bounded.max_total_bytes = raw.len() as u64,
                "disk" => bounded.max_disk_bytes = 512,
                _ => unreachable!(),
            }
            let mut transport = FakeTransport {
                snapshot: Snapshot {
                    uid_validity: 9,
                    uid_next: 3,
                },
                inventory: vec![item(1, 4), item(2, 4)],
                outcomes: [
                    (1, VecDeque::from([message(raw)])),
                    (2, VecDeque::from([message(raw)])),
                ]
                .into(),
                vanished_on_inventory: BTreeSet::new(),
                expunge_after_first_page: None,
                reconnects: 0,
                page_requests: Vec::new(),
            };
            let result = run_acquisition(
                &mut transport,
                &mut FakeCanonicalArchive::default(),
                "INBOX",
                identity(),
                &root,
                bounded,
                CancellationToken::new(),
            )
            .await;
            match case {
                "messages" | "disk" => assert!(result.is_err()),
                "total-bytes" => {
                    let report = result.unwrap();
                    assert!(!report.success);
                    assert_eq!(report.checkpoint, None);
                }
                _ => unreachable!(),
            }
            fs::remove_dir_all(root).ok();
        }
    }

    #[tokio::test]
    async fn oversized_lower_uid_does_not_hide_successful_higher_uid_or_checkpoint() {
        let root = temp_root("oversized");
        let mut small_limits = limits();
        small_limits.max_literal_bytes = 4;
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 21,
            },
            inventory: vec![item(10, 5), item(20, 2)],
            outcomes: [
                (10, VecDeque::from([message(b"large")])),
                (20, VecDeque::from([message(b"ok")])),
            ]
            .into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        let report = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            small_limits,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.success);
        assert_eq!(
            (report.planned, report.processed, report.checkpoint),
            (2, 1, None)
        );
        assert!(matches!(report.states[&10], UidState::Oversized { .. }));
        assert!(matches!(report.states[&20], UidState::Committed { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn disconnect_reconnects_and_retries_same_uid_before_checkpoint() {
        let root = temp_root("reconnect");
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, 4)],
            outcomes: [(
                7,
                VecDeque::from([
                    Err(TransportFailure {
                        message: "disconnect during literal".into(),
                        network: true,
                    }),
                    message(b"mail"),
                ]),
            )]
            .into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut transport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!(transport.reconnects, 1);
        assert_eq!(report.checkpoint, Some(7));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn pending_restart_never_advances_and_vanished_reconciles_explicitly() {
        let root = temp_root("restart");
        let mut first = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 31,
            },
            inventory: vec![item(10, 2), item(30, 2)],
            outcomes: [
                (10, VecDeque::from([message(b"ok")])),
                (30, VecDeque::from([Ok(FetchOutcome::Missing)])),
            ]
            .into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        let report = run_acquisition(
            &mut first,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(!report.success);
        assert_eq!(report.checkpoint, None);

        let mut restarted = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 99,
            },
            inventory: vec![item(10, 2)],
            outcomes: BTreeMap::new(),
            vanished_on_inventory: BTreeSet::from([30]),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut restarted,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!(
            report.checkpoint,
            Some(30),
            "restart retains the original fixed snapshot"
        );
        assert!(matches!(report.states[&30], UidState::Vanished));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn changed_uidvalidity_starts_a_fresh_staging_epoch() {
        let root = temp_root("uidvalidity");
        let mut first = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 1)],
            outcomes: [(1, VecDeque::from([message(b"x")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        run_acquisition(
            &mut first,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut changed = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 10,
                uid_next: 2,
            },
            inventory: vec![],
            outcomes: BTreeMap::new(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut changed,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert!(report.states.is_empty());
        let identity_dir = root.join(identity().storage_key());
        assert_eq!(
            fs::read_to_string(identity_dir.join("current-uidvalidity")).unwrap(),
            "10"
        );
        assert!(identity_dir.join("9").exists());
        assert!(identity_dir.join("10").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn expunge_between_inventory_pages_cannot_shift_a_uid_behind_cursor() {
        let root = temp_root("expunge-pages");
        let inventory = vec![
            item(10, 1),
            item(20, 1),
            item(30, 1),
            item(40, 1),
            item(50, 1),
        ];
        let outcomes = inventory
            .iter()
            .map(|item| (item.uid, VecDeque::from([message(b"x")])))
            .collect();
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 51,
            },
            inventory,
            outcomes,
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: Some(10),
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut transport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!(report.states.len(), 5);
        assert!(report.states.contains_key(&30));
        assert_eq!(
            transport.page_requests,
            vec![(1, 50, 2), (21, 50, 2), (41, 50, 2)]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn vanished_during_body_fetch_is_an_explicit_reconciliation() {
        let root = temp_root("vanished-fetch");
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, 10)],
            outcomes: [(7, VecDeque::from([Ok(FetchOutcome::Vanished)]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut transport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert!(matches!(report.states[&7], UidState::Vanished));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn restart_retries_pending_queue_ack_without_checkpointing_it() {
        let root = temp_root("pending-queue-ack");
        let archive = DurableArchive::open(&root, &identity(), 9, limits()).unwrap();
        let mut ledger = archive.load_or_create(identity(), 9, 7).unwrap();
        ledger.entries.insert(
            7,
            UidEntry {
                declared_size: Some(4),
                state: UidState::Pending,
            },
        );
        archive.persist_entry(7, &ledger.entries[&7]).unwrap();

        let mut restarted = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, 4)],
            outcomes: [(7, VecDeque::from([message(b"mail")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut restarted,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!(report.checkpoint, Some(7));
        assert!(matches!(report.states[&7], UidState::Committed { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    fn uidfetch_metadata(entries: &[(u32, usize)]) -> Vec<u8> {
        let mut response = Vec::new();
        for (uid, bytes) in entries {
            response.extend_from_slice(
                format!("* {uid} UIDFETCH (UID {uid} RFC822.SIZE {bytes})\r\n").as_bytes(),
            );
        }
        response.extend_from_slice(b"{TAG} OK UID FETCH completed\r\n");
        response
    }

    fn uidfetch_body(uid: u32, raw: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "* {uid} UIDFETCH (UID {uid} RFC822.SIZE {} BODY[] {{{}}}\r\n",
            raw.len(),
            raw.len()
        )
        .into_bytes();
        response.extend_from_slice(raw);
        response.extend_from_slice(b")\r\n{TAG} OK UID FETCH completed\r\n");
        response
    }

    async fn transcript_session(
        server: &crate::imap::mock_server::MockImapServerHandle,
        limits: ResponseLimits,
    ) -> Session<Box<dyn SessionStream>> {
        let stream = TcpStream::connect((server.host(), server.port()))
            .await
            .unwrap();
        let mut client =
            async_imap::Client::new(Box::new(TestStream(stream)) as Box<dyn SessionStream>);
        client.read_response().await.unwrap().unwrap();
        let mut session = client
            .login("test", "test")
            .await
            .map_err(|(e, _)| e)
            .unwrap();
        session.set_response_limits(limits).unwrap();
        session.enable_uidonly().await.unwrap();
        session
    }

    #[tokio::test]
    async fn tcp_fake_server_uses_only_uid_commands_after_enable() {
        let raw2 = b"From: a@example.invalid\r\n\r\ntwo";
        let raw30 = b"From: b@example.invalid\r\n\r\nthirty";
        let raw50 = b"From: c@example.invalid\r\n\r\nfifty";
        let server = MockImapServer::new()
            .respond("LOGIN", b"{TAG} OK LOGIN completed\r\n".to_vec())
            .respond(
                "ENABLE UIDONLY",
                b"* ENABLED UIDONLY\r\n{TAG} OK ENABLE completed\r\n".to_vec(),
            )
            .respond("EXAMINE", examine_response("INBOX", 3, 9, 51))
            .respond(
                "UID FETCH 1:50 (UID RFC822.SIZE) (PARTIAL 1:2)",
                uidfetch_metadata(&[(2, raw2.len()), (30, raw30.len())]),
            )
            .respond(
                "UID FETCH 31:50 (UID RFC822.SIZE) (PARTIAL 1:2)",
                uidfetch_metadata(&[(50, raw50.len())]),
            )
            .respond("UID FETCH 2 ", uidfetch_body(2, raw2))
            .respond("UID FETCH 30 ", uidfetch_body(30, raw30))
            .respond("UID FETCH 50 ", uidfetch_body(50, raw50))
            .start()
            .await;
        let response_limits = limits().response_limits().unwrap();
        let session = transcript_session(&server, response_limits).await;
        let root = temp_root("tcp-fake");
        let mut transport = SessionUidOnlyTransport::new(7, session, Some(2), response_limits);
        let report = run_acquisition(
            &mut transport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        let commands = server.commands();
        let enabled = commands
            .iter()
            .position(|command| command.contains("ENABLE UIDONLY"))
            .unwrap();
        for command in &commands[enabled + 1..] {
            assert!(
                !command.contains(" SEARCH ")
                    && !command.contains(" STORE ")
                    && !command.contains(" COPY ")
                    && !command.contains(" MOVE ")
                    && (!command.contains(" FETCH ") || command.contains(" UID FETCH ")),
                "UIDONLY session emitted forbidden command: {command}"
            );
        }
        assert!(commands
            .iter()
            .any(|command| command.contains("PARTIAL 1:2")));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn tcp_fake_rejects_declared_literal_before_body_acceptance() {
        let server = MockImapServer::new()
            .respond("LOGIN", b"{TAG} OK LOGIN completed\r\n".to_vec())
            .respond(
                "ENABLE UIDONLY",
                b"* ENABLED UIDONLY\r\n{TAG} OK ENABLE completed\r\n".to_vec(),
            )
            .respond(
                "UID FETCH 7 ",
                b"* 7 UIDFETCH (UID 7 RFC822.SIZE 100 BODY[] {100}\r\n".to_vec(),
            )
            .start()
            .await;
        let mut session = transcript_session(&server, ResponseLimits::new(1024, 4)).await;
        let mut stream = session.uid_fetch_uidonly("7", BODY_QUERY).await.unwrap();
        let error = stream.try_next().await.unwrap_err();
        assert!(error.to_string().contains("literal") || error.to_string().contains("large"));
    }

    #[tokio::test]
    #[ignore = "requires an explicitly provisioned disposable localhost Cyrus instance"]
    async fn cyrus_uidonly_exact_raw_roundtrip() {
        let port: u16 = std::env::var("BICHON_CYRUS_PORT")
            .expect("BICHON_CYRUS_PORT")
            .parse()
            .expect("numeric Cyrus port");
        let root = PathBuf::from(
            std::env::var("BICHON_CYRUS_ARCHIVE_ROOT").expect("BICHON_CYRUS_ARCHIVE_ROOT"),
        );
        assert!(root.is_absolute());
        fs::create_dir_all(&root).unwrap();

        let connect = || async move {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut client =
                async_imap::Client::new(Box::new(TestStream(stream)) as Box<dyn SessionStream>);
            client.read_response().await.unwrap().unwrap();
            client
                .login("archive-test", "synthetic-only-password")
                .await
                .map_err(|(error, _)| error)
                .unwrap()
        };

        let raw_messages: [&[u8]; 3] = [
            b"From: one@example.invalid\r\nTo: archive@example.invalid\r\nSubject: one\r\n\r\nfirst\r\n",
            b"From: two@example.invalid\r\nTo: archive@example.invalid\r\nSubject: two\r\n\r\nsecond\r\n",
            b"From: three@example.invalid\r\nTo: archive@example.invalid\r\nSubject: three\r\n\r\nthird\r\n",
        ];
        let mut seed = connect().await;
        for raw in raw_messages {
            seed.append("INBOX", None, None, raw).await.unwrap();
        }
        seed.logout().await.unwrap();

        let mut session = connect().await;
        let capabilities = session.capabilities().await.unwrap();
        assert!(capabilities.has_str("UIDONLY"));
        assert!(capabilities.has_str("PARTIAL"));
        let cyrus_limits = AcquisitionLimits {
            max_messages: 100,
            max_total_bytes: 100 * 1024 * 1024,
            max_literal_bytes: 25 * 1024 * 1024,
            max_response_bytes: 26 * 1024 * 1024,
            max_runtime: Duration::from_secs(600),
            max_disk_bytes: 1024 * 1024 * 1024,
            page_size: 2,
        };
        let response_limits = cyrus_limits.response_limits().unwrap();
        session.set_response_limits(response_limits).unwrap();
        session.enable_uidonly().await.unwrap();
        let mut transport = SessionUidOnlyTransport::new(7, session, None, response_limits);
        let cyrus_identity = AcquisitionIdentity {
            endpoint: format!("127.0.0.1:{port}"),
            account_id: 7,
            canonical_mailbox: "INBOX".into(),
        };
        let mut canonical = FakeCanonicalArchive::default();
        let report = run_acquisition(
            &mut transport,
            &mut canonical,
            "INBOX",
            cyrus_identity.clone(),
            &root,
            cyrus_limits,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!((report.planned, report.processed), (3, 3));
        drop(transport);

        let mut restart_session = connect().await;
        restart_session
            .set_response_limits(response_limits)
            .unwrap();
        restart_session.enable_uidonly().await.unwrap();
        let mut restart_transport =
            SessionUidOnlyTransport::new(7, restart_session, None, response_limits);
        let restart_report = run_acquisition(
            &mut restart_transport,
            &mut canonical,
            "INBOX",
            cyrus_identity.clone(),
            &root,
            cyrus_limits,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(restart_report.success);
        assert_eq!((restart_report.planned, restart_report.processed), (3, 3));
        assert_eq!(
            canonical.projected_uids.len(),
            3,
            "restart must revalidate committed records without reprojecting bodies"
        );

        let epoch = root
            .join(cyrus_identity.storage_key())
            .join(report.uid_validity.to_string());
        assert_eq!(fs::read_dir(epoch.join("records")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(epoch.join("blobs")).unwrap().count(), 0);
        assert_eq!(canonical.records.len(), 3);
        let expected_hashes: BTreeSet<_> = raw_messages
            .iter()
            .map(|raw| compute_content_hash(raw))
            .collect();
        let projected_hashes: BTreeSet<_> = canonical
            .records
            .values()
            .map(|projection| projection.content_hash.clone())
            .collect();
        let envelope_ids: BTreeSet<_> = canonical
            .records
            .values()
            .map(|projection| projection.envelope_id.clone())
            .collect();
        assert_eq!(projected_hashes, expected_hashes);
        assert_eq!(envelope_ids.len(), 3);
    }
}
