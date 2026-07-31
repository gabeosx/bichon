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
#[cfg(test)]
use crate::envelope::extractor::prepare_detached_attachments;
use crate::envelope::extractor::{
    project_uidonly_message, reattach_eml_content, rollback_uidonly_message, CanonicalProjection,
};
use crate::error::code::ErrorCode;
use crate::error::{BichonError, BichonResult};
use crate::imap::manager::{
    acquisition_connection_identity, AcquisitionConnection, AcquisitionConnectionIdentity,
    ImapConnectionManager,
};
use crate::imap::session::SessionStream;
use crate::message::content::AttachmentInfo;
use crate::raise_error;
use crate::store::blob::{uidonly_attachment_blob_key, BLOB_MANAGER};
use crate::store::tantivy::attachment::{CanonicalAttachmentRecord, ATTACHMENT_MANAGER};
use crate::store::tantivy::dedup::UIDONLY_SHARD_ID;
use crate::store::tantivy::envelope::{ENVELOPE_MANAGER, UIDONLY_CANONICAL_WRITE_LOCK};
use crate::utils::compute_content_hash;
use bichon_uidonly::{
    missing_verified_uids, AdapterLimits, CommandLimits, ExactFetchOutcome, InventoryRequest,
    Notification, UidOnlySession,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::num::{NonZeroU32, NonZeroUsize};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const MAX_NETWORK_RETRIES: u32 = 3;
const MAX_LEDGER_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEDGER_ENTRY_BYTES: u64 = 64 * 1024;
const MAX_STAGING_RECORD_BYTES: u64 = 64 * 1024;
const LEDGER_BASE_MEMORY_ESTIMATE: u64 = 1024 * 1024;
const LEDGER_ENTRY_MEMORY_ESTIMATE: u64 = 384;
const VANISHED_RANGE_MEMORY_ESTIMATE: u64 = 32;
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
    pub max_state_bytes: u64,
    pub max_memory_bytes: u64,
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
            max_state_bytes: 512 * 1024 * 1024,
            max_memory_bytes: literal.saturating_mul(5).saturating_add(64 * 1024 * 1024),
            page_size: account.download_batch_size.unwrap_or(30).max(1),
        }
    }

    fn body_chunk_size(self) -> BichonResult<NonZeroU32> {
        let bytes = self.max_literal_bytes.min(1024 * 1024).min(u32::MAX as u64);
        NonZeroU32::new(bytes as u32).ok_or_else(|| {
            raise_error!(
                "UIDONLY body chunk ceiling must be nonzero".into(),
                ErrorCode::InvalidParameter
            )
        })
    }

    pub fn adapter_limits(self) -> BichonResult<AdapterLimits> {
        let chunk = self.body_chunk_size()?.get() as usize;
        let configured_response = usize::try_from(self.max_response_bytes).map_err(|_| {
            raise_error!(
                "response ceiling does not fit usize".into(),
                ErrorCode::InvalidParameter
            )
        })?;
        let response = configured_response.min(chunk.saturating_add(1024 * 1024));
        let control = 64 * 1024;
        if response < chunk || response < control {
            return Err(raise_error!(
                "UIDONLY response ceiling must cover control lines and one body chunk".into(),
                ErrorCode::InvalidParameter
            ));
        }
        Ok(AdapterLimits {
            max_input_bytes: NonZeroUsize::new(control).expect("constant is nonzero"),
            max_control_line_bytes: NonZeroUsize::new(control).expect("constant is nonzero"),
            max_literal_bytes: NonZeroUsize::new(chunk).expect("validated nonzero"),
            max_response_bytes: NonZeroUsize::new(response).expect("validated nonzero"),
            provenance_capacity: NonZeroUsize::new(64).expect("constant is nonzero"),
        })
    }

    pub fn command_limits(self) -> BichonResult<CommandLimits> {
        let response = usize::try_from(self.max_response_bytes).map_err(|_| {
            raise_error!(
                "response ceiling does not fit usize".into(),
                ErrorCode::InvalidParameter
            )
        })?;
        let page = NonZeroU32::new(self.page_size).ok_or_else(|| {
            raise_error!(
                "UIDONLY inventory page size must be nonzero".into(),
                ErrorCode::InvalidParameter
            )
        })?;
        let event_limit = self.max_messages.clamp(1, 4096);
        Ok(CommandLimits {
            timeout: Duration::from_secs(60).min(self.max_runtime),
            max_responses: NonZeroUsize::new(event_limit).expect("clamped nonzero"),
            max_wire_bytes: NonZeroUsize::new(response).ok_or_else(|| {
                raise_error!(
                    "UIDONLY command wire ceiling must be nonzero".into(),
                    ErrorCode::InvalidParameter
                )
            })?,
            max_events: NonZeroUsize::new(event_limit).expect("clamped nonzero"),
            max_vanished_ranges: NonZeroUsize::new(event_limit).expect("clamped nonzero"),
            max_inventory_page: page,
            max_body_chunk_bytes: self.body_chunk_size()?,
            max_mailbox_wire_bytes: NonZeroUsize::new(4096).expect("constant is nonzero"),
        })
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

    fn account_marker(&self) -> String {
        format!(".bichon-account-{}", self.account_id)
    }

    fn mailbox_marker(&self) -> String {
        format!(
            ".bichon-mailbox-{}",
            mailbox_marker_hash(&self.canonical_mailbox)
        )
    }
}

fn mailbox_marker_hash(canonical_mailbox: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bichon-uidonly-mailbox-marker-v1");
    hasher.update(canonical_mailbox.as_bytes());
    hasher.finalize().to_hex().to_string()
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
        #[serde(default)]
        envelope_id: Option<String>,
        #[serde(default)]
        owned: Option<bool>,
    },
    Committed {
        blob_hash: String,
        bytes: u64,
        #[serde(default)]
        canonical_bytes: u64,
        #[serde(default)]
        envelope_id: Option<String>,
        #[serde(default = "default_true")]
        owned: bool,
    },
    Filtered {
        reason: String,
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

const fn default_true() -> bool {
    true
}

impl UidState {
    fn reconciled(&self) -> bool {
        matches!(
            self,
            Self::Committed { .. } | Self::Filtered { .. } | Self::Vanished
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct UidEntry {
    pub declared_size: Option<u64>,
    #[serde(default)]
    pub internal_date: Option<i64>,
    pub state: UidState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AcquisitionLedger {
    pub identity: AcquisitionIdentity,
    pub uid_validity: u32,
    #[serde(default = "first_uid")]
    pub snapshot_start: u32,
    pub snapshot_end: u32,
    #[serde(default)]
    pub inventory_cursor: Option<u32>,
    #[serde(default)]
    pub inventory_complete: bool,
    #[serde(default)]
    pub inventory_count: u64,
    #[serde(default)]
    pub inventory_digest: Option<String>,
    pub checkpoint: Option<u32>,
    #[serde(default)]
    pub vanished_ranges: Vec<UidRange>,
    pub entries: BTreeMap<u32, UidEntry>,
}

const fn first_uid() -> u32 {
    1
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct UidRange {
    pub start: u32,
    pub end: u32,
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
    pub internal_date: Option<i64>,
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

    fn take_vanished(&mut self) -> Vec<RangeInclusive<u32>> {
        Vec::new()
    }
}

#[allow(async_fn_in_trait)]
trait CanonicalArchive {
    fn begin_epoch(&mut self, uid_validity: u32) -> BichonResult<()>;

    fn envelope_id(&self, uid: u32, content_hash: &str) -> BichonResult<String>;

    fn disk_budget(&self, raw: &[u8]) -> BichonResult<u64>;

    fn memory_budget(&self, raw: &[u8]) -> BichonResult<u64>;

    async fn project(
        &mut self,
        uid: u32,
        raw: Vec<u8>,
        declared_size: Option<u64>,
        internal_date: i64,
        shutdown: CancellationToken,
    ) -> BichonResult<Option<CanonicalProjection>>;

    async fn verify(&self, uid: u32, blob_hash: &str, envelope_id: &str) -> BichonResult<bool>;
    async fn rollback(
        &mut self,
        uid: u32,
        content_hash: &str,
        envelope_id: Option<&str>,
        raw: Option<&[u8]>,
    ) -> BichonResult<()>;
}

struct BichonCanonicalArchive {
    account_id: u64,
    mailbox_id: u64,
    uid_validity: Option<u32>,
    #[cfg(test)]
    projected_uids: Vec<u32>,
}

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
            uid_validity: None,
            #[cfg(test)]
            projected_uids: Vec::new(),
        }
    }

    fn envelope_id(&self, uid: u32, content_hash: &str) -> String {
        Self::envelope_id_for(
            self.account_id,
            self.mailbox_id,
            self.uid_validity
                .expect("UIDONLY epoch must be initialized"),
            uid,
            content_hash,
        )
    }

    fn envelope_id_for(
        account_id: u64,
        mailbox_id: u64,
        uid_validity: u32,
        uid: u32,
        content_hash: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bichon-uidonly-envelope-v2");
        hasher.update(&account_id.to_be_bytes());
        hasher.update(&mailbox_id.to_be_bytes());
        hasher.update(&uid_validity.to_be_bytes());
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
            created: false,
        })
    }

    fn verify_projection_record(
        account_id: u64,
        uid: u32,
        blob_hash: &str,
        envelope_id: &str,
        record: crate::store::tantivy::envelope::CanonicalProjectionRecord,
        require_uidonly: bool,
    ) -> BichonResult<bool> {
        if record.envelope_id != envelope_id
            || record.uid != uid
            || record.content_hash != blob_hash
            || (require_uidonly && record.shard_id != UIDONLY_SHARD_ID)
        {
            return Ok(false);
        }
        for attachment in &record.attachments {
            let Some(bytes) = BLOB_MANAGER.get_attachment(&attachment.content_hash)? else {
                return Ok(false);
            };
            if uidonly_attachment_blob_key(&compute_content_hash(&bytes)) != attachment.content_hash
            {
                return Ok(false);
            }
        }
        let expected_attachments = canonical_attachment_records(record.attachments);
        if ATTACHMENT_MANAGER.canonical_records_by_envelope(account_id, envelope_id)?
            != expected_attachments
        {
            return Ok(false);
        }
        let (envelope, raw) = match reattach_eml_content(account_id, envelope_id.to_string()) {
            Ok(value) => value,
            Err(error) if error.code() == ErrorCode::ResourceNotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if expected_attachments.len() != envelope.regular_attachment_count {
            return Ok(false);
        }
        Ok(compute_content_hash(&raw) == blob_hash)
    }
}

impl CanonicalArchive for BichonCanonicalArchive {
    fn begin_epoch(&mut self, uid_validity: u32) -> BichonResult<()> {
        self.uid_validity = Some(uid_validity);
        Ok(())
    }

    fn envelope_id(&self, uid: u32, content_hash: &str) -> BichonResult<String> {
        let uid_validity = self.uid_validity.ok_or_else(|| {
            raise_error!(
                "UIDONLY canonical epoch was not initialized".into(),
                ErrorCode::InternalError
            )
        })?;
        Ok(Self::envelope_id_for(
            self.account_id,
            self.mailbox_id,
            uid_validity,
            uid,
            content_hash,
        ))
    }

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

    fn memory_budget(&self, raw: &[u8]) -> BichonResult<u64> {
        (raw.len() as u64)
            .checked_mul(5)
            .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
            .ok_or_else(|| {
                raise_error!(
                    "canonical projection memory budget overflow".into(),
                    ErrorCode::PayloadTooLarge
                )
            })
    }

    async fn project(
        &mut self,
        uid: u32,
        raw: Vec<u8>,
        _declared_size: Option<u64>,
        internal_date: i64,
        shutdown: CancellationToken,
    ) -> BichonResult<Option<CanonicalProjection>> {
        #[cfg(test)]
        self.projected_uids.push(uid);
        let account_id = self.account_id;
        let mailbox_id = self.mailbox_id;
        let uid_validity = self.uid_validity.ok_or_else(|| {
            raise_error!(
                "UIDONLY canonical epoch was not initialized".into(),
                ErrorCode::InternalError
            )
        })?;
        let body = raw;
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
            let envelope_id =
                Self::envelope_id_for(account_id, mailbox_id, uid_validity, uid, &expected_hash);
            if let Some(existing) =
                ENVELOPE_MANAGER.get_projection_by_envelope_id(account_id, &envelope_id)?
            {
                if Self::verify_projection_record(
                    account_id,
                    uid,
                    &expected_hash,
                    &envelope_id,
                    existing.clone(),
                    true,
                )? {
                    return Self::reuse_projection(uid, &expected_hash, existing).map(Some);
                }
                // The deterministic ID proves this is the current epoch's
                // damaged projection. Remove it under the canonical write
                // lock, then rebuild it from the exact fetched raw bytes.
                rollback_uidonly_message(account_id, &envelope_id, &expected_hash, Some(&body))
                    .await?;
            }
            // Legacy records have no per-record UIDVALIDITY provenance. Even
            // identical UID and raw bytes cannot prove epoch identity, so the
            // current epoch always receives its deterministic UIDONLY record.
            let size = u32::try_from(body.len()).map_err(|_| {
                raise_error!(
                    format!("UID {uid} literal length does not fit Bichon's envelope size field"),
                    ErrorCode::PayloadTooLarge
                )
            })?;
            project_uidonly_message(
                &body,
                uid,
                size,
                internal_date,
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
        let uid_validity = self.uid_validity.ok_or_else(|| {
            raise_error!(
                "UIDONLY canonical epoch was not initialized".into(),
                ErrorCode::InternalError
            )
        })?;
        if envelope_id
            != Self::envelope_id_for(
                self.account_id,
                self.mailbox_id,
                uid_validity,
                uid,
                blob_hash,
            )
        {
            return Ok(false);
        }
        let Some(record) =
            ENVELOPE_MANAGER.get_projection_by_envelope_id(self.account_id, envelope_id)?
        else {
            return Ok(false);
        };
        Self::verify_projection_record(self.account_id, uid, blob_hash, envelope_id, record, true)
    }

    async fn rollback(
        &mut self,
        uid: u32,
        content_hash: &str,
        envelope_id: Option<&str>,
        raw: Option<&[u8]>,
    ) -> BichonResult<()> {
        let _write_guard = UIDONLY_CANONICAL_WRITE_LOCK.lock().await;
        let envelope_id = envelope_id
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| self.envelope_id(uid, content_hash));
        rollback_uidonly_message(self.account_id, &envelope_id, content_hash, raw).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcquisitionReport {
    pub uid_validity: u32,
    pub planned: u64,
    /// Messages durably written to Bichon's canonical archive. This excludes
    /// rule-filtered and VANISHED UIDs so progress never calls either one a
    /// download.
    pub processed: u64,
    pub filtered: u64,
    pub vanished: u64,
    /// All terminally reconciled UIDs. Checkpoint success is based on this
    /// count, while user-visible download progress is based on `processed`.
    pub resolved: u64,
    pub checkpoint: Option<u32>,
    pub success: bool,
    pub vanished_ranges: Vec<UidRange>,
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
    state_bytes: AtomicU64,
    started: Option<Instant>,
    token: Option<CancellationToken>,
    #[cfg(test)]
    state_bytes_written: AtomicU64,
}

#[derive(Clone, Serialize, Deserialize)]
struct LedgerMetadata {
    identity: AcquisitionIdentity,
    uid_validity: u32,
    #[serde(default = "first_uid")]
    snapshot_start: u32,
    snapshot_end: u32,
    #[serde(default)]
    inventory_cursor: Option<u32>,
    #[serde(default)]
    inventory_complete: bool,
    #[serde(default)]
    inventory_count: u64,
    #[serde(default)]
    inventory_digest: Option<String>,
    checkpoint: Option<u32>,
    #[serde(default)]
    vanished_ranges: Vec<UidRange>,
}

#[derive(Serialize, Deserialize)]
struct LedgerMetadataFile {
    metadata: LedgerMetadata,
    checksum: String,
}

#[derive(Serialize, Deserialize)]
struct LedgerEntryFile {
    entry: UidEntry,
    checksum: String,
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
    #[cfg(test)]
    fn open(
        root: &Path,
        identity: &AcquisitionIdentity,
        uid_validity: u32,
        limits: AcquisitionLimits,
    ) -> BichonResult<Self> {
        Self::open_internal(root, identity, uid_validity, limits, None, None)
    }

    fn open_bounded(
        root: &Path,
        identity: &AcquisitionIdentity,
        uid_validity: u32,
        limits: AcquisitionLimits,
        started: Instant,
        token: &CancellationToken,
    ) -> BichonResult<Self> {
        Self::open_internal(
            root,
            identity,
            uid_validity,
            limits,
            Some(started),
            Some(token.clone()),
        )
    }

    fn open_internal(
        root: &Path,
        identity: &AcquisitionIdentity,
        uid_validity: u32,
        limits: AcquisitionLimits,
        started: Option<Instant>,
        token: Option<CancellationToken>,
    ) -> BichonResult<Self> {
        let identity_dir = root.join(identity.storage_key());
        fs::create_dir_all(&identity_dir).map_err(io_error)?;
        discard_owned_atomic_temps(&identity_dir, started, token.as_ref(), limits)?;
        // Marker filenames let lifecycle cleanup select its target without
        // parsing unrelated ledgers. Write the mailbox marker first so a
        // crash can never expose an account marker without its mailbox marker.
        for marker in [identity.mailbox_marker(), identity.account_marker()] {
            let path = identity_dir.join(marker);
            if !path.exists() {
                atomic_write(&path, b"v1")?;
            }
        }
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
        let disk_bytes = directory_size_guarded(&identity_dir, started, token.as_ref(), limits)?;
        if disk_bytes > limits.max_disk_bytes {
            return Err(raise_error!(
                format!(
                    "UIDONLY disk ceiling {} bytes already exceeded",
                    limits.max_disk_bytes
                ),
                ErrorCode::PayloadTooLarge
            ));
        }
        let state_bytes = fs::metadata(&ledger_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0)
            .saturating_add(directory_size_guarded(
                &ledger_entries_dir,
                started,
                token.as_ref(),
                limits,
            )?);
        if state_bytes > limits.max_state_bytes {
            return Err(raise_error!(
                format!(
                    "UIDONLY state ceiling {} bytes already exceeded",
                    limits.max_state_bytes
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
            state_bytes: AtomicU64::new(state_bytes),
            started,
            token,
            #[cfg(test)]
            state_bytes_written: AtomicU64::new(0),
        })
    }

    fn validate_local(&self) -> BichonResult<()> {
        if let (Some(started), Some(token)) = (self.started, self.token.as_ref()) {
            validate_runtime(started, self.limits, token)?;
        }
        Ok(())
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

    fn reserve_state(&self, additional: u64) -> BichonResult<()> {
        self.state_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let next = current.checked_add(additional)?;
                (next <= self.limits.max_state_bytes).then_some(next)
            })
            .map(|_| ())
            .map_err(|_| {
                raise_error!(
                    format!(
                        "UIDONLY state ceiling {} bytes exceeded",
                        self.limits.max_state_bytes
                    ),
                    ErrorCode::PayloadTooLarge
                )
            })
    }

    fn load_or_create(
        &self,
        identity: AcquisitionIdentity,
        uid_validity: u32,
        snapshot_end: u32,
    ) -> BichonResult<AcquisitionLedger> {
        if self.ledger_path.exists() {
            let bytes = read_bounded_file(&self.ledger_path, MAX_LEDGER_METADATA_BYTES)?;
            if (bytes.len() as u64).saturating_mul(4) > self.limits.max_memory_bytes {
                return Err(raise_error!(
                    "UIDONLY ledger metadata parse would exceed the acquisition memory ceiling"
                        .into(),
                    ErrorCode::PayloadTooLarge
                ));
            }
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
                let file: LedgerMetadataFile = serde_json::from_value(value).map_err(|e| {
                    raise_error!(
                        format!("invalid UIDONLY ledger metadata: {e}"),
                        ErrorCode::InternalError
                    )
                })?;
                if file.checksum != ledger_metadata_checksum(&file.metadata) {
                    return Err(raise_error!(
                        "UIDONLY ledger metadata checksum mismatch".into(),
                        ErrorCode::InternalError
                    ));
                }
                let metadata = file.metadata;
                AcquisitionLedger {
                    identity: metadata.identity,
                    uid_validity: metadata.uid_validity,
                    snapshot_start: metadata.snapshot_start,
                    snapshot_end: metadata.snapshot_end,
                    inventory_cursor: metadata.inventory_cursor,
                    inventory_complete: metadata.inventory_complete,
                    inventory_count: metadata.inventory_count,
                    inventory_digest: metadata.inventory_digest,
                    checkpoint: metadata.checkpoint,
                    vanished_ranges: metadata.vanished_ranges,
                    entries: BTreeMap::new(),
                }
            };
            let mut loaded_entries = 0usize;
            let mut loaded_state_bytes = 0u64;
            let mut removed_atomic_temp = false;
            for file in fs::read_dir(&self.ledger_entries_dir).map_err(io_error)? {
                self.validate_local()?;
                let file = file.map_err(io_error)?;
                if !file.file_type().map_err(io_error)?.is_file() {
                    continue;
                }
                if is_owned_atomic_temp(&file.file_name()) {
                    fs::remove_file(file.path()).map_err(io_error)?;
                    removed_atomic_temp = true;
                    continue;
                }
                loaded_entries = loaded_entries.checked_add(1).ok_or_else(|| {
                    raise_error!(
                        "UIDONLY ledger entry count overflow".into(),
                        ErrorCode::PayloadTooLarge
                    )
                })?;
                if loaded_entries > self.limits.max_messages {
                    return Err(raise_error!(
                        format!(
                            "UIDONLY ledger entry ceiling {} exceeded",
                            self.limits.max_messages
                        ),
                        ErrorCode::PayloadTooLarge
                    ));
                }
                enforce_state_memory_ceiling(
                    self.limits,
                    loaded_entries,
                    ledger.vanished_ranges.len(),
                    0,
                )?;
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
                let entry_bytes = read_bounded_file(&file.path(), MAX_LEDGER_ENTRY_BYTES)?;
                loaded_state_bytes = loaded_state_bytes
                    .checked_add(entry_bytes.len() as u64)
                    .ok_or_else(|| {
                        raise_error!(
                            "UIDONLY ledger byte count overflow".into(),
                            ErrorCode::PayloadTooLarge
                        )
                    })?;
                if loaded_state_bytes > self.limits.max_state_bytes {
                    return Err(raise_error!(
                        format!(
                            "UIDONLY state ceiling {} bytes exceeded while loading",
                            self.limits.max_state_bytes
                        ),
                        ErrorCode::PayloadTooLarge
                    ));
                }
                let file: LedgerEntryFile = serde_json::from_slice(&entry_bytes).map_err(|e| {
                    raise_error!(
                        format!("invalid UIDONLY ledger entry for UID {uid}: {e}"),
                        ErrorCode::InternalError
                    )
                })?;
                if file.checksum != ledger_entry_checksum(uid, &file.entry) {
                    return Err(raise_error!(
                        format!("UIDONLY ledger entry checksum mismatch for UID {uid}"),
                        ErrorCode::InternalError
                    ));
                }
                let entry = file.entry;
                ledger.entries.insert(uid, entry);
            }
            if removed_atomic_temp {
                File::open(&self.ledger_entries_dir)
                    .and_then(|directory| directory.sync_all())
                    .map_err(io_error)?;
            }
            if ledger.identity != identity || ledger.uid_validity != uid_validity {
                return Err(raise_error!(
                    "UIDONLY ledger identity mismatch".into(),
                    ErrorCode::Incompatible
                ));
            }
            if ledger
                .entries
                .keys()
                .any(|uid| *uid == 0 || *uid > ledger.snapshot_end)
            {
                return Err(raise_error!(
                    "UIDONLY ledger contains a UID outside its fixed snapshot".into(),
                    ErrorCode::Incompatible
                ));
            }
            // An entry file can reach durable storage immediately before a
            // crash that prevents the page cursor/manifest metadata rename.
            // Such trailing entries are outside the committed prefix and are
            // discarded; the server page will be requested again.
            if let Some(cursor) = ledger.inventory_cursor {
                let trailing: Vec<u32> = ledger
                    .entries
                    .range(cursor..)
                    .map(|(&uid, _)| uid)
                    .collect();
                for uid in trailing {
                    let path = self.ledger_entries_dir.join(format!("{uid}.json"));
                    if let Ok(metadata) = fs::metadata(&path) {
                        fs::remove_file(&path).map_err(io_error)?;
                        self.state_bytes.fetch_sub(metadata.len(), Ordering::AcqRel);
                        self.disk_bytes.fetch_sub(metadata.len(), Ordering::AcqRel);
                    }
                    ledger.entries.remove(&uid);
                }
            }
            let actual_digest = inventory_digest(&ledger);
            let cursor_valid = if ledger.inventory_complete {
                ledger.inventory_cursor.is_none()
            } else {
                ledger.inventory_cursor.is_some_and(|cursor| {
                    cursor >= ledger.snapshot_start && cursor <= ledger.snapshot_end
                })
            };
            let checkpoint_valid = ledger.checkpoint.is_none()
                || (ledger.inventory_complete && ledger.checkpoint == Some(ledger.snapshot_end));
            if !cursor_valid
                || !checkpoint_valid
                || ledger.inventory_digest.as_deref() != Some(actual_digest.as_str())
                || ledger.inventory_count != ledger.entries.len() as u64
            {
                ledger.inventory_complete = false;
                ledger.inventory_cursor = Some(ledger.snapshot_start);
                ledger.checkpoint = None;
                let invalid_uids: Vec<u32> = ledger.entries.keys().copied().collect();
                for uid in invalid_uids {
                    let path = self.ledger_entries_dir.join(format!("{uid}.json"));
                    if let Ok(metadata) = fs::metadata(&path) {
                        fs::remove_file(&path).map_err(io_error)?;
                        self.state_bytes.fetch_sub(metadata.len(), Ordering::AcqRel);
                        self.disk_bytes.fetch_sub(metadata.len(), Ordering::AcqRel);
                    }
                }
                ledger.entries.clear();
                refresh_inventory_manifest(&mut ledger);
                self.persist_metadata(&ledger)?;
            }
            return Ok(ledger);
        }
        let mut ledger = AcquisitionLedger {
            identity,
            uid_validity,
            snapshot_start: 1,
            snapshot_end,
            inventory_cursor: (snapshot_end >= 1).then_some(1),
            inventory_complete: snapshot_end == 0,
            inventory_count: 0,
            inventory_digest: None,
            checkpoint: None,
            vanished_ranges: Vec::new(),
            entries: BTreeMap::new(),
        };
        refresh_inventory_manifest(&mut ledger);
        self.persist_metadata(&ledger)?;
        Ok(ledger)
    }

    fn persist_metadata(&self, ledger: &AcquisitionLedger) -> BichonResult<()> {
        let metadata = LedgerMetadata {
            identity: ledger.identity.clone(),
            uid_validity: ledger.uid_validity,
            snapshot_start: ledger.snapshot_start,
            snapshot_end: ledger.snapshot_end,
            inventory_cursor: ledger.inventory_cursor,
            inventory_complete: ledger.inventory_complete,
            inventory_count: ledger.inventory_count,
            inventory_digest: ledger.inventory_digest.clone(),
            checkpoint: ledger.checkpoint,
            vanished_ranges: ledger.vanished_ranges.clone(),
        };
        let bytes = serde_json::to_vec(&LedgerMetadataFile {
            checksum: ledger_metadata_checksum(&metadata),
            metadata,
        })
        .map_err(|e| {
            raise_error!(
                format!("cannot serialize UIDONLY ledger metadata: {e}"),
                ErrorCode::InternalError
            )
        })?;
        if bytes.len() as u64 > MAX_LEDGER_METADATA_BYTES {
            return Err(raise_error!(
                format!(
                    "UIDONLY ledger metadata exceeds its {}-byte ceiling",
                    MAX_LEDGER_METADATA_BYTES
                ),
                ErrorCode::PayloadTooLarge
            ));
        }
        let previous = fs::metadata(&self.ledger_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let additional = (bytes.len() as u64).saturating_sub(previous);
        self.reserve_state(additional)?;
        if let Err(error) = self.reserve_disk(additional) {
            self.state_bytes.fetch_sub(additional, Ordering::AcqRel);
            return Err(error);
        }
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
        let bytes = serde_json::to_vec(&LedgerEntryFile {
            entry: entry.clone(),
            checksum: ledger_entry_checksum(uid, entry),
        })
        .map_err(|e| {
            raise_error!(
                format!("cannot serialize UIDONLY ledger entry {uid}: {e}"),
                ErrorCode::InternalError
            )
        })?;
        if bytes.len() as u64 > MAX_LEDGER_ENTRY_BYTES {
            return Err(raise_error!(
                format!(
                    "UIDONLY ledger entry {uid} exceeds its {}-byte ceiling",
                    MAX_LEDGER_ENTRY_BYTES
                ),
                ErrorCode::PayloadTooLarge
            ));
        }
        let previous = fs::metadata(&path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let additional = (bytes.len() as u64).saturating_sub(previous);
        self.reserve_state(additional)?;
        if let Err(error) = self.reserve_disk(additional) {
            self.state_bytes.fetch_sub(additional, Ordering::AcqRel);
            return Err(error);
        }
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
        let blob_path = self.epoch_dir.join("blobs").join(format!("{uid}-{hash}"));
        let record_path = self.epoch_dir.join("records").join(format!("{uid}.json"));
        let blob_was_present = blob_path.exists();
        if !blob_was_present {
            self.reserve_disk(raw.len() as u64)?;
        }

        if blob_was_present {
            let existing = read_exact_file(&blob_path, raw.len() as u64)?;
            if blake3::hash(&existing).to_hex().as_str() != hash || existing != raw {
                return Err(raise_error!(
                    format!("stored blob verification failed for UID {uid}"),
                    ErrorCode::InternalError
                ));
            }
        } else {
            atomic_write(&blob_path, raw)?;
            let stored = read_exact_file(&blob_path, raw.len() as u64)?;
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

    fn read_staged_raw(
        &self,
        ledger: &AcquisitionLedger,
        uid: u32,
        expected_hash: &str,
    ) -> BichonResult<Vec<u8>> {
        let record_path = self.epoch_dir.join("records").join(format!("{uid}.json"));
        let record: StagingRecord =
            serde_json::from_slice(&read_bounded_file(&record_path, MAX_STAGING_RECORD_BYTES)?)
                .map_err(|error| {
                    raise_error!(
                        format!("invalid UIDONLY staging record for UID {uid}: {error}"),
                        ErrorCode::InternalError
                    )
                })?;
        if record.identity != ledger.identity
            || record.uid_validity != ledger.uid_validity
            || record.uid != uid
            || record.blob_hash != expected_hash
        {
            return Err(raise_error!(
                format!("UIDONLY staging record identity mismatch for UID {uid}"),
                ErrorCode::Incompatible
            ));
        }
        if record.bytes > self.limits.max_literal_bytes {
            return Err(raise_error!(
                format!("UIDONLY staging blob for UID {uid} exceeds the literal ceiling"),
                ErrorCode::PayloadTooLarge
            ));
        }
        let raw = read_exact_file(
            &self
                .epoch_dir
                .join("blobs")
                .join(format!("{uid}-{expected_hash}")),
            record.bytes,
        )?;
        if raw.len() as u64 != record.bytes || compute_content_hash(&raw) != expected_hash {
            return Err(raise_error!(
                format!("UIDONLY staging blob verification failed for UID {uid}"),
                ErrorCode::InternalError
            ));
        }
        Ok(raw)
    }

    fn reclaim_committed_staging(&self, ledger: &AcquisitionLedger) -> BichonResult<()> {
        for (&uid, entry) in &ledger.entries {
            self.validate_local()?;
            if matches!(
                entry.state,
                UidState::Committed { .. } | UidState::Filtered { .. }
            ) {
                let path = self.epoch_dir.join("records").join(format!("{uid}.json"));
                if let Ok(metadata) = fs::metadata(&path) {
                    fs::remove_file(&path).map_err(io_error)?;
                    self.disk_bytes.fetch_sub(metadata.len(), Ordering::AcqRel);
                }
            }
        }

        let mut referenced = BTreeSet::new();
        for entry in fs::read_dir(self.epoch_dir.join("records")).map_err(io_error)? {
            self.validate_local()?;
            let entry = entry.map_err(io_error)?;
            if !entry.file_type().map_err(io_error)?.is_file() {
                continue;
            }
            if is_owned_atomic_temp(&entry.file_name()) {
                fs::remove_file(entry.path()).map_err(io_error)?;
                continue;
            }
            let record: StagingRecord = serde_json::from_slice(&read_bounded_file(
                &entry.path(),
                MAX_STAGING_RECORD_BYTES,
            )?)
            .map_err(|error| {
                raise_error!(
                    format!("invalid UIDONLY staging record: {error}"),
                    ErrorCode::InternalError
                )
            })?;
            referenced.insert(format!("{}-{}", record.uid, record.blob_hash));
        }

        for entry in fs::read_dir(self.epoch_dir.join("blobs")).map_err(io_error)? {
            self.validate_local()?;
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

    fn reclaim_uid_staging(&self, uid: u32, blob_hash: &str) -> BichonResult<()> {
        for path in [
            self.epoch_dir.join("records").join(format!("{uid}.json")),
            self.epoch_dir
                .join("blobs")
                .join(format!("{uid}-{blob_hash}")),
        ] {
            if let Ok(metadata) = fs::metadata(&path) {
                fs::remove_file(&path).map_err(io_error)?;
                self.disk_bytes.fetch_sub(metadata.len(), Ordering::AcqRel);
            }
        }
        for directory in [self.epoch_dir.join("records"), self.epoch_dir.join("blobs")] {
            File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(io_error)?;
        }
        Ok(())
    }
}

fn is_owned_atomic_temp(file_name: &OsStr) -> bool {
    let Some(name) = file_name.to_str() else {
        return false;
    };
    let Some(body) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((target, id)) = body.rsplit_once('.') else {
        return false;
    };
    !target.is_empty() && uuid::Uuid::parse_str(id).is_ok()
}

fn io_error(error: std::io::Error) -> crate::error::BichonError {
    raise_error!(
        format!("UIDONLY durable I/O failed: {error}"),
        ErrorCode::InternalError
    )
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> BichonResult<Vec<u8>> {
    let size = fs::metadata(path).map_err(io_error)?.len();
    if size > max_bytes {
        return Err(raise_error!(
            format!(
                "UIDONLY durable file {} is {size} bytes, exceeding its {max_bytes}-byte read ceiling",
                path.display()
            ),
            ErrorCode::PayloadTooLarge
        ));
    }
    let capacity = usize::try_from(size).map_err(|_| {
        raise_error!(
            "UIDONLY durable file size does not fit memory address space".into(),
            ErrorCode::PayloadTooLarge
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .map_err(io_error)?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > max_bytes {
        return Err(raise_error!(
            format!(
                "UIDONLY durable file {} grew beyond its {max_bytes}-byte read ceiling",
                path.display()
            ),
            ErrorCode::PayloadTooLarge
        ));
    }
    Ok(bytes)
}

fn read_exact_file(path: &Path, expected_bytes: u64) -> BichonResult<Vec<u8>> {
    let bytes = read_bounded_file(path, expected_bytes)?;
    if bytes.len() as u64 != expected_bytes {
        return Err(raise_error!(
            format!(
                "UIDONLY durable file {} has {} bytes, expected {expected_bytes}",
                path.display(),
                bytes.len()
            ),
            ErrorCode::InternalError
        ));
    }
    Ok(bytes)
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

#[cfg(test)]
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

fn directory_size_guarded(
    path: &Path,
    started: Option<Instant>,
    token: Option<&CancellationToken>,
    limits: AcquisitionLimits,
) -> BichonResult<u64> {
    if let (Some(started), Some(token)) = (started, token) {
        validate_runtime(started, limits, token)?;
    }
    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in fs::read_dir(path).map_err(io_error)? {
        if let (Some(started), Some(token)) = (started, token) {
            validate_runtime(started, limits, token)?;
        }
        let entry = entry.map_err(io_error)?;
        let metadata = entry.metadata().map_err(io_error)?;
        total = total.saturating_add(if metadata.is_dir() {
            directory_size_guarded(&entry.path(), started, token, limits)?
        } else {
            metadata.len()
        });
    }
    Ok(total)
}

fn discard_owned_atomic_temps(
    path: &Path,
    started: Option<Instant>,
    token: Option<&CancellationToken>,
    limits: AcquisitionLimits,
) -> BichonResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut removed = false;
    for entry in fs::read_dir(path).map_err(io_error)? {
        if let (Some(started), Some(token)) = (started, token) {
            validate_runtime(started, limits, token)?;
        }
        let entry = entry.map_err(io_error)?;
        if entry.file_type().map_err(io_error)?.is_dir() {
            discard_owned_atomic_temps(&entry.path(), started, token, limits)?;
        } else if is_owned_atomic_temp(&entry.file_name()) {
            fs::remove_file(entry.path()).map_err(io_error)?;
            removed = true;
        }
    }
    if removed {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
    }
    Ok(())
}

enum CleanupMarkers {
    Absent,
    Present {
        accounts: BTreeSet<String>,
        mailboxes: BTreeSet<String>,
        invalid_account_type: bool,
        invalid_mailbox_type: bool,
    },
}

fn cleanup_markers(identity_dir: &Path) -> BichonResult<CleanupMarkers> {
    let mut accounts = BTreeSet::new();
    let mut mailboxes = BTreeSet::new();
    let mut invalid_account_type = false;
    let mut invalid_mailbox_type = false;
    for entry in fs::read_dir(identity_dir).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_account = name.starts_with(".bichon-account-");
        let is_mailbox = name.starts_with(".bichon-mailbox-");
        if !is_account && !is_mailbox {
            continue;
        }
        if !entry.file_type().map_err(io_error)?.is_file() {
            if is_account {
                invalid_account_type = true;
            } else {
                invalid_mailbox_type = true;
            }
            continue;
        }
        if is_account {
            accounts.insert(name);
        } else {
            mailboxes.insert(name);
        }
    }
    if accounts.is_empty() && mailboxes.is_empty() && !invalid_account_type && !invalid_mailbox_type
    {
        return Ok(CleanupMarkers::Absent);
    }
    Ok(CleanupMarkers::Present {
        accounts,
        mailboxes,
        invalid_account_type,
        invalid_mailbox_type,
    })
}

fn legacy_cleanup_identity(identity_dir: &Path) -> BichonResult<Option<AcquisitionIdentity>> {
    for epoch in fs::read_dir(identity_dir).map_err(io_error)? {
        let epoch = epoch.map_err(io_error)?;
        if !epoch.file_type().map_err(io_error)?.is_dir() {
            continue;
        }
        let ledger = epoch.path().join("ledger.json");
        if !ledger.exists() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_slice(&read_bounded_file(&ledger, MAX_LEDGER_METADATA_BYTES)?)
                .map_err(|error| {
                    raise_error!(
                        format!(
                            "invalid UIDONLY cleanup ledger {}: {error}",
                            ledger.display()
                        ),
                        ErrorCode::InternalError
                    )
                })?;
        if value.get("entries").is_some() {
            return serde_json::from_value::<AcquisitionLedger>(value)
                .map(|ledger| Some(ledger.identity))
                .map_err(|error| {
                    raise_error!(
                        format!(
                            "invalid legacy UIDONLY cleanup ledger {}: {error}",
                            ledger.display()
                        ),
                        ErrorCode::InternalError
                    )
                });
        }
        let file: LedgerMetadataFile = serde_json::from_value(value).map_err(|error| {
            raise_error!(
                format!(
                    "invalid UIDONLY cleanup metadata {}: {error}",
                    ledger.display()
                ),
                ErrorCode::InternalError
            )
        })?;
        if file.checksum != ledger_metadata_checksum(&file.metadata) {
            return Err(raise_error!(
                format!(
                    "UIDONLY cleanup metadata checksum mismatch in {}",
                    ledger.display()
                ),
                ErrorCode::InternalError
            ));
        }
        return Ok(Some(file.metadata.identity));
    }
    Ok(None)
}

fn cleanup_uidonly_state(
    root: &Path,
    account_marker: &str,
    mailbox_markers: Option<&BTreeSet<String>>,
    legacy_matches: impl Fn(&AcquisitionIdentity) -> bool,
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
        let selected = match cleanup_markers(&identity_dir.path())? {
            CleanupMarkers::Present {
                accounts,
                mailboxes,
                invalid_account_type,
                invalid_mailbox_type,
            } => {
                let account_matches = !invalid_account_type
                    && accounts.len() == 1
                    && accounts.contains(account_marker);
                let mailbox_matches = mailbox_markers.is_none_or(|targets| {
                    !invalid_mailbox_type
                        && mailboxes.len() == 1
                        && mailboxes
                            .iter()
                            .next()
                            .is_some_and(|marker| targets.contains(marker))
                });
                let selected = account_matches && mailbox_matches;
                if !selected
                    && (accounts.contains(account_marker)
                        || mailboxes.iter().any(|marker| {
                            mailbox_markers.is_some_and(|targets| targets.contains(marker))
                        }))
                {
                    tracing::warn!(
                        path = %identity_dir.path().display(),
                        "retaining UIDONLY state with ambiguous lifecycle markers"
                    );
                }
                selected
            }
            CleanupMarkers::Absent => match legacy_cleanup_identity(&identity_dir.path()) {
                Ok(identity) => identity.as_ref().is_some_and(&legacy_matches),
                Err(error) => {
                    // This branch predates marker routing and has never shipped.
                    // Retain an unmarked corrupt directory for manual review;
                    // it cannot identify itself safely and must never block a
                    // marker-routed deletion for another account or mailbox.
                    tracing::warn!(
                        path = %identity_dir.path().display(),
                        error = %error,
                        "retaining corrupt unmarked UIDONLY state during lifecycle cleanup"
                    );
                    false
                }
            },
        };
        if selected {
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
    cleanup_uidonly_state(
        root,
        &format!(".bichon-account-{account_id}"),
        None,
        |identity| identity.account_id == account_id,
    )
}

pub(crate) fn cleanup_uidonly_mailbox_state(
    root: &Path,
    account_id: u64,
    canonical_mailboxes: &BTreeSet<String>,
) -> BichonResult<usize> {
    let mailbox_markers: BTreeSet<_> = canonical_mailboxes
        .iter()
        .map(|mailbox| format!(".bichon-mailbox-{}", mailbox_marker_hash(mailbox)))
        .collect();
    cleanup_uidonly_state(
        root,
        &format!(".bichon-account-{account_id}"),
        Some(&mailbox_markers),
        |identity| {
            identity.account_id == account_id
                && canonical_mailboxes.contains(&identity.canonical_mailbox)
        },
    )
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
    raw: Option<&[u8]>,
) -> BichonResult<()> {
    tokio::time::timeout(
        CANONICAL_CLEANUP_GRACE,
        canonical.rollback(uid, content_hash, envelope_id, raw),
    )
    .await
    .map_err(|_| {
        raise_error!(
            "UIDONLY canonical rollback timed out".into(),
            ErrorCode::RequestTimeout
        )
    })?
}

async fn cleanup_staged_canonical<C: CanonicalArchive>(
    canonical: &mut C,
    archive: &DurableArchive,
    ledger: &AcquisitionLedger,
    uid: u32,
    content_hash: &str,
    envelope_id: Option<&str>,
) -> BichonResult<()> {
    let raw = archive.read_staged_raw(ledger, uid, content_hash)?;
    cleanup_canonical(canonical, uid, content_hash, envelope_id, Some(&raw)).await
}

fn record_vanished_ranges(
    ranges: &mut Vec<UidRange>,
    additions: impl IntoIterator<Item = RangeInclusive<u32>>,
    snapshot_start: u32,
    snapshot_end: u32,
) -> bool {
    let mut changed = false;
    for range in additions {
        let start = (*range.start()).max(snapshot_start);
        let end = (*range.end()).min(snapshot_end);
        if start > end {
            continue;
        }

        // `ranges` is always sorted and coalesced. The overwhelmingly common
        // sparse-mailbox case appends ascending VANISHED ranges in O(1); an
        // out-of-order unsolicited range uses binary search and only rewrites
        // the overlapping interval instead of re-sorting the full history.
        let first = ranges.partition_point(|existing| existing.end.saturating_add(1) < start);
        let mut merged_start = start;
        let mut merged_end = end;
        let mut last = first;
        while let Some(existing) = ranges.get(last) {
            if existing.start > merged_end.saturating_add(1) {
                break;
            }
            merged_start = merged_start.min(existing.start);
            merged_end = merged_end.max(existing.end);
            last += 1;
        }
        if first == last {
            ranges.insert(
                first,
                UidRange {
                    start: merged_start,
                    end: merged_end,
                },
            );
            changed = true;
        } else if last - first != 1
            || ranges[first].start != merged_start
            || ranges[first].end != merged_end
        {
            ranges.splice(
                first..last,
                [UidRange {
                    start: merged_start,
                    end: merged_end,
                }],
            );
            changed = true;
        }
    }
    changed
}

fn inventory_digest(ledger: &AcquisitionLedger) -> String {
    let mut digest = inventory_digest_seed(
        &ledger.identity,
        ledger.uid_validity,
        ledger.snapshot_start,
        ledger.snapshot_end,
    );
    for (uid, entry) in &ledger.entries {
        digest = extend_inventory_digest(&digest, *uid, entry);
    }
    digest
}

fn inventory_digest_seed(
    identity: &AcquisitionIdentity,
    uid_validity: u32,
    snapshot_start: u32,
    snapshot_end: u32,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bichon-uidonly-inventory-chain-v2");
    hasher.update(identity.storage_key().as_bytes());
    hasher.update(&uid_validity.to_be_bytes());
    hasher.update(&snapshot_start.to_be_bytes());
    hasher.update(&snapshot_end.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

fn extend_inventory_digest(previous: &str, uid: u32, entry: &UidEntry) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bichon-uidonly-inventory-entry-v2");
    hasher.update(previous.as_bytes());
    hasher.update(&uid.to_be_bytes());
    match entry.declared_size {
        Some(size) => {
            hasher.update(&[1]);
            hasher.update(&size.to_be_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match entry.internal_date {
        Some(date) => {
            hasher.update(&[1]);
            hasher.update(&date.to_be_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.finalize().to_hex().to_string()
}

fn append_inventory_manifest(ledger: &mut AcquisitionLedger, uid: u32) {
    let previous = ledger.inventory_digest.clone().unwrap_or_else(|| {
        inventory_digest_seed(
            &ledger.identity,
            ledger.uid_validity,
            ledger.snapshot_start,
            ledger.snapshot_end,
        )
    });
    ledger.inventory_digest = Some(extend_inventory_digest(
        &previous,
        uid,
        &ledger.entries[&uid],
    ));
    ledger.inventory_count = ledger.inventory_count.saturating_add(1);
}

fn ledger_entry_checksum(uid: u32, entry: &UidEntry) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bichon-uidonly-ledger-entry-v1");
    hasher.update(&uid.to_be_bytes());
    hasher.update(
        &serde_json::to_vec(entry).expect("UID ledger entries are serializable for checksumming"),
    );
    hasher.finalize().to_hex().to_string()
}

fn ledger_metadata_checksum(metadata: &LedgerMetadata) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bichon-uidonly-ledger-metadata-v1");
    hasher.update(
        &serde_json::to_vec(metadata)
            .expect("UID ledger metadata is serializable for checksumming"),
    );
    hasher.finalize().to_hex().to_string()
}

fn seal_inventory(ledger: &mut AcquisitionLedger) {
    ledger.inventory_cursor = None;
    ledger.inventory_complete = true;
    refresh_inventory_manifest(ledger);
}

fn has_vanished_evidence(ledger: &AcquisitionLedger, uid: u32) -> bool {
    let index = ledger
        .vanished_ranges
        .partition_point(|range| range.end < uid);
    ledger
        .vanished_ranges
        .get(index)
        .is_some_and(|range| range.start <= uid)
}

fn acquisition_state_memory_estimate(
    entry_count: usize,
    vanished_range_count: usize,
    uid_worklist_count: usize,
) -> u64 {
    LEDGER_BASE_MEMORY_ESTIMATE
        .saturating_add((entry_count as u64).saturating_mul(LEDGER_ENTRY_MEMORY_ESTIMATE))
        .saturating_add(
            (vanished_range_count as u64).saturating_mul(VANISHED_RANGE_MEMORY_ESTIMATE),
        )
        .saturating_add((uid_worklist_count as u64).saturating_mul(u32::BITS as u64 / 8))
}

fn enforce_state_memory_ceiling(
    limits: AcquisitionLimits,
    entry_count: usize,
    vanished_range_count: usize,
    uid_worklist_count: usize,
) -> BichonResult<u64> {
    let estimated =
        acquisition_state_memory_estimate(entry_count, vanished_range_count, uid_worklist_count);
    if estimated > limits.max_memory_bytes {
        return Err(raise_error!(
            format!(
                "UIDONLY acquisition state memory estimate {estimated} exceeds its {}-byte ceiling",
                limits.max_memory_bytes
            ),
            ErrorCode::PayloadTooLarge
        ));
    }
    Ok(estimated)
}

fn refresh_inventory_manifest(ledger: &mut AcquisitionLedger) {
    ledger.inventory_count = ledger.entries.len() as u64;
    ledger.inventory_digest = Some(inventory_digest(ledger));
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
    let mut snapshot_retry = 0;
    let snapshot = loop {
        match bounded_transport(transport.snapshot(mailbox), started, limits, &token).await {
            Ok(snapshot) => break snapshot,
            Err(error)
                if error.code() == ErrorCode::NetworkError
                    && snapshot_retry < MAX_NETWORK_RETRIES =>
            {
                snapshot_retry += 1;
                bounded_transport(transport.reconnect(), started, limits, &token).await?;
            }
            Err(error) => return Err(error),
        }
    };
    let snapshot_vanished = transport.take_vanished();
    canonical.begin_epoch(snapshot.uid_validity)?;
    let snapshot_end = snapshot.uid_next.saturating_sub(1);
    let archive = DurableArchive::open_bounded(
        root,
        &identity,
        snapshot.uid_validity,
        limits,
        started,
        &token,
    )?;
    let mut ledger = archive.load_or_create(identity, snapshot.uid_validity, snapshot_end)?;
    enforce_state_memory_ceiling(
        limits,
        ledger.entries.len(),
        ledger.vanished_ranges.len(),
        0,
    )?;
    if ledger.snapshot_end > snapshot_end {
        return Err(raise_error!(
            format!(
                "UIDONLY current UIDNEXT is behind durable snapshot end {}",
                ledger.snapshot_end
            ),
            ErrorCode::Incompatible
        ));
    }
    if ledger.checkpoint == Some(ledger.snapshot_end) && snapshot_end > ledger.snapshot_end {
        ledger.snapshot_start = ledger.snapshot_end.saturating_add(1);
        ledger.snapshot_end = snapshot_end;
        ledger.inventory_cursor = Some(ledger.snapshot_start);
        ledger.inventory_complete = false;
        refresh_inventory_manifest(&mut ledger);
        ledger.checkpoint = None;
        archive.persist_metadata(&ledger)?;
    }
    let snapshot_metadata_changed = record_vanished_ranges(
        &mut ledger.vanished_ranges,
        snapshot_vanished.iter().cloned(),
        ledger.snapshot_start,
        ledger.snapshot_end,
    );
    for range in snapshot_vanished {
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
    if ledger.vanished_ranges.len() > limits.max_messages {
        return Err(raise_error!(
            format!(
                "UIDONLY VANISHED range ceiling {} exceeded",
                limits.max_messages
            ),
            ErrorCode::PayloadTooLarge
        ));
    }
    if snapshot_metadata_changed {
        archive.persist_metadata(&ledger)?;
    }
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
                envelope_id,
                owned,
                ..
            } => Some((
                uid,
                blob_hash.clone(),
                *canonical_bytes,
                envelope_id.clone(),
                *owned,
            )),
            _ => None,
        })
        .collect();
    for (uid, blob_hash, canonical_bytes, envelope_id, owned) in interrupted {
        let raw = archive.read_staged_raw(&ledger, uid, &blob_hash)?;
        let verified = match envelope_id.as_deref() {
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
        if verified {
            ledger.entries.get_mut(&uid).unwrap().state = UidState::Committed {
                blob_hash: blob_hash.clone(),
                bytes: raw.len() as u64,
                canonical_bytes,
                envelope_id,
                owned: owned.unwrap_or(true),
            };
            archive.persist_entry(uid, &ledger.entries[&uid])?;
            archive.reclaim_uid_staging(uid, &blob_hash)?;
            continue;
        }
        if owned == Some(true) {
            cleanup_canonical(
                canonical,
                uid,
                &blob_hash,
                envelope_id.as_deref(),
                Some(&raw),
            )
            .await?;
        }
        archive.release_disk(canonical_bytes);
        ledger.entries.get_mut(&uid).unwrap().state = UidState::Missing;
        archive.persist_entry(uid, &ledger.entries[&uid])?;
        ledger.checkpoint = None;
    }
    if ledger.checkpoint.is_none() {
        archive.persist_metadata(&ledger)?;
    }

    let committed: Vec<_> = ledger
        .entries
        .iter()
        .filter_map(|(&uid, entry)| match &entry.state {
            UidState::Committed {
                blob_hash,
                canonical_bytes,
                envelope_id,
                owned,
                ..
            } => Some((
                uid,
                blob_hash.clone(),
                *canonical_bytes,
                envelope_id.clone(),
                *owned,
            )),
            _ => None,
        })
        .collect();
    for (uid, blob_hash, canonical_bytes, envelope_id, owned) in committed {
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
            if owned {
                cleanup_canonical(canonical, uid, &blob_hash, envelope_id.as_deref(), None).await?;
            }
            archive.release_disk(canonical_bytes);
            ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                reason: "committed canonical record or blob failed restart validation".into(),
            };
            archive.persist_entry(uid, &ledger.entries[&uid])?;
            ledger.checkpoint = None;
        }
    }
    // A restart continues the original fixed snapshot even if UIDNEXT grew.
    let snapshot_end = ledger.snapshot_end;

    let page_size = limits.page_size.max(1);
    let mut first_uid = ledger.inventory_cursor.unwrap_or(ledger.snapshot_start);
    while !ledger.inventory_complete && first_uid <= snapshot_end {
        validate_runtime(started, limits, &token)?;
        let mut page_retry = 0;
        let page = loop {
            match bounded_transport(
                transport.inventory_page(first_uid, snapshot_end, page_size),
                started,
                limits,
                &token,
            )
            .await
            {
                Ok(page) => break page,
                Err(error)
                    if error.code() == ErrorCode::NetworkError
                        && page_retry < MAX_NETWORK_RETRIES =>
                {
                    page_retry += 1;
                    bounded_transport(transport.reconnect(), started, limits, &token).await?;
                    let resumed =
                        bounded_transport(transport.snapshot(mailbox), started, limits, &token)
                            .await?;
                    if resumed.uid_validity != ledger.uid_validity {
                        return Err(raise_error!(
                            format!(
                                "UIDVALIDITY changed during inventory reconnect from {} to {}",
                                ledger.uid_validity, resumed.uid_validity
                            ),
                            ErrorCode::Incompatible
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        };
        if page.items.len() > page_size as usize {
            return Err(raise_error!(
                format!(
                    "UIDONLY server returned {} inventory items for requested page size {page_size}",
                    page.items.len()
                ),
                ErrorCode::ImapUnexpectedResult
            ));
        }
        let prospective_entries = ledger
            .entries
            .len()
            .checked_add(page.items.len())
            .ok_or_else(|| {
                raise_error!(
                    "UIDONLY inventory entry count overflow".into(),
                    ErrorCode::PayloadTooLarge
                )
            })?;
        if prospective_entries > limits.max_messages {
            return Err(raise_error!(
                format!("UIDONLY message ceiling {} exceeded", limits.max_messages),
                ErrorCode::PayloadTooLarge
            ));
        }
        let mut vanished = transport.take_vanished();
        vanished.extend(page.vanished);
        let metadata_changed = record_vanished_ranges(
            &mut ledger.vanished_ranges,
            vanished.iter().cloned(),
            ledger.snapshot_start,
            snapshot_end,
        );
        for range in vanished {
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
        if ledger.vanished_ranges.len() > limits.max_messages {
            return Err(raise_error!(
                format!(
                    "UIDONLY VANISHED range ceiling {} exceeded",
                    limits.max_messages
                ),
                ErrorCode::PayloadTooLarge
            ));
        }
        if metadata_changed {
            archive.persist_metadata(&ledger)?;
        }
        enforce_state_memory_ceiling(
            limits,
            prospective_entries,
            ledger.vanished_ranges.len(),
            page.items.len(),
        )?;
        if page.items.is_empty() {
            seal_inventory(&mut ledger);
            archive.persist_metadata(&ledger)?;
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
            if has_vanished_evidence(&ledger, item.uid) {
                return Err(raise_error!(
                    format!(
                        "UIDONLY inventory contradicted durable VANISHED evidence for UID {}",
                        item.uid
                    ),
                    ErrorCode::ImapUnexpectedResult
                ));
            }
            previous = item.uid;
            if ledger.entries.contains_key(&item.uid) {
                return Err(raise_error!(
                    format!(
                        "UIDONLY inventory cursor revisited already-durable UID {}",
                        item.uid
                    ),
                    ErrorCode::ImapUnexpectedResult
                ));
            }
            ledger.entries.insert(
                item.uid,
                UidEntry {
                    declared_size: item.size,
                    internal_date: item.internal_date,
                    state: UidState::Missing,
                },
            );
            archive.persist_entry(item.uid, &ledger.entries[&item.uid])?;
            append_inventory_manifest(&mut ledger, item.uid);
        }
        if ledger.entries.len() > limits.max_messages {
            return Err(raise_error!(
                format!("UIDONLY message ceiling {} exceeded", limits.max_messages),
                ErrorCode::PayloadTooLarge
            ));
        }
        if previous == snapshot_end {
            seal_inventory(&mut ledger);
            archive.persist_metadata(&ledger)?;
            break;
        }
        first_uid = previous.checked_add(1).ok_or_else(|| {
            raise_error!(
                "UID cursor overflow".into(),
                ErrorCode::ImapUnexpectedResult
            )
        })?;
        ledger.inventory_cursor = Some(first_uid);
        archive.persist_metadata(&ledger)?;
    }

    // This is deliberately `remote - durably revalidated local`. Records not
    // represented by this epoch's ledger are fetched into a deterministic
    // current-epoch identity, so local metadata can never omit remote mail.
    enforce_state_memory_ceiling(
        limits,
        ledger.entries.len(),
        ledger.vanished_ranges.len(),
        ledger.entries.len().saturating_mul(6),
    )?;
    let remote_uids: Vec<NonZeroU32> = ledger
        .entries
        .keys()
        .map(|uid| NonZeroU32::new(*uid).expect("inventory UIDs are nonzero"))
        .collect();
    let locally_verified: Vec<NonZeroU32> = ledger
        .entries
        .iter()
        .filter(|(_, entry)| matches!(entry.state, UidState::Committed { .. }))
        .map(|(&uid, _)| NonZeroU32::new(uid).expect("inventory UIDs are nonzero"))
        .collect();
    let uids: Vec<u32> = missing_verified_uids(&remote_uids, &locally_verified)
        .map_err(|error| {
            raise_error!(
                format!("UIDONLY local reconciliation failed: {error}"),
                ErrorCode::InternalError
            )
        })?
        .into_iter()
        .map(NonZeroU32::get)
        .collect();
    // Account for the durable map plus the remote/local/difference vectors.
    // The estimate deliberately prices each UID vector element above its
    // physical u32 size to cover Vec capacity and alignment slack.
    let state_memory = enforce_state_memory_ceiling(
        limits,
        ledger.entries.len(),
        ledger.vanished_ranges.len(),
        remote_uids
            .len()
            .saturating_add(locally_verified.len())
            .saturating_add(uids.len())
            .saturating_mul(2),
    )?;
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
        let current_state = ledger.entries[&uid].state.clone();
        let declared_size = ledger.entries[&uid].declared_size;
        if current_state.reconciled() {
            continue;
        }
        if let UidState::Oversized { declared, .. } = current_state {
            if declared > limits.max_literal_bytes {
                continue;
            }
            ledger.entries.get_mut(&uid).unwrap().state = UidState::Missing;
            archive.persist_entry(uid, &ledger.entries[&uid])?;
        }
        if let Some(declared) = declared_size {
            if declared > limits.max_literal_bytes {
                ledger.entries.get_mut(&uid).unwrap().state = UidState::Oversized {
                    declared,
                    limit: limits.max_literal_bytes,
                };
                archive.persist_entry(uid, &ledger.entries[&uid])?;
                continue;
            }
            if total_bytes
                .checked_add(declared)
                .is_none_or(|total| total > limits.max_total_bytes)
            {
                ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                    reason: format!(
                        "UIDONLY total byte ceiling {} would be exceeded by declared UID {uid} size {declared}",
                        limits.max_total_bytes
                    ),
                };
                archive.persist_entry(uid, &ledger.entries[&uid])?;
                continue;
            }
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

        let fetch_vanished = transport.take_vanished();
        let metadata_changed = record_vanished_ranges(
            &mut ledger.vanished_ranges,
            fetch_vanished.iter().cloned(),
            ledger.snapshot_start,
            snapshot_end,
        );
        for range in fetch_vanished {
            let mut changed = Vec::new();
            for (&vanished_uid, entry) in ledger.entries.range_mut(range) {
                if !matches!(entry.state, UidState::Committed { .. } | UidState::Vanished) {
                    entry.state = UidState::Vanished;
                    changed.push(vanished_uid);
                }
            }
            for vanished_uid in changed {
                archive.persist_entry(vanished_uid, &ledger.entries[&vanished_uid])?;
            }
        }
        if ledger.vanished_ranges.len() > limits.max_messages {
            return Err(raise_error!(
                format!(
                    "UIDONLY VANISHED range ceiling {} exceeded",
                    limits.max_messages
                ),
                ErrorCode::PayloadTooLarge
            ));
        }
        if metadata_changed {
            archive.persist_metadata(&ledger)?;
        }

        // VANISHED is permanent within a UIDVALIDITY epoch. A notification
        // observed on EXAMINE/reconnect wins over a later stale body or empty
        // FETCH response and must never be overwritten by Committed/Missing.
        let outcome = if has_vanished_evidence(&ledger, uid) {
            FetchOutcome::Vanished
        } else {
            outcome
        };

        match outcome {
            FetchOutcome::Vanished => {
                record_vanished_ranges(
                    &mut ledger.vanished_ranges,
                    [uid..=uid],
                    ledger.snapshot_start,
                    snapshot_end,
                );
                ledger.entries.get_mut(&uid).unwrap().state = UidState::Vanished;
                archive.persist_metadata(&ledger)?;
            }
            FetchOutcome::Missing => {
                // A tagged-OK body FETCH with no data is not, by itself,
                // durable absence evidence. Re-inventory this exact UID in
                // the fixed snapshot range. A successful empty result proves
                // the UID is now absent even when the server cannot replay a
                // historical VANISHED event after reconnect.
                let mut absence_retry = 0;
                let absence_page = loop {
                    match bounded_transport(
                        transport.inventory_page(uid, uid, 1),
                        started,
                        limits,
                        &token,
                    )
                    .await
                    {
                        Ok(page) => break Ok((page, transport.take_vanished())),
                        Err(error)
                            if error.code() == ErrorCode::NetworkError
                                && absence_retry < MAX_NETWORK_RETRIES =>
                        {
                            absence_retry += 1;
                            bounded_transport(transport.reconnect(), started, limits, &token)
                                .await?;
                            let resumed = bounded_transport(
                                transport.snapshot(mailbox),
                                started,
                                limits,
                                &token,
                            )
                            .await?;
                            if resumed.uid_validity != ledger.uid_validity {
                                break Err(raise_error!(
                                    format!(
                                        "UIDVALIDITY changed during missing-UID revalidation from {} to {}",
                                        ledger.uid_validity, resumed.uid_validity
                                    ),
                                    ErrorCode::Incompatible
                                ));
                            }
                        }
                        Err(error) => break Err(error),
                    }
                };
                match absence_page {
                    Ok((page, unsolicited))
                        if page.items.is_empty()
                            && page.vanished.is_empty()
                            && unsolicited.is_empty() =>
                    {
                        record_vanished_ranges(
                            &mut ledger.vanished_ranges,
                            [uid..=uid],
                            ledger.snapshot_start,
                            snapshot_end,
                        );
                        ledger.entries.get_mut(&uid).unwrap().state = UidState::Vanished;
                        archive.persist_metadata(&ledger)?;
                    }
                    Ok((page, unsolicited)) => {
                        let mut evidence = unsolicited;
                        evidence.extend(page.vanished);
                        let changed = record_vanished_ranges(
                            &mut ledger.vanished_ranges,
                            evidence,
                            ledger.snapshot_start,
                            snapshot_end,
                        );
                        if changed {
                            archive.persist_metadata(&ledger)?;
                        }
                        if has_vanished_evidence(&ledger, uid) {
                            ledger.entries.get_mut(&uid).unwrap().state = UidState::Vanished;
                        } else if page.items.len() == 1 && page.items[0].uid == uid {
                            ledger.entries.get_mut(&uid).unwrap().state = UidState::Missing;
                        } else {
                            ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                                reason: "exact missing-UID inventory returned an unexpected result"
                                    .into(),
                            };
                        }
                    }
                    Err(error) => {
                        ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                            reason: error.to_string(),
                        };
                    }
                }
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
                } else if canonical
                    .memory_budget(&raw)?
                    .checked_add(state_memory)
                    .is_none_or(|required| required > limits.max_memory_bytes)
                {
                    ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                        reason: format!(
                            "UIDONLY projection memory ceiling {} bytes would be exceeded",
                            limits.max_memory_bytes
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
                                let envelope_id = canonical.envelope_id(uid, &blob_hash)?;
                                ledger.entries.get_mut(&uid).unwrap().state =
                                    UidState::Projecting {
                                        blob_hash: blob_hash.clone(),
                                        bytes,
                                        canonical_bytes: budget,
                                        envelope_id: Some(envelope_id.clone()),
                                        owned: Some(true),
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
                                        raw,
                                        declared,
                                        ledger.entries[&uid].internal_date.unwrap_or(0),
                                        projection_shutdown.clone(),
                                    ),
                                    started,
                                    limits,
                                    &token,
                                    Some(&projection_shutdown),
                                )
                                .await;
                                match projected {
                                    Ok(Some(projection)) => {
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
                                                // Retain the conservative
                                                // reservation for canonical
                                                // values created by this UID.
                                                // It intentionally overcounts
                                                // shared blobs so the durable
                                                // ledger enforces a hard
                                                // acquisition-owned disk
                                                // admission ceiling across
                                                // restarts.
                                                let canonical_bytes = if projection.created {
                                                    budget
                                                } else {
                                                    archive.release_disk(budget);
                                                    0
                                                };
                                                ledger.entries.get_mut(&uid).unwrap().state =
                                                    UidState::Projecting {
                                                        blob_hash: blob_hash.clone(),
                                                        bytes,
                                                        canonical_bytes,
                                                        envelope_id: Some(
                                                            projection.envelope_id.clone(),
                                                        ),
                                                        owned: Some(projection.created),
                                                    };
                                                if let Err(error) = archive
                                                    .persist_entry(uid, &ledger.entries[&uid])
                                                {
                                                    if projection.created {
                                                        cleanup_staged_canonical(
                                                            canonical,
                                                            &archive,
                                                            &ledger,
                                                            uid,
                                                            &blob_hash,
                                                            Some(&projection.envelope_id),
                                                        )
                                                        .await?;
                                                        archive.release_disk(budget);
                                                    }
                                                    return Err(error);
                                                }
                                                ledger.entries.get_mut(&uid).unwrap().state =
                                                    UidState::Committed {
                                                        blob_hash: blob_hash.clone(),
                                                        bytes,
                                                        canonical_bytes,
                                                        envelope_id: Some(
                                                            projection.envelope_id.clone(),
                                                        ),
                                                        owned: projection.created,
                                                    };
                                                if let Err(error) = archive
                                                    .persist_entry(uid, &ledger.entries[&uid])
                                                {
                                                    if projection.created {
                                                        cleanup_staged_canonical(
                                                            canonical,
                                                            &archive,
                                                            &ledger,
                                                            uid,
                                                            &blob_hash,
                                                            Some(&projection.envelope_id),
                                                        )
                                                        .await?;
                                                        archive.release_disk(budget);
                                                    }
                                                    return Err(error);
                                                }
                                                archive.reclaim_uid_staging(uid, &blob_hash)?;
                                                total_bytes = total_bytes.saturating_add(bytes);
                                                continue;
                                            }
                                            Ok(false) => {
                                                if projection.created {
                                                    cleanup_staged_canonical(
                                                        canonical,
                                                        &archive,
                                                        &ledger,
                                                        uid,
                                                        &blob_hash,
                                                        Some(&projection.envelope_id),
                                                    )
                                                    .await?;
                                                }
                                                archive.release_disk(budget);
                                                ledger.entries.get_mut(&uid).unwrap().state =
                                                    UidState::Failed {
                                                        reason: "canonical projection verification failed"
                                                            .into(),
                                                    };
                                            }
                                            Err(failure) => {
                                                if projection.created {
                                                    cleanup_staged_canonical(
                                                        canonical,
                                                        &archive,
                                                        &ledger,
                                                        uid,
                                                        &blob_hash,
                                                        Some(&projection.envelope_id),
                                                    )
                                                    .await?;
                                                }
                                                archive.release_disk(budget);
                                                return Err(failure.error);
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        archive.release_disk(budget);
                                        total_bytes = total_bytes.saturating_add(bytes);
                                        ledger.entries.get_mut(&uid).unwrap().state =
                                            UidState::Filtered {
                                                reason: "excluded by configured archive rules"
                                                    .into(),
                                            };
                                        archive.persist_entry(uid, &ledger.entries[&uid])?;
                                        archive.reclaim_uid_staging(uid, &blob_hash)?;
                                        continue;
                                    }
                                    Err(failure) => {
                                        if !failure.cleanup_pending {
                                            cleanup_staged_canonical(
                                                canonical,
                                                &archive,
                                                &ledger,
                                                uid,
                                                &blob_hash,
                                                Some(&envelope_id),
                                            )
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
                owned,
                ..
            } => Some((
                uid,
                blob_hash.clone(),
                *canonical_bytes,
                envelope_id.clone(),
                *owned,
            )),
            _ => None,
        })
        .collect();
    for (uid, blob_hash, canonical_bytes, envelope_id, owned) in final_committed {
        if !bounded_canonical(
            canonical.verify(uid, &blob_hash, &envelope_id),
            started,
            limits,
            &token,
            None,
        )
        .await?
        {
            if owned {
                cleanup_canonical(canonical, uid, &blob_hash, Some(&envelope_id), None).await?;
            }
            archive.release_disk(canonical_bytes);
            ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                reason: "canonical record failed final checkpoint revalidation".into(),
            };
            archive.persist_entry(uid, &ledger.entries[&uid])?;
            ledger.checkpoint = None;
        }
    }

    let unproven_vanished: Vec<u32> = ledger
        .entries
        .iter()
        .filter_map(|(&uid, entry)| {
            (matches!(entry.state, UidState::Vanished) && !has_vanished_evidence(&ledger, uid))
                .then_some(uid)
        })
        .collect();
    for uid in unproven_vanished {
        ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
            reason: "VANISHED state has no durable server evidence".into(),
        };
        archive.persist_entry(uid, &ledger.entries[&uid])?;
        ledger.checkpoint = None;
    }

    let planned = ledger.entries.len() as u64;
    let processed = ledger
        .entries
        .values()
        .filter(|entry| matches!(entry.state, UidState::Committed { .. }))
        .count() as u64;
    let filtered = ledger
        .entries
        .values()
        .filter(|entry| matches!(entry.state, UidState::Filtered { .. }))
        .count() as u64;
    let vanished = ledger
        .entries
        .values()
        .filter(|entry| matches!(entry.state, UidState::Vanished))
        .count() as u64;
    let resolved = ledger
        .entries
        .values()
        .filter(|entry| entry.state.reconciled())
        .count() as u64;
    let success = ledger.inventory_complete && resolved == planned;
    refresh_inventory_manifest(&mut ledger);
    if success {
        ledger.checkpoint = Some(snapshot_end);
    } else {
        ledger.checkpoint = None;
    }
    archive.persist_metadata(&ledger)?;
    archive.reclaim_committed_staging(&ledger)?;
    #[cfg(test)]
    let state_bytes_written = archive.state_bytes_written.load(Ordering::Relaxed);
    Ok(AcquisitionReport {
        uid_validity: ledger.uid_validity,
        planned,
        processed,
        filtered,
        vanished,
        resolved,
        checkpoint: ledger.checkpoint,
        success,
        vanished_ranges: ledger.vanished_ranges,
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
    session: Option<UidOnlySession<Box<dyn SessionStream>>>,
    message_limit: Option<NonZeroU32>,
    adapter_limits: AdapterLimits,
    command_limits: CommandLimits,
    body_chunk_size: NonZeroU32,
    max_literal_bytes: u64,
    remaining_transfer_bytes: u64,
    expected_identity: Option<AcquisitionConnectionIdentity>,
    pending_vanished: Vec<RangeInclusive<u32>>,
}

struct SessionTransportConfig {
    account_id: u64,
    message_limit: Option<NonZeroU32>,
    adapter_limits: AdapterLimits,
    command_limits: CommandLimits,
    body_chunk_size: NonZeroU32,
    max_literal_bytes: u64,
    max_total_bytes: u64,
    expected_identity: Option<AcquisitionConnectionIdentity>,
}

impl SessionUidOnlyTransport {
    fn new(
        session: UidOnlySession<Box<dyn SessionStream>>,
        config: SessionTransportConfig,
    ) -> Self {
        Self {
            account_id: config.account_id,
            session: Some(session),
            message_limit: config.message_limit,
            adapter_limits: config.adapter_limits,
            command_limits: config.command_limits,
            body_chunk_size: config.body_chunk_size,
            max_literal_bytes: config.max_literal_bytes,
            remaining_transfer_bytes: config.max_total_bytes,
            expected_identity: config.expected_identity,
            pending_vanished: Vec::new(),
        }
    }

    fn take_session(&mut self) -> Result<UidOnlySession<Box<dyn SessionStream>>, TransportFailure> {
        self.session
            .take()
            .ok_or_else(|| TransportFailure::command("UIDONLY session is unavailable"))
    }

    fn record_notifications(&mut self, notifications: &[Notification]) {
        for notification in notifications {
            if let Notification::Vanished { uids, .. } = notification {
                self.pending_vanished.extend(uids.iter().cloned());
            }
        }
    }

    async fn logout(&mut self) {
        if let Some(session) = self.session.take() {
            session.logout().await.ok();
        }
    }
}

fn classify_transport(error: std::io::Error) -> TransportFailure {
    let network = matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected
    );
    TransportFailure {
        message: format!("{error:#?}"),
        network,
    }
}

impl UidOnlyTransport for SessionUidOnlyTransport {
    async fn snapshot(&mut self, mailbox: &str) -> Result<Snapshot, TransportFailure> {
        let session = self.take_session()?;
        let (session, selected) = session.examine(mailbox).await.map_err(classify_transport)?;
        self.record_notifications(&selected.notifications);
        self.session = Some(session);
        Ok(Snapshot {
            uid_validity: selected.uid_validity.get(),
            uid_next: selected.uid_next.get(),
        })
    }

    async fn inventory_page(
        &mut self,
        first_uid: u32,
        snapshot_end: u32,
        page_size: u32,
    ) -> Result<InventoryPage, TransportFailure> {
        let start = NonZeroU32::new(first_uid)
            .ok_or_else(|| TransportFailure::command("inventory start UID must be nonzero"))?;
        let end = NonZeroU32::new(snapshot_end)
            .ok_or_else(|| TransportFailure::command("inventory end UID must be nonzero"))?;
        let configured = NonZeroU32::new(page_size)
            .ok_or_else(|| TransportFailure::command("inventory page size must be nonzero"))?;
        let page_size = self
            .message_limit
            .map(|limit| configured.min(limit))
            .unwrap_or(configured);
        let request = InventoryRequest::new(start, end, page_size).map_err(classify_transport)?;
        let session = self.take_session()?;
        let (session, page) = session
            .inventory(request)
            .await
            .map_err(classify_transport)?;
        self.session = Some(session);
        let vanished = page
            .notifications
            .iter()
            .filter_map(|notification| match notification {
                Notification::Vanished { uids, .. } => Some(uids.iter().cloned()),
                _ => None,
            })
            .flatten()
            .collect();
        let items = page
            .items
            .into_iter()
            .map(|item| {
                let internal_date =
                    chrono::DateTime::parse_from_str(&item.internal_date, "%d-%b-%Y %H:%M:%S %z")
                        .map_err(|error| {
                            TransportFailure::command(format!(
                                "UID {} returned malformed INTERNALDATE {:?}: {error}",
                                item.uid, item.internal_date
                            ))
                        })?
                        .timestamp_millis();
                Ok(InventoryItem {
                    uid: item.uid.get(),
                    size: Some(u64::from(item.rfc822_size)),
                    internal_date: Some(internal_date),
                })
            })
            .collect::<Result<Vec<_>, TransportFailure>>()?;
        Ok(InventoryPage { items, vanished })
    }

    async fn fetch_uid(&mut self, uid: u32) -> Result<FetchOutcome, TransportFailure> {
        let uid = NonZeroU32::new(uid)
            .ok_or_else(|| TransportFailure::command("body UID must be nonzero"))?;
        let mut offset = 0u32;
        let mut expected_size = None;
        let mut raw = Vec::new();
        loop {
            let requested_bytes = self
                .remaining_transfer_bytes
                .min(u64::from(self.body_chunk_size.get()))
                .min(u64::from(u32::MAX));
            let requested_bytes = NonZeroU32::new(requested_bytes as u32).ok_or_else(|| {
                TransportFailure::command("UIDONLY total transfer byte ceiling exhausted")
            })?;
            let session = self.take_session()?;
            let literal_meter = session.literal_byte_meter();
            let literal_bytes_before = literal_meter.literal_bytes_received();
            let result = session.fetch_body_chunk(uid, offset, requested_bytes).await;
            let received_literal_bytes = literal_meter
                .literal_bytes_received()
                .checked_sub(literal_bytes_before)
                .ok_or_else(|| TransportFailure::command("literal byte counter moved backwards"))?;
            if received_literal_bytes > self.remaining_transfer_bytes {
                self.remaining_transfer_bytes = 0;
                return Err(TransportFailure::command(
                    "UIDONLY total transfer byte ceiling exceeded while receiving a body literal",
                ));
            }
            self.remaining_transfer_bytes -= received_literal_bytes;
            let (session, outcome) = result.map_err(classify_transport)?;
            self.session = Some(session);
            match outcome {
                ExactFetchOutcome::Chunk(chunk) => {
                    self.record_notifications(&chunk.notifications);
                    if expected_size
                        .replace(chunk.rfc822_size)
                        .is_some_and(|size| size != chunk.rfc822_size)
                    {
                        return Err(TransportFailure::command(format!(
                            "UID {} changed RFC822.SIZE during exact body fetch",
                            uid
                        )));
                    }
                    if u64::from(chunk.rfc822_size) > self.max_literal_bytes {
                        return Err(TransportFailure::command(format!(
                            "UID {} declared size {} exceeds configured literal ceiling {}",
                            uid, chunk.rfc822_size, self.max_literal_bytes
                        )));
                    }
                    raw.try_reserve(chunk.bytes.len()).map_err(|_| {
                        TransportFailure::command("body allocation exceeded process limits")
                    })?;
                    raw.extend_from_slice(&chunk.bytes);
                    offset = offset
                        .checked_add(chunk.bytes.len() as u32)
                        .ok_or_else(|| TransportFailure::command("body offset overflow"))?;
                    if offset == chunk.rfc822_size {
                        return Ok(FetchOutcome::Message {
                            declared_size: Some(u64::from(chunk.rfc822_size)),
                            raw,
                        });
                    }
                    if offset > chunk.rfc822_size || chunk.bytes.is_empty() {
                        return Err(TransportFailure::command(
                            "exact body fetch made invalid progress",
                        ));
                    }
                }
                ExactFetchOutcome::Vanished { notifications, .. } => {
                    self.record_notifications(&notifications);
                    return Ok(FetchOutcome::Vanished);
                }
                ExactFetchOutcome::Missing { notifications, .. } => {
                    self.record_notifications(&notifications);
                    return Ok(FetchOutcome::Missing);
                }
            }
        }
    }

    async fn reconnect(&mut self) -> Result<(), TransportFailure> {
        match ImapConnectionManager::build_acquisition_at_endpoint(
            self.account_id,
            self.expected_identity.as_ref(),
            self.adapter_limits.clone(),
            self.command_limits.clone(),
        )
        .await
        .map_err(|e| TransportFailure {
            message: e.to_string(),
            network: e.code() == ErrorCode::NetworkError,
        })? {
            AcquisitionConnection::UidOnly {
                session,
                message_limit,
            } => {
                self.session = Some(*session);
                self.message_limit = message_limit;
                Ok(())
            }
            AcquisitionConnection::Standard(_) => Err(TransportFailure::command(
                "server stopped advertising UIDONLY after reconnect",
            )),
        }
    }

    fn take_vanished(&mut self) -> Vec<RangeInclusive<u32>> {
        std::mem::take(&mut self.pending_vanished)
    }
}

pub(crate) async fn acquire_bichon_mailbox(
    account: &AccountModel,
    mailbox: &MailBox,
    session: UidOnlySession<Box<dyn SessionStream>>,
    message_limit: Option<NonZeroU32>,
    root: &Path,
    limits: AcquisitionLimits,
    token: CancellationToken,
) -> BichonResult<AcquisitionReport> {
    let identity = AcquisitionIdentity::from_account(account, mailbox)?;
    let adapter_limits = limits.adapter_limits()?;
    let command_limits = limits.command_limits()?;
    let body_chunk_size = limits.body_chunk_size()?;
    let mut transport = SessionUidOnlyTransport::new(
        session,
        SessionTransportConfig {
            account_id: account.id,
            message_limit,
            adapter_limits,
            command_limits,
            body_chunk_size,
            max_literal_bytes: limits.max_literal_bytes,
            max_total_bytes: limits.max_total_bytes,
            expected_identity: Some(acquisition_connection_identity(account)?),
        },
    );
    let mut canonical = BichonCanonicalArchive::new(account.id, mailbox.id);
    let result = run_acquisition(
        &mut transport,
        &mut canonical,
        &mailbox.encoded_name(),
        identity,
        root,
        limits,
        token,
    )
    .await;
    transport.logout().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::entity::{AuthConfig, Encryption, ImapConfig};
    use crate::account::migration::AccountType;
    use crate::database::{insert_impl, manager::DB_MANAGER};
    use crate::envelope::extractor::fail_uidonly_after_attachments;
    use crate::imap::mock_server::{examine_response, MockImapServer};
    use crate::message::search::{EmailSearchFilter, SortBy};
    use crate::message::tags::{TagAction, TagsRequest};
    use crate::store::blob::{uidonly_exact_raw_blob_key, BLOB_MANAGER};
    use crate::store::tantivy::dedup::dedup_task;
    use futures::TryStreamExt;
    use mail_parser::MessageParser;
    use std::cell::Cell;
    use std::collections::{HashSet, VecDeque};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
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

    #[derive(Debug)]
    struct RecordingTestStream {
        stream: TcpStream,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for RecordingTestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for RecordingTestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            match Pin::new(&mut self.stream).poll_write(cx, buf) {
                Poll::Ready(Ok(written)) => {
                    self.written
                        .lock()
                        .unwrap()
                        .extend_from_slice(&buf[..written]);
                    Poll::Ready(Ok(written))
                }
                result => result,
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    impl SessionStream for RecordingTestStream {}

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

    struct InterruptedInventoryTransport {
        calls: usize,
    }

    impl UidOnlyTransport for InterruptedInventoryTransport {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            Ok(Snapshot {
                uid_validity: 9,
                uid_next: 51,
            })
        }

        async fn inventory_page(
            &mut self,
            _first_uid: u32,
            _snapshot_end: u32,
            _page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            self.calls += 1;
            if self.calls == 1 {
                Ok(InventoryPage {
                    items: vec![item(2, 4), item(30, 4)],
                    vanished: Vec::new(),
                })
            } else {
                Err(TransportFailure::command(
                    "synthetic interruption after durable inventory page",
                ))
            }
        }

        async fn fetch_uid(&mut self, _uid: u32) -> Result<FetchOutcome, TransportFailure> {
            unreachable!("inventory interruption happens before body fetch")
        }

        async fn reconnect(&mut self) -> Result<(), TransportFailure> {
            unreachable!()
        }
    }

    struct BoundaryDisconnectTransport {
        disconnect_snapshot_once: bool,
        disconnect_inventory_once: bool,
        changed_uid_validity_after_reconnect: bool,
        snapshot_calls: usize,
        inventory_calls: usize,
        reconnects: usize,
    }

    impl UidOnlyTransport for BoundaryDisconnectTransport {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            self.snapshot_calls += 1;
            if std::mem::take(&mut self.disconnect_snapshot_once) {
                return Err(TransportFailure {
                    message: "synthetic snapshot disconnect".into(),
                    network: true,
                });
            }
            Ok(Snapshot {
                uid_validity: if self.changed_uid_validity_after_reconnect && self.reconnects > 0 {
                    10
                } else {
                    9
                },
                uid_next: 8,
            })
        }

        async fn inventory_page(
            &mut self,
            _first_uid: u32,
            _snapshot_end: u32,
            _page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            self.inventory_calls += 1;
            if std::mem::take(&mut self.disconnect_inventory_once) {
                return Err(TransportFailure {
                    message: "synthetic inventory disconnect".into(),
                    network: true,
                });
            }
            Ok(InventoryPage {
                items: vec![item(7, 4)],
                vanished: Vec::new(),
            })
        }

        async fn fetch_uid(&mut self, _uid: u32) -> Result<FetchOutcome, TransportFailure> {
            message(b"mail")
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

    struct OverfullInventoryTransport;

    impl UidOnlyTransport for OverfullInventoryTransport {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            Ok(Snapshot {
                uid_validity: 9,
                uid_next: 4,
            })
        }

        async fn inventory_page(
            &mut self,
            _first_uid: u32,
            _snapshot_end: u32,
            _page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            Ok(InventoryPage {
                items: vec![item(1, 1), item(2, 1), item(3, 1)],
                vanished: Vec::new(),
            })
        }

        async fn fetch_uid(&mut self, _uid: u32) -> Result<FetchOutcome, TransportFailure> {
            panic!("overfull inventory must be rejected before body fetch")
        }

        async fn reconnect(&mut self) -> Result<(), TransportFailure> {
            Ok(())
        }
    }

    struct CrossPageVanishedContradiction {
        calls: usize,
    }

    impl UidOnlyTransport for CrossPageVanishedContradiction {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            Ok(Snapshot {
                uid_validity: 9,
                uid_next: 51,
            })
        }

        async fn inventory_page(
            &mut self,
            _first_uid: u32,
            _snapshot_end: u32,
            _page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            self.calls += 1;
            Ok(if self.calls == 1 {
                InventoryPage {
                    items: vec![item(2, 1)],
                    vanished: vec![50..=50],
                }
            } else {
                InventoryPage {
                    items: vec![item(50, 1)],
                    vanished: Vec::new(),
                }
            })
        }

        async fn fetch_uid(&mut self, _uid: u32) -> Result<FetchOutcome, TransportFailure> {
            panic!("contradictory inventory must fail before body fetch")
        }

        async fn reconnect(&mut self) -> Result<(), TransportFailure> {
            Ok(())
        }
    }

    struct ReconnectExamineVanishedTransport {
        snapshot_calls: usize,
        fetch_calls: usize,
        vanished_pending: bool,
    }

    struct DisappearsWithoutVanishedTransport {
        inventory_calls: usize,
    }

    impl UidOnlyTransport for DisappearsWithoutVanishedTransport {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            Ok(Snapshot {
                uid_validity: 9,
                uid_next: 8,
            })
        }

        async fn inventory_page(
            &mut self,
            _first_uid: u32,
            _snapshot_end: u32,
            _page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            self.inventory_calls += 1;
            Ok(if self.inventory_calls == 1 {
                InventoryPage {
                    items: vec![item(7, 4)],
                    vanished: Vec::new(),
                }
            } else {
                InventoryPage {
                    items: Vec::new(),
                    vanished: Vec::new(),
                }
            })
        }

        async fn fetch_uid(&mut self, _uid: u32) -> Result<FetchOutcome, TransportFailure> {
            Ok(FetchOutcome::Missing)
        }

        async fn reconnect(&mut self) -> Result<(), TransportFailure> {
            Ok(())
        }
    }

    impl UidOnlyTransport for ReconnectExamineVanishedTransport {
        async fn snapshot(&mut self, _mailbox: &str) -> Result<Snapshot, TransportFailure> {
            self.snapshot_calls += 1;
            if self.snapshot_calls > 1 {
                self.vanished_pending = true;
            }
            Ok(Snapshot {
                uid_validity: 9,
                uid_next: 8,
            })
        }

        async fn inventory_page(
            &mut self,
            _first_uid: u32,
            _snapshot_end: u32,
            _page_size: u32,
        ) -> Result<InventoryPage, TransportFailure> {
            Ok(InventoryPage {
                items: vec![item(7, 4)],
                vanished: Vec::new(),
            })
        }

        async fn fetch_uid(&mut self, _uid: u32) -> Result<FetchOutcome, TransportFailure> {
            self.fetch_calls += 1;
            if self.fetch_calls == 1 {
                Err(TransportFailure {
                    message: "synthetic disconnect".into(),
                    network: true,
                })
            } else {
                message(b"mail")
            }
        }

        async fn reconnect(&mut self) -> Result<(), TransportFailure> {
            Ok(())
        }

        fn take_vanished(&mut self) -> Vec<RangeInclusive<u32>> {
            if std::mem::take(&mut self.vanished_pending) {
                vec![7..=7]
            } else {
                Vec::new()
            }
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
        filtered_uids: BTreeSet<u32>,
        hang_projection: BTreeSet<u32>,
        disk_budget_override: Option<u64>,
        projected_uids: Vec<u32>,
        projected_internal_dates: BTreeMap<u32, i64>,
        fail_verify_on_call: Option<usize>,
        verify_calls: Cell<usize>,
        active_projects: usize,
        quiesced_projects: Vec<u32>,
        rollback_raw_hashes: Vec<(u32, String)>,
    }

    impl CanonicalArchive for FakeCanonicalArchive {
        fn begin_epoch(&mut self, _uid_validity: u32) -> BichonResult<()> {
            Ok(())
        }

        fn envelope_id(&self, uid: u32, _content_hash: &str) -> BichonResult<String> {
            Ok(format!("envelope-{uid}"))
        }

        fn disk_budget(&self, raw: &[u8]) -> BichonResult<u64> {
            Ok(self.disk_budget_override.unwrap_or(raw.len() as u64 + 128))
        }

        fn memory_budget(&self, raw: &[u8]) -> BichonResult<u64> {
            Ok(raw.len() as u64 + 128)
        }

        async fn project(
            &mut self,
            uid: u32,
            raw: Vec<u8>,
            _declared_size: Option<u64>,
            internal_date: i64,
            shutdown: CancellationToken,
        ) -> BichonResult<Option<CanonicalProjection>> {
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
            if self.filtered_uids.contains(&uid) {
                return Ok(None);
            }
            self.projected_uids.push(uid);
            self.projected_internal_dates.insert(uid, internal_date);
            let projection = CanonicalProjection {
                envelope_id: format!("envelope-{uid}"),
                content_hash: compute_content_hash(&raw),
                created: true,
            };
            self.records.insert(uid, projection.clone());
            Ok(Some(projection))
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
            raw: Option<&[u8]>,
        ) -> BichonResult<()> {
            if let Some(raw) = raw {
                self.rollback_raw_hashes
                    .push((uid, compute_content_hash(raw)));
            }
            self.corrupt_blobs.remove(&uid);
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
            max_state_bytes: 64 * 1024 * 1024,
            max_memory_bytes: 128 * 1024 * 1024,
            page_size: 2,
        }
    }

    #[test]
    fn durable_read_rejects_a_file_larger_than_its_allocation_ceiling() {
        let root = temp_root("bounded-durable-read");
        let path = root.join("oversized");
        fs::write(&path, b"12345").unwrap();
        let error = read_bounded_file(&path, 4).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PayloadTooLarge);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn valid_json_metadata_corruption_fails_checksum_validation() {
        let root = temp_root("metadata-checksum");
        let identity = identity();
        let archive = DurableArchive::open(&root, &identity, 9, limits()).unwrap();
        archive.load_or_create(identity.clone(), 9, 50).unwrap();
        let mut file: LedgerMetadataFile = serde_json::from_slice(
            &read_bounded_file(&archive.ledger_path, MAX_LEDGER_METADATA_BYTES).unwrap(),
        )
        .unwrap();
        file.metadata.inventory_complete = true;
        file.metadata.inventory_cursor = None;
        atomic_write(&archive.ledger_path, &serde_json::to_vec(&file).unwrap()).unwrap();
        drop(archive);

        let restarted = DurableArchive::open(&root, &identity, 9, limits()).unwrap();
        let error = restarted.load_or_create(identity, 9, 50).unwrap_err();
        assert!(error.to_string().contains("metadata checksum mismatch"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rolling_inventory_manifest_scales_linearly_to_large_sparse_prefix() {
        let mut ledger = AcquisitionLedger {
            identity: identity(),
            uid_validity: 9,
            snapshot_start: 1,
            snapshot_end: 1_000_000,
            inventory_cursor: Some(1),
            inventory_complete: false,
            inventory_count: 0,
            inventory_digest: None,
            checkpoint: None,
            vanished_ranges: Vec::new(),
            entries: BTreeMap::new(),
        };
        refresh_inventory_manifest(&mut ledger);
        for uid in 1..=100_000u32 {
            ledger.entries.insert(
                uid,
                UidEntry {
                    declared_size: Some(1),
                    internal_date: Some(1_704_067_200_000),
                    state: UidState::Missing,
                },
            );
            append_inventory_manifest(&mut ledger, uid);
        }
        assert_eq!(ledger.inventory_count, 100_000);
        assert_eq!(ledger.inventory_digest, Some(inventory_digest(&ledger)));
    }

    #[test]
    fn million_uid_diff_stays_sparse_and_exact() {
        let remote: Vec<_> = (1..=1_000_000)
            .map(|uid| NonZeroU32::new(uid).unwrap())
            .collect();
        let local: Vec<_> = (2..=1_000_000)
            .step_by(2)
            .map(|uid| NonZeroU32::new(uid).unwrap())
            .collect();
        let missing = missing_verified_uids(&remote, &local).unwrap();
        assert_eq!(missing.len(), 500_000);
        assert_eq!(missing.first().unwrap().get(), 1);
        assert_eq!(missing.last().unwrap().get(), 999_999);
    }

    #[test]
    fn large_alternating_vanished_history_appends_and_looks_up_exactly() {
        let mut ranges = Vec::new();
        for uid in (1..=200_000u32).step_by(2) {
            assert!(record_vanished_ranges(&mut ranges, [uid..=uid], 1, 200_000,));
        }
        assert_eq!(ranges.len(), 100_000);
        let ledger = AcquisitionLedger {
            identity: identity(),
            uid_validity: 9,
            snapshot_start: 1,
            snapshot_end: 200_000,
            inventory_cursor: None,
            inventory_complete: true,
            inventory_count: 0,
            inventory_digest: None,
            checkpoint: None,
            vanished_ranges: ranges,
            entries: BTreeMap::new(),
        };
        for uid in 1..=200_000u32 {
            assert_eq!(has_vanished_evidence(&ledger, uid), uid % 2 == 1);
        }
    }

    #[test]
    fn orphan_atomic_temps_are_discarded_without_blocking_restart() {
        let root = temp_root("orphan-atomic-temp");
        let identity = identity();
        let archive = DurableArchive::open(&root, &identity, 9, limits()).unwrap();
        let ledger = archive.load_or_create(identity.clone(), 9, 7).unwrap();
        let id = uuid::Uuid::new_v4();
        let entry_temp = archive.ledger_entries_dir.join(format!(".7.json.{id}.tmp"));
        let record_temp = archive
            .epoch_dir
            .join("records")
            .join(format!(".7.json.{}.tmp", uuid::Uuid::new_v4()));
        fs::write(&entry_temp, b"partial").unwrap();
        fs::write(&record_temp, b"partial").unwrap();
        drop(archive);

        let restarted = DurableArchive::open(&root, &identity, 9, limits()).unwrap();
        let restarted_ledger = restarted.load_or_create(identity, 9, 7).unwrap();
        assert!(!entry_temp.exists());
        restarted
            .reclaim_committed_staging(&restarted_ledger)
            .unwrap();
        assert!(!record_temp.exists());
        assert!(ledger.entries.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ledger_entry_count_is_bounded_before_deserialization_growth() {
        let root = temp_root("ledger-count-bound");
        let identity = identity();
        let mut bounded = limits();
        bounded.max_messages = 1;
        let archive = DurableArchive::open(&root, &identity, 9, bounded).unwrap();
        archive.load_or_create(identity.clone(), 9, 2).unwrap();
        let entry_value = UidEntry {
            declared_size: Some(4),
            internal_date: None,
            state: UidState::Missing,
        };
        for uid in [1, 2] {
            let entry = serde_json::to_vec(&LedgerEntryFile {
                checksum: ledger_entry_checksum(uid, &entry_value),
                entry: entry_value.clone(),
            })
            .unwrap();
            atomic_write(
                &archive.ledger_entries_dir.join(format!("{uid}.json")),
                &entry,
            )
            .unwrap();
        }
        drop(archive);

        let restarted = DurableArchive::open(&root, &identity, 9, bounded).unwrap();
        let error = restarted.load_or_create(identity, 9, 2).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PayloadTooLarge);
        assert!(error.to_string().contains("entry ceiling"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_shard_record_is_never_reused_for_uidonly_projection() {
        let error = BichonCanonicalArchive::reuse_projection(
            7,
            "expected-hash",
            crate::store::tantivy::envelope::CanonicalProjectionRecord {
                envelope_id: "legacy-envelope".into(),
                uid: 7,
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

    #[test]
    fn canonical_identity_is_scoped_to_uidvalidity_epoch() {
        let first = BichonCanonicalArchive::envelope_id_for(7, 11, 9, 42, "same-hash");
        let second = BichonCanonicalArchive::envelope_id_for(7, 11, 10, 42, "same-hash");
        assert_ne!(first, second);
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
            internal_date: Some(1_704_067_200_000),
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
        let archive7 = identity_for(7, "Archive");
        let inbox8 = identity_for(8, "INBOX");
        for identity in [&inbox7, &sent7, &archive7, &inbox8] {
            DurableArchive::open(&root, identity, 9, limits())
                .unwrap()
                .load_or_create(identity.clone(), 9, 1)
                .unwrap();
        }

        // Marker-routed cleanup must not parse even the target ledger, and an
        // unrelated corrupt pre-marker directory must not block deletion.
        fs::write(
            root.join(inbox7.storage_key()).join("9/ledger.json"),
            b"corrupt target metadata",
        )
        .unwrap();
        let sent_dir = root.join(sent7.storage_key());
        fs::remove_file(sent_dir.join(sent7.mailbox_marker())).unwrap();
        fs::write(sent_dir.join("9/ledger.json"), b"corrupt account target").unwrap();
        for identity in [&archive7, &inbox8] {
            let dir = root.join(identity.storage_key());
            fs::remove_file(dir.join(identity.account_marker())).unwrap();
            fs::remove_file(dir.join(identity.mailbox_marker())).unwrap();
        }
        fs::write(
            root.join(inbox8.storage_key()).join("9/ledger.json"),
            b"corrupt unrelated legacy metadata",
        )
        .unwrap();

        assert_eq!(
            cleanup_uidonly_mailbox_state(&root, 7, &BTreeSet::from(["INBOX".to_string()]))
                .unwrap(),
            1
        );
        assert!(!root.join(inbox7.storage_key()).exists());
        assert!(root.join(sent7.storage_key()).exists());
        assert!(root.join(archive7.storage_key()).exists());
        assert!(root.join(inbox8.storage_key()).exists());

        assert_eq!(cleanup_uidonly_account_state(&root, 7).unwrap(), 2);
        assert!(!root.join(sent7.storage_key()).exists());
        assert!(!root.join(archive7.storage_key()).exists());
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
    async fn restart_resumes_from_the_durable_inventory_cursor() {
        let root = temp_root("inventory-cursor-restart");
        let mut interrupted = InterruptedInventoryTransport { calls: 0 };
        let error = run_acquisition(
            &mut interrupted,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("synthetic interruption"));

        let mut restart = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 51,
            },
            inventory: vec![item(2, 4), item(30, 4), item(50, 4)],
            outcomes: [
                (2, VecDeque::from([message(b"mail")])),
                (30, VecDeque::from([message(b"mail")])),
                (50, VecDeque::from([message(b"mail")])),
            ]
            .into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut restart,
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
        assert_eq!(restart.page_requests.first(), Some(&(31, 50, 2)));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn missing_prefix_entry_invalidates_cursor_and_forces_rescan() {
        let root = temp_root("inventory-cursor-manifest");
        let mut interrupted = InterruptedInventoryTransport { calls: 0 };
        run_acquisition(
            &mut interrupted,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        let entry = root
            .join(identity().storage_key())
            .join("9")
            .join("ledger-entries")
            .join("2.json");
        fs::remove_file(entry).unwrap();

        let mut restart = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 51,
            },
            inventory: vec![item(2, 4), item(30, 4), item(50, 4)],
            outcomes: [
                (2, VecDeque::from([message(b"mail")])),
                (30, VecDeque::from([message(b"mail")])),
                (50, VecDeque::from([message(b"mail")])),
            ]
            .into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut restart,
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
        assert_eq!(restart.page_requests.first(), Some(&(1, 50, 2)));
        assert_eq!(report.planned, 3);
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
                    internal_date: Some(1_704_067_200_000),
                },
                InventoryItem {
                    uid: 2,
                    size: Some(999),
                    internal_date: Some(1_704_067_200_000),
                },
                InventoryItem {
                    uid: 3,
                    size: None,
                    internal_date: None,
                },
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
        assert_eq!(
            canonical.projected_internal_dates,
            BTreeMap::from([(1, 1_704_067_200_000), (2, 1_704_067_200_000), (3, 0),])
        );
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
    async fn archive_rule_filter_is_an_explicit_checkpointable_outcome() {
        let root = temp_root("archive-rule-filter");
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
            filtered_uids: BTreeSet::from([7]),
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
        assert!(report.success);
        assert_eq!(report.checkpoint, Some(7));
        assert!(matches!(report.states[&7], UidState::Filtered { .. }));
        assert!(canonical.records.is_empty());
        let epoch = root.join(identity().storage_key()).join("9");
        assert_eq!(fs::read_dir(epoch.join("blobs")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(epoch.join("records")).unwrap().count(), 0);
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
        let persisted: LedgerEntryFile =
            serde_json::from_slice(&fs::read(entry_path).unwrap()).unwrap();
        assert!(matches!(persisted.entry.state, UidState::Projecting { .. }));

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
        assert!(
            canonical
                .rollback_raw_hashes
                .contains(&(1, compute_content_hash(b"mail"))),
            "restart rollback must recover attachment cleanup evidence from staged raw bytes"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn restart_commits_a_verified_projection_interrupted_before_ledger_ack() {
        let root = temp_root("verified-projecting-restart");
        let identity = identity();
        let archive = DurableArchive::open(&root, &identity, 9, limits()).unwrap();
        let mut ledger = archive.load_or_create(identity.clone(), 9, 7).unwrap();
        let raw = b"mail";
        let blob_hash = compute_content_hash(raw);
        archive.commit_raw(&ledger, 7, raw).unwrap();
        ledger.entries.insert(
            7,
            UidEntry {
                declared_size: Some(raw.len() as u64),
                internal_date: Some(1_704_067_200_000),
                state: UidState::Projecting {
                    blob_hash: blob_hash.clone(),
                    bytes: raw.len() as u64,
                    canonical_bytes: 128,
                    envelope_id: Some("envelope-7".into()),
                    owned: Some(true),
                },
            },
        );
        archive.persist_entry(7, &ledger.entries[&7]).unwrap();
        seal_inventory(&mut ledger);
        archive.persist_metadata(&ledger).unwrap();
        drop(archive);

        let projection = CanonicalProjection {
            envelope_id: "envelope-7".into(),
            content_hash: blob_hash,
            created: true,
        };
        let mut canonical = FakeCanonicalArchive::default();
        canonical.records.insert(7, projection);
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 8,
            },
            inventory: vec![item(7, raw.len() as u64)],
            outcomes: BTreeMap::new(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut transport,
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
        assert!(matches!(report.states[&7], UidState::Committed { .. }));
        assert!(
            transport.outcomes.is_empty(),
            "verified projection is not refetched"
        );
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
        canonical.begin_epoch(9).unwrap();
        let parsed = MessageParser::new().parse(raw).unwrap();
        let (_, legacy_detached) = prepare_detached_attachments(
            raw,
            &parsed,
            &compute_content_hash(raw),
            account_id,
            mailbox_id,
            None,
        )
        .await
        .unwrap();
        BLOB_MANAGER.store_durable(legacy_detached).await.unwrap();
        assert!(BLOB_MANAGER
            .get_email(&compute_content_hash(raw))
            .unwrap()
            .is_some());
        assert!(BLOB_MANAGER
            .get_email(&uidonly_exact_raw_blob_key(&compute_content_hash(raw)))
            .unwrap()
            .is_none());
        let first = canonical
            .project(
                first_uid,
                raw.to_vec(),
                None,
                1_704_067_200_000,
                CancellationToken::new(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(BLOB_MANAGER
            .get_email(&uidonly_exact_raw_blob_key(&compute_content_hash(raw)))
            .unwrap()
            .is_some());
        let second = canonical
            .project(
                second_uid,
                raw.to_vec(),
                None,
                1_704_067_200_000,
                CancellationToken::new(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_ne!(first.envelope_id, second.envelope_id);
        let attachment = parsed.attachments().next().unwrap();
        let raw_attachment_hash = uidonly_attachment_blob_key(&compute_content_hash(
            &raw[attachment.raw_body_offset() as usize..attachment.raw_end_offset() as usize],
        ));
        ENVELOPE_MANAGER
            .update_envelope_tags(TagsRequest {
                updates: [(account_id, vec![first.envelope_id.clone()])].into(),
                tags: vec!["/uidonly-regression".into()],
                action: TagAction::Add,
            })
            .await
            .unwrap();
        let searchable_after_tag_update = ENVELOPE_MANAGER
            .search(
                Some(HashSet::from([account_id])),
                EmailSearchFilter {
                    body: Some("exact body bytes".into()),
                    ..Default::default()
                },
                1,
                10,
                false,
                SortBy::DATE,
            )
            .unwrap();
        assert!(searchable_after_tag_update
            .items
            .iter()
            .any(|envelope| envelope.id == first.envelope_id));

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
                    content_hash: raw_attachment_hash.clone(),
                    name: Some("fixture.bin".into()),
                    size: 4,
                    content_type: "application/octet-stream".into(),
                }]
            );

            let (envelope, restored) =
                reattach_eml_content(account_id, projection.envelope_id.clone()).unwrap();
            assert_eq!(envelope.uid, uid);
            assert_eq!(envelope.internal_date, 1_704_067_200_000);
            assert_eq!(restored.as_ref(), raw);
            assert!(canonical
                .verify(uid, &projection.content_hash, &projection.envelope_id)
                .await
                .unwrap());
        }

        canonical.begin_epoch(10).unwrap();
        let next_epoch = canonical
            .project(
                first_uid,
                raw.to_vec(),
                None,
                1_704_067_200_000,
                CancellationToken::new(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_ne!(first.envelope_id, next_epoch.envelope_id);
        let next_epoch_record = ENVELOPE_MANAGER
            .get_projection_by_envelope_id(account_id, &next_epoch.envelope_id)
            .unwrap()
            .expect("UID reuse in a new UIDVALIDITY epoch must create a distinct record");
        assert_eq!(next_epoch_record.uid, first_uid);
        assert!(canonical
            .verify(first_uid, &next_epoch.content_hash, &next_epoch.envelope_id)
            .await
            .unwrap());

        let malformed_uid = 80;
        let malformed = canonical
            .project(
                malformed_uid,
                Vec::new(),
                Some(0),
                1_704_067_200_000,
                CancellationToken::new(),
            )
            .await
            .unwrap()
            .expect("even an empty stored RFC822 literal must receive a fallback envelope");
        assert!(canonical
            .verify(
                malformed_uid,
                &malformed.content_hash,
                &malformed.envelope_id,
            )
            .await
            .unwrap());
        let (_, restored_malformed) =
            reattach_eml_content(account_id, malformed.envelope_id.clone()).unwrap();
        assert!(restored_malformed.is_empty());

        let orphan_uid = 81;
        let orphan_raw = b"From: orphan@example.invalid\r\n\
To: archive@example.invalid\r\n\
Subject: failed projection cleanup\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=orphan-boundary\r\n\
\r\n\
--orphan-boundary\r\n\
Content-Type: text/plain\r\n\
\r\n\
orphan body\r\n\
--orphan-boundary\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=orphan.bin\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
ZmFpbGVk\r\n\
--orphan-boundary--\r\n";
        let orphan_hash = compute_content_hash(orphan_raw);
        let orphan_message = MessageParser::new().parse(orphan_raw).unwrap();
        let orphan_attachment = orphan_message.attachments().next().unwrap();
        let orphan_attachment_hash = uidonly_attachment_blob_key(&compute_content_hash(
            &orphan_raw[orphan_attachment.raw_body_offset() as usize
                ..orphan_attachment.raw_end_offset() as usize],
        ));
        fail_uidonly_after_attachments(true);
        let orphan_failure = canonical
            .project(
                orphan_uid,
                orphan_raw.to_vec(),
                None,
                1_704_067_200_000,
                CancellationToken::new(),
            )
            .await;
        fail_uidonly_after_attachments(false);
        assert!(orphan_failure.is_err());
        assert!(BLOB_MANAGER
            .get_email(&uidonly_exact_raw_blob_key(&orphan_hash))
            .unwrap()
            .is_none());
        assert!(BLOB_MANAGER
            .get_attachment(&orphan_attachment_hash)
            .unwrap()
            .is_none());

        let failed_uid = 79;
        // The failed writer reuses the exact email and attachment blobs owned
        // by two committed projections. Rollback must remove only its index
        // documents and preserve both shared blob values.
        let failed_raw = raw;
        let failed_hash = compute_content_hash(failed_raw);
        let failed_envelope_id = canonical.envelope_id(failed_uid, &failed_hash);
        fail_uidonly_after_attachments(true);
        let failure = canonical
            .project(
                failed_uid,
                failed_raw.to_vec(),
                None,
                1_704_067_200_000,
                CancellationToken::new(),
            )
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
        assert!(BLOB_MANAGER
            .get_email(&uidonly_exact_raw_blob_key(&failed_hash))
            .unwrap()
            .is_some());
        assert!(BLOB_MANAGER
            .get_attachment(&raw_attachment_hash)
            .unwrap()
            .is_some());
        for projection in [&first, &second] {
            let (_, restored) =
                reattach_eml_content(account_id, projection.envelope_id.clone()).unwrap();
            assert_eq!(restored.as_ref(), raw);
        }

        for (position, projection) in [&first, &second, &next_epoch].into_iter().enumerate() {
            let deletes = std::collections::HashMap::from([(
                account_id,
                vec![projection.envelope_id.clone()],
            )]);
            ENVELOPE_MANAGER
                .delete_envelopes_multi_account(deletes.clone())
                .await
                .unwrap();
            ATTACHMENT_MANAGER
                .delete_attachments_multi_account(deletes)
                .await
                .unwrap();
            let shared_reference_remains = position < 2;
            assert_eq!(
                BLOB_MANAGER
                    .get_email(&uidonly_exact_raw_blob_key(&failed_hash))
                    .unwrap()
                    .is_some(),
                shared_reference_remains,
                "exact raw must survive until the final canonical reference is deleted"
            );
            assert_eq!(
                BLOB_MANAGER
                    .get_attachment(&raw_attachment_hash)
                    .unwrap()
                    .is_some(),
                shared_reference_remains,
                "UIDONLY attachment must survive until the final canonical reference is deleted"
            );
        }
        assert!(BLOB_MANAGER.get_email(&failed_hash).unwrap().is_none());

        let malformed_hash = compute_content_hash(&[]);
        let malformed_deletes =
            std::collections::HashMap::from([(account_id, vec![malformed.envelope_id.clone()])]);
        ENVELOPE_MANAGER
            .delete_envelopes_multi_account(malformed_deletes.clone())
            .await
            .unwrap();
        ATTACHMENT_MANAGER
            .delete_attachments_multi_account(malformed_deletes)
            .await
            .unwrap();
        assert!(BLOB_MANAGER
            .get_email(&uidonly_exact_raw_blob_key(&malformed_hash))
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn committed_record_deletion_is_refetched_on_the_first_restart() {
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
            outcomes: [(7, VecDeque::from([message(b"mail")]))].into(),
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
        assert!(report.success);
        assert_eq!(report.checkpoint, Some(7));
        assert!(matches!(report.states[&7], UidState::Committed { .. }));
        let epoch = root.join(identity().storage_key()).join("9");
        assert_eq!(fs::read_dir(epoch.join("blobs")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(epoch.join("records")).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn committed_blob_corruption_is_refetched_on_the_first_restart() {
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
            outcomes: [(7, VecDeque::from([message(b"mail")]))].into(),
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
        assert!(report.success);
        assert_eq!(report.checkpoint, Some(7));
        assert!(matches!(report.states[&7], UidState::Committed { .. }));
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
                    internal_date: None,
                    state: UidState::Missing,
                },
            );
        }
        for uid in [2, 30, 50] {
            archive.persist_entry(uid, &ledger.entries[&uid]).unwrap();
        }
        ledger.inventory_cursor = Some(51);
        refresh_inventory_manifest(&mut ledger);
        archive.persist_metadata(&ledger).unwrap();
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
        assert_eq!(
            (
                report.planned,
                report.processed,
                report.resolved,
                report.vanished,
            ),
            (3, 0, 3, 3)
        );
        assert!(report
            .states
            .values()
            .all(|state| matches!(state, UidState::Vanished)));
        assert_eq!(
            report.vanished_ranges,
            vec![UidRange {
                start: 1,
                end: u32::MAX - 1,
            }]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unseen_vanished_range_is_durable_compact_evidence() {
        let root = temp_root("unseen-vanished-evidence");
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
        assert_eq!((report.planned, report.processed), (0, 0));
        assert_eq!(
            report.vanished_ranges,
            vec![UidRange {
                start: 1,
                end: u32::MAX - 1,
            }]
        );
        let archive = DurableArchive::open(&root, &identity(), 9, limits()).unwrap();
        let ledger = archive.load_or_create(identity(), 9, u32::MAX - 1).unwrap();
        assert_eq!(ledger.vanished_ranges, report.vanished_ranges);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn server_cannot_overrun_requested_partial_page() {
        let root = temp_root("overfull-partial");
        let error = run_acquisition(
            &mut OverfullInventoryTransport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ImapUnexpectedResult);
        let archive = DurableArchive::open(&root, &identity(), 9, limits()).unwrap();
        let ledger = archive.load_or_create(identity(), 9, 3).unwrap();
        assert_eq!(ledger.checkpoint, None);
        assert!(ledger.entries.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn completed_snapshot_extends_from_prior_checkpoint() {
        let root = temp_root("periodic-window");
        let mut canonical = FakeCanonicalArchive::default();
        let mut first = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 2,
            },
            inventory: vec![item(1, 1)],
            outcomes: [(1, VecDeque::from([message(b"a")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
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

        let mut second = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 3,
            },
            inventory: vec![item(1, 1), item(2, 1)],
            outcomes: [(2, VecDeque::from([message(b"b")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut second,
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
        assert_eq!(report.checkpoint, Some(2));
        assert_eq!(second.page_requests.first(), Some(&(2, 2, 2)));
        assert_eq!(canonical.projected_uids, vec![1, 2]);
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
                "messages" => assert!(result.is_err()),
                "total-bytes" => {
                    let report = result.unwrap();
                    assert!(!report.success);
                    assert_eq!(report.checkpoint, None);
                    assert_eq!(
                        transport.outcomes[&2].len(),
                        1,
                        "declared size must fail before the second body fetch"
                    );
                }
                "disk" => match result {
                    Ok(report) => {
                        assert!(!report.success);
                        assert_eq!(report.checkpoint, None);
                    }
                    Err(error) => assert_eq!(error.code(), ErrorCode::PayloadTooLarge),
                },
                _ => unreachable!(),
            }
            fs::remove_dir_all(root).ok();
        }
    }

    #[tokio::test]
    async fn message_ceiling_rejects_a_page_before_any_entry_is_durable() {
        let root = temp_root("message-page-boundary");
        let mut bounded = limits();
        bounded.max_messages = 1;
        let mut transport = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 3,
            },
            inventory: vec![item(1, 1), item(2, 1)],
            outcomes: BTreeMap::new(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let error = run_acquisition(
            &mut transport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            bounded,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PayloadTooLarge);
        let archive = DurableArchive::open(&root, &identity(), 9, bounded).unwrap();
        assert_eq!(fs::read_dir(archive.ledger_entries_dir).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
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

        let mut raised_limits = small_limits;
        raised_limits.max_literal_bytes = 5;
        raised_limits.max_response_bytes = 1024 * 1024;
        let mut retry = FakeTransport {
            snapshot: Snapshot {
                uid_validity: 9,
                uid_next: 21,
            },
            inventory: vec![item(10, 5), item(20, 2)],
            outcomes: [(10, VecDeque::from([message(b"large")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut retry,
            &mut canonical,
            "INBOX",
            identity(),
            &root,
            raised_limits,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!((report.processed, report.checkpoint), (2, Some(20)));
        assert!(matches!(report.states[&10], UidState::Committed { .. }));
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
    async fn snapshot_disconnect_reconnects_before_inventory() {
        let root = temp_root("snapshot-disconnect");
        let mut transport = BoundaryDisconnectTransport {
            disconnect_snapshot_once: true,
            disconnect_inventory_once: false,
            changed_uid_validity_after_reconnect: false,
            snapshot_calls: 0,
            inventory_calls: 0,
            reconnects: 0,
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
        assert_eq!(transport.snapshot_calls, 2);
        assert_eq!(transport.reconnects, 1);
        assert_eq!(transport.inventory_calls, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn inventory_disconnect_reexamines_same_epoch_and_resumes_page() {
        let root = temp_root("inventory-disconnect");
        let mut transport = BoundaryDisconnectTransport {
            disconnect_snapshot_once: false,
            disconnect_inventory_once: true,
            changed_uid_validity_after_reconnect: false,
            snapshot_calls: 0,
            inventory_calls: 0,
            reconnects: 0,
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
        assert_eq!(transport.snapshot_calls, 2);
        assert_eq!(transport.inventory_calls, 2);
        assert_eq!(transport.reconnects, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn inventory_disconnect_rejects_changed_uidvalidity_before_retry() {
        let root = temp_root("inventory-disconnect-uidvalidity");
        let mut transport = BoundaryDisconnectTransport {
            disconnect_snapshot_once: false,
            disconnect_inventory_once: true,
            changed_uid_validity_after_reconnect: true,
            snapshot_calls: 0,
            inventory_calls: 0,
            reconnects: 0,
        };
        let error = run_acquisition(
            &mut transport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Incompatible);
        assert!(error.to_string().contains("UIDVALIDITY changed"));
        assert_eq!(transport.inventory_calls, 1);
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
            outcomes: [(30, VecDeque::from([Ok(FetchOutcome::Vanished)]))].into(),
            vanished_on_inventory: BTreeSet::new(),
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
    async fn cross_page_item_cannot_contradict_durable_vanished_evidence() {
        let root = temp_root("cross-page-vanished-contradiction");
        let error = run_acquisition(
            &mut CrossPageVanishedContradiction { calls: 0 },
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ImapUnexpectedResult);
        assert!(error.to_string().contains("contradicted durable VANISHED"));
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
    async fn reconnect_examine_vanished_wins_over_stale_retried_body() {
        let root = temp_root("reconnect-examine-vanished");
        let mut transport = ReconnectExamineVanishedTransport {
            snapshot_calls: 0,
            fetch_calls: 0,
            vanished_pending: false,
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
            (
                report.planned,
                report.processed,
                report.resolved,
                report.vanished,
            ),
            (1, 0, 1, 1)
        );
        assert!(matches!(report.states[&7], UidState::Vanished));
        assert!(canonical.records.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn exact_empty_reinventory_reconciles_offline_deletion_without_vanished() {
        let root = temp_root("missing-reinventory");
        let mut transport = DisappearsWithoutVanishedTransport { inventory_calls: 0 };
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
        assert_eq!(transport.inventory_calls, 2);
        assert_eq!(
            (report.processed, report.vanished, report.resolved),
            (0, 1, 1)
        );
        assert!(matches!(report.states[&7], UidState::Vanished));
        assert_eq!(report.vanished_ranges, vec![UidRange { start: 7, end: 7 }]);
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
                internal_date: Some(1_704_067_200_000),
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
                format!(
                    "* {uid} UIDFETCH (UID {uid} RFC822.SIZE {bytes} INTERNALDATE \"01-Jan-2024 00:00:00 +0000\")\r\n"
                )
                .as_bytes(),
            );
        }
        response.extend_from_slice(b"{TAG} OK UID FETCH completed\r\n");
        response
    }

    fn uidfetch_body(uid: u32, raw: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "* {uid} UIDFETCH (UID {uid} RFC822.SIZE {} BODY[]<0> {{{}}}\r\n",
            raw.len(),
            raw.len()
        )
        .into_bytes();
        response.extend_from_slice(raw);
        response.extend_from_slice(b")\r\n{TAG} OK UID FETCH completed\r\n");
        response
    }

    fn uidfetch_body_without_completion(uid: u32, raw: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "* {uid} UIDFETCH (UID {uid} RFC822.SIZE {} BODY[]<0> {{{}}}\r\n",
            raw.len(),
            raw.len()
        )
        .into_bytes();
        response.extend_from_slice(raw);
        response.extend_from_slice(b")\r\n");
        response
    }

    async fn adapted_login(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        limits: AcquisitionLimits,
    ) -> (
        async_imap::Session<bichon_uidonly::UidOnlyAdapter<Box<dyn SessionStream>>>,
        bichon_uidonly::AdapterHandle,
    ) {
        let stream = TcpStream::connect((host, port)).await.unwrap();
        let stream = Box::new(TestStream(stream)) as Box<dyn SessionStream>;
        let (stream, handle) =
            bichon_uidonly::UidOnlyAdapter::new(stream, limits.adapter_limits().unwrap()).unwrap();
        let mut client = async_imap::Client::new(stream);
        client.read_response().await.unwrap().unwrap();
        let session = client
            .login(username, password)
            .await
            .map_err(|(e, _)| e)
            .unwrap();
        (session, handle)
    }

    async fn recorded_adapted_login(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        limits: AcquisitionLimits,
    ) -> (
        async_imap::Session<bichon_uidonly::UidOnlyAdapter<Box<dyn SessionStream>>>,
        bichon_uidonly::AdapterHandle,
        Arc<Mutex<Vec<u8>>>,
    ) {
        let stream = TcpStream::connect((host, port)).await.unwrap();
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = Box::new(RecordingTestStream {
            stream,
            written: Arc::clone(&written),
        }) as Box<dyn SessionStream>;
        let (stream, handle) =
            bichon_uidonly::UidOnlyAdapter::new(stream, limits.adapter_limits().unwrap()).unwrap();
        let mut client = async_imap::Client::new(stream);
        client.read_response().await.unwrap().unwrap();
        let session = client
            .login(username, password)
            .await
            .map_err(|(error, _)| error)
            .unwrap();
        (session, handle, written)
    }

    async fn transcript_session(
        server: &crate::imap::mock_server::MockImapServerHandle,
        limits: AcquisitionLimits,
    ) -> UidOnlySession<Box<dyn SessionStream>> {
        let (session, handle) =
            adapted_login(&server.host(), server.port(), "test", "test", limits).await;
        UidOnlySession::enable(session, handle, limits.command_limits().unwrap())
            .await
            .unwrap()
    }

    fn transcript_transport(
        session: UidOnlySession<Box<dyn SessionStream>>,
        message_limit: Option<NonZeroU32>,
        limits: AcquisitionLimits,
    ) -> SessionUidOnlyTransport {
        SessionUidOnlyTransport::new(
            session,
            SessionTransportConfig {
                account_id: 7,
                message_limit,
                adapter_limits: limits.adapter_limits().unwrap(),
                command_limits: limits.command_limits().unwrap(),
                body_chunk_size: limits.body_chunk_size().unwrap(),
                max_literal_bytes: limits.max_literal_bytes,
                max_total_bytes: limits.max_total_bytes,
                expected_identity: None,
            },
        )
    }

    async fn cyrus_flag_snapshot(port: u16) -> Vec<(u32, Vec<String>)> {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut client =
            async_imap::Client::new(Box::new(TestStream(stream)) as Box<dyn SessionStream>);
        client.read_response().await.unwrap().unwrap();
        let mut session = client
            .login("archive-test", "synthetic-only-password")
            .await
            .map_err(|(error, _)| error)
            .unwrap();
        session.select("INBOX").await.unwrap();
        let fetches = session
            .uid_fetch("1:*", "(UID FLAGS)")
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        let mut snapshot: Vec<_> = fetches
            .into_iter()
            .map(|fetch| {
                (
                    fetch.uid.expect("Cyrus UID FETCH must return UID"),
                    fetch
                        .flags()
                        .map(|flag| format!("{flag:?}"))
                        .filter(|flag| flag != "Recent")
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        snapshot.sort_unstable_by_key(|(uid, _)| *uid);
        session.logout().await.unwrap();
        snapshot
    }

    #[tokio::test]
    async fn manager_route_reconnects_after_each_real_durable_boundary_eof() {
        let raw = b"From: route@example.invalid\r\n\r\nmanager path";
        let server = MockImapServer::new()
            .respond("LOGIN", b"{TAG} OK LOGIN completed\r\n".to_vec())
            .respond(
                "CAPABILITY",
                b"* CAPABILITY IMAP4rev1 UIDONLY PARTIAL MESSAGELIMIT=2\r\n{TAG} OK CAPABILITY completed\r\n"
                    .to_vec(),
            )
            .respond(
                "LOGOUT",
                b"* BYE logout\r\n{TAG} OK LOGOUT completed\r\n".to_vec(),
            )
            .respond(
                "ENABLE UIDONLY",
                b"* ENABLED UIDONLY\r\n{TAG} OK ENABLE completed\r\n".to_vec(),
            )
            .disconnect_once("EXAMINE")
            .respond("EXAMINE", examine_response("INBOX", 1, 9, 8))
            .disconnect_once("UID FETCH 1:7 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:2)")
            .respond(
                "UID FETCH 1:7 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:2)",
                uidfetch_metadata(&[(7, raw.len())]),
            )
            .respond_then_disconnect_once(
                "UID FETCH 7 ",
                uidfetch_body_without_completion(7, raw),
            )
            .respond("UID FETCH 7 ", uidfetch_body(7, raw))
            .start()
            .await;
        let account_id = 7_200_000_001;
        let imap = ImapConfig {
            host: server.host(),
            port: server.port(),
            encryption: Encryption::None,
            auth: AuthConfig {
                password: Some("synthetic-manager-password".into()),
                ..Default::default()
            },
            use_proxy: None,
        }
        .try_encrypt_password()
        .unwrap();
        insert_impl(
            DB_MANAGER.db(),
            AccountModel {
                id: account_id,
                email: "route@example.invalid".into(),
                login_name: Some("route-test".into()),
                imap: Some(imap),
                enabled: true,
                account_type: AccountType::IMAP,
                ..Default::default()
            },
        )
        .unwrap();
        let test_limits = limits();
        let connection = ImapConnectionManager::build_acquisition(
            account_id,
            test_limits.adapter_limits().unwrap(),
            test_limits.command_limits().unwrap(),
        )
        .await
        .unwrap();
        let AcquisitionConnection::UidOnly {
            session,
            message_limit,
        } = connection
        else {
            panic!("UIDONLY+PARTIAL capability set must route to UIDONLY")
        };
        assert_eq!(message_limit, NonZeroU32::new(2));
        let root = temp_root("manager-route");
        let mut transport = SessionUidOnlyTransport::new(
            *session,
            SessionTransportConfig {
                account_id,
                message_limit,
                adapter_limits: test_limits.adapter_limits().unwrap(),
                command_limits: test_limits.command_limits().unwrap(),
                body_chunk_size: test_limits.body_chunk_size().unwrap(),
                max_literal_bytes: test_limits.max_literal_bytes,
                max_total_bytes: test_limits.max_total_bytes,
                expected_identity: Some(
                    acquisition_connection_identity(&AccountModel::get(account_id).unwrap())
                        .unwrap(),
                ),
            },
        );
        let report = run_acquisition(
            &mut transport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            AcquisitionIdentity {
                endpoint: format!("{}:{}", server.host(), server.port()),
                account_id,
                canonical_mailbox: "INBOX".into(),
            },
            &root,
            test_limits,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!(
            transport.remaining_transfer_bytes,
            test_limits.max_total_bytes - 2 * raw.len() as u64,
            "both the truncated first literal and the successful retry must consume the hard total-transfer budget"
        );
        transport.logout().await;
        let commands = server.commands();
        assert_eq!(
            commands,
            vec![
                "A0001 LOGIN \"route-test\" \"synthetic-manager-password\"",
                "A0002 CAPABILITY",
                "A0003 CAPABILITY",
                "A0004 LOGOUT",
                "A0001 LOGIN \"route-test\" \"synthetic-manager-password\"",
                "A0002 CAPABILITY",
                "A0003 ENABLE UIDONLY",
                "A0004 EXAMINE \"INBOX\"",
                "A0001 LOGIN \"route-test\" \"synthetic-manager-password\"",
                "A0002 CAPABILITY",
                "A0003 CAPABILITY",
                "A0004 LOGOUT",
                "A0001 LOGIN \"route-test\" \"synthetic-manager-password\"",
                "A0002 CAPABILITY",
                "A0003 ENABLE UIDONLY",
                "A0004 EXAMINE \"INBOX\"",
                "A0005 UID FETCH 1:7 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:2)",
                "A0001 LOGIN \"route-test\" \"synthetic-manager-password\"",
                "A0002 CAPABILITY",
                "A0003 CAPABILITY",
                "A0004 LOGOUT",
                "A0001 LOGIN \"route-test\" \"synthetic-manager-password\"",
                "A0002 CAPABILITY",
                "A0003 ENABLE UIDONLY",
                "A0004 EXAMINE \"INBOX\"",
                "A0005 UID FETCH 1:7 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:2)",
                "A0006 UID FETCH 7 (UID RFC822.SIZE BODY.PEEK[]<0.1048576>)",
                "A0001 LOGIN \"route-test\" \"synthetic-manager-password\"",
                "A0002 CAPABILITY",
                "A0003 CAPABILITY",
                "A0004 LOGOUT",
                "A0001 LOGIN \"route-test\" \"synthetic-manager-password\"",
                "A0002 CAPABILITY",
                "A0003 ENABLE UIDONLY",
                "A0004 EXAMINE \"INBOX\"",
                "A0005 UID FETCH 7 (UID RFC822.SIZE BODY.PEEK[]<0.1048576>)",
                "A0006 LOGOUT",
            ],
            "probe, activation, disconnect, reconnect, re-enable, re-examine, retry, and logout must remain exactly ordered and read-only"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn ordinary_manager_route_keeps_legacy_large_literal_connection() {
        let raw = vec![b'x'; 1024 * 1024 + 1];
        let mut fetch_response =
            format!("* 1 FETCH (UID 1 BODY[] {{{}}}\r\n", raw.len()).into_bytes();
        fetch_response.extend_from_slice(&raw);
        fetch_response.extend_from_slice(b")\r\n{TAG} OK UID FETCH completed\r\n");
        let server = MockImapServer::new()
            .respond("LOGIN", b"{TAG} OK LOGIN completed\r\n".to_vec())
            .respond(
                "CAPABILITY",
                b"* CAPABILITY IMAP4rev1 IDLE\r\n{TAG} OK CAPABILITY completed\r\n".to_vec(),
            )
            .respond(
                "LOGOUT",
                b"* BYE logout\r\n{TAG} OK LOGOUT completed\r\n".to_vec(),
            )
            .respond("UID FETCH 1 ", fetch_response)
            .start()
            .await;
        let account_id = 7_200_000_003;
        let imap = ImapConfig {
            host: server.host(),
            port: server.port(),
            encryption: Encryption::None,
            auth: AuthConfig {
                password: Some("synthetic-standard-password".into()),
                ..Default::default()
            },
            use_proxy: None,
        }
        .try_encrypt_password()
        .unwrap();
        insert_impl(
            DB_MANAGER.db(),
            AccountModel {
                id: account_id,
                email: "standard@example.invalid".into(),
                login_name: Some("standard-route-test".into()),
                imap: Some(imap),
                enabled: true,
                account_type: AccountType::IMAP,
                ..Default::default()
            },
        )
        .unwrap();
        let test_limits = limits();
        let connection = ImapConnectionManager::build_acquisition(
            account_id,
            test_limits.adapter_limits().unwrap(),
            test_limits.command_limits().unwrap(),
        )
        .await
        .unwrap();
        let AcquisitionConnection::Standard(mut session) = connection else {
            panic!("ordinary capability set must remain on the standard provider path")
        };
        let fetched = session
            .uid_fetch("1", "(UID BODY.PEEK[])")
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].body().unwrap(), raw);
        session.logout().await.unwrap();
        assert_eq!(
            server.commands(),
            vec![
                "A0001 LOGIN \"standard-route-test\" \"synthetic-standard-password\"",
                "A0002 CAPABILITY",
                "A0003 CAPABILITY",
                "A0004 LOGOUT",
                "A0001 LOGIN \"standard-route-test\" \"synthetic-standard-password\"",
                "A0002 CAPABILITY",
                "A0003 UID FETCH 1 (UID BODY.PEEK[])",
                "A0004 LOGOUT",
            ],
            "ordinary acquisition must keep its unwrapped legacy connection and command lifecycle"
        );
    }

    #[tokio::test]
    async fn yahoo_like_empty_mailbox_still_enables_uidonly_and_examines() {
        let server = MockImapServer::new()
            .respond("LOGIN", b"{TAG} OK LOGIN completed\r\n".to_vec())
            .respond(
                "CAPABILITY",
                b"* CAPABILITY IMAP4rev1 UIDONLY PARTIAL\r\n{TAG} OK CAPABILITY completed\r\n"
                    .to_vec(),
            )
            .respond(
                "LOGOUT",
                b"* BYE logout\r\n{TAG} OK LOGOUT completed\r\n".to_vec(),
            )
            .respond(
                "ENABLE UIDONLY",
                b"* ENABLED UIDONLY\r\n{TAG} OK ENABLE completed\r\n".to_vec(),
            )
            .respond("EXAMINE", examine_response("INBOX", 0, 9, 1))
            .start()
            .await;
        let account_id = 7_200_000_002;
        let imap = ImapConfig {
            host: server.host(),
            port: server.port(),
            encryption: Encryption::None,
            auth: AuthConfig {
                password: Some("synthetic-empty-password".into()),
                ..Default::default()
            },
            use_proxy: None,
        }
        .try_encrypt_password()
        .unwrap();
        insert_impl(
            DB_MANAGER.db(),
            AccountModel {
                id: account_id,
                email: "empty@example.invalid".into(),
                login_name: Some("empty-route-test".into()),
                imap: Some(imap),
                enabled: true,
                account_type: AccountType::IMAP,
                ..Default::default()
            },
        )
        .unwrap();
        let test_limits = limits();
        let connection = ImapConnectionManager::build_acquisition(
            account_id,
            test_limits.adapter_limits().unwrap(),
            test_limits.command_limits().unwrap(),
        )
        .await
        .unwrap();
        let AcquisitionConnection::UidOnly {
            session,
            message_limit,
        } = connection
        else {
            panic!("Yahoo-like capability set must route through UIDONLY")
        };
        let mut transport = SessionUidOnlyTransport::new(
            *session,
            SessionTransportConfig {
                account_id,
                message_limit,
                adapter_limits: test_limits.adapter_limits().unwrap(),
                command_limits: test_limits.command_limits().unwrap(),
                body_chunk_size: test_limits.body_chunk_size().unwrap(),
                max_literal_bytes: test_limits.max_literal_bytes,
                max_total_bytes: test_limits.max_total_bytes,
                expected_identity: Some(
                    acquisition_connection_identity(&AccountModel::get(account_id).unwrap())
                        .unwrap(),
                ),
            },
        );
        let root = temp_root("empty-yahoo-route");
        let report = run_acquisition(
            &mut transport,
            &mut FakeCanonicalArchive::default(),
            "INBOX",
            AcquisitionIdentity {
                endpoint: format!("{}:{}", server.host(), server.port()),
                account_id,
                canonical_mailbox: "INBOX".into(),
            },
            &root,
            test_limits,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(report.success);
        assert_eq!(
            (report.planned, report.processed, report.resolved),
            (0, 0, 0)
        );
        transport.logout().await;
        assert_eq!(
            server.commands(),
            vec![
                "A0001 LOGIN \"empty-route-test\" \"synthetic-empty-password\"",
                "A0002 CAPABILITY",
                "A0003 CAPABILITY",
                "A0004 LOGOUT",
                "A0001 LOGIN \"empty-route-test\" \"synthetic-empty-password\"",
                "A0002 CAPABILITY",
                "A0003 ENABLE UIDONLY",
                "A0004 EXAMINE \"INBOX\"",
                "A0005 LOGOUT",
            ]
        );
        fs::remove_dir_all(root).unwrap();
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
                "UID FETCH 1:50 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:2)",
                uidfetch_metadata(&[(2, raw2.len()), (30, raw30.len())]),
            )
            .respond(
                "UID FETCH 31:50 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:2)",
                uidfetch_metadata(&[(50, raw50.len())]),
            )
            .respond("UID FETCH 2 ", uidfetch_body(2, raw2))
            .respond("UID FETCH 30 ", uidfetch_body(30, raw30))
            .respond("UID FETCH 50 ", uidfetch_body(50, raw50))
            .respond(
                "LOGOUT",
                b"* BYE logout\r\n{TAG} OK LOGOUT completed\r\n".to_vec(),
            )
            .start()
            .await;
        let test_limits = limits();
        let session = transcript_session(&server, test_limits).await;
        let root = temp_root("tcp-fake");
        let mut transport = transcript_transport(session, NonZeroU32::new(2), test_limits);
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
        transport.logout().await;
        let commands = server.commands();
        let untagged: Vec<_> = commands
            .iter()
            .map(|command| command.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(
            untagged,
            vec![
                "LOGIN \"test\" \"test\"",
                "ENABLE UIDONLY",
                "EXAMINE \"INBOX\"",
                "UID FETCH 1:50 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:2)",
                "UID FETCH 31:50 (UID RFC822.SIZE INTERNALDATE) (PARTIAL 1:2)",
                "UID FETCH 2 (UID RFC822.SIZE BODY.PEEK[]<0.1048576>)",
                "UID FETCH 30 (UID RFC822.SIZE BODY.PEEK[]<0.1048576>)",
                "UID FETCH 50 (UID RFC822.SIZE BODY.PEEK[]<0.1048576>)",
                "LOGOUT",
            ],
            "the complete UIDONLY transcript must remain read-only and ordered"
        );
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
        let small_limits = AcquisitionLimits {
            max_literal_bytes: 4,
            max_response_bytes: 1024 * 1024,
            ..limits()
        };
        let session = transcript_session(&server, small_limits).await;
        let error = session
            .fetch_body_chunk(NonZeroU32::new(7).unwrap(), 0, NonZeroU32::new(4).unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "UIDONLY IMAP response read or parse failed"
        );
    }

    #[tokio::test]
    #[ignore = "run crates/core/tests/cyrus/run.sh"]
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

        let connect = |username: &'static str| async move {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut client =
                async_imap::Client::new(Box::new(TestStream(stream)) as Box<dyn SessionStream>);
            client.read_response().await.unwrap().unwrap();
            client
                .login(username, "synthetic-only-password")
                .await
                .map_err(|(error, _)| error)
                .unwrap()
        };

        let mut admin = connect("cyrus").await;
        admin.create("user/archive-test").await.unwrap();
        admin.logout().await.unwrap();

        let raw_messages: [&[u8]; 3] = [
            b"From: one@example.invalid\r\nTo: archive@example.invalid\r\nSubject: one\r\n\r\nfirst\r\n",
            b"From: two@example.invalid\r\nTo: archive@example.invalid\r\nSubject: two\r\n\r\nsecond\r\n",
            b"From: three@example.invalid\r\nTo: archive@example.invalid\r\nSubject: three\r\n\r\nthird\r\n",
        ];
        let mut seed = connect("archive-test").await;
        for raw in raw_messages {
            seed.append("INBOX", None, None, raw).await.unwrap();
        }
        seed.logout().await.unwrap();
        let flags_before = cyrus_flag_snapshot(port).await;

        let account_id = 7_100_000_001;
        let mailbox_id = 7_100_000_002;
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

        let cyrus_limits = AcquisitionLimits {
            max_messages: 100,
            max_total_bytes: 100 * 1024 * 1024,
            max_literal_bytes: 25 * 1024 * 1024,
            max_response_bytes: 26 * 1024 * 1024,
            max_runtime: Duration::from_secs(600),
            max_disk_bytes: 1024 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_memory_bytes: 256 * 1024 * 1024,
            page_size: 2,
        };
        let (mut session, handle, first_wire) = recorded_adapted_login(
            "127.0.0.1",
            port,
            "archive-test",
            "synthetic-only-password",
            cyrus_limits,
        )
        .await;
        let capabilities = session.capabilities().await.unwrap();
        assert!(capabilities.has_str("UIDONLY"));
        assert!(capabilities.has_str("PARTIAL"));
        let session =
            UidOnlySession::enable(session, handle, cyrus_limits.command_limits().unwrap())
                .await
                .unwrap();
        let mut transport = transcript_transport(session, None, cyrus_limits);
        let cyrus_identity = AcquisitionIdentity {
            endpoint: format!("127.0.0.1:{port}"),
            account_id,
            canonical_mailbox: "INBOX".into(),
        };
        let mut canonical = BichonCanonicalArchive::new(account_id, mailbox_id);
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
        transport.logout().await;

        let (restart_session, restart_handle, restart_wire) = recorded_adapted_login(
            "127.0.0.1",
            port,
            "archive-test",
            "synthetic-only-password",
            cyrus_limits,
        )
        .await;
        let restart_session = UidOnlySession::enable(
            restart_session,
            restart_handle,
            cyrus_limits.command_limits().unwrap(),
        )
        .await
        .unwrap();
        let mut restart_transport = transcript_transport(restart_session, None, cyrus_limits);
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
            "restart must revalidate canonical records without reprojecting bodies"
        );
        restart_transport.logout().await;

        let mut acquisition_wire = first_wire.lock().unwrap().clone();
        acquisition_wire.extend_from_slice(&restart_wire.lock().unwrap());
        let acquisition_wire = String::from_utf8(acquisition_wire).unwrap();
        let commands: Vec<_> = acquisition_wire
            .lines()
            .filter_map(|line| line.split_once(' ').map(|(_, command)| command))
            .collect();
        assert!(commands.contains(&"ENABLE UIDONLY"));
        assert!(commands
            .iter()
            .any(|command| command.starts_with("EXAMINE ")));
        assert!(commands
            .iter()
            .any(|command| command.contains("PARTIAL 1:2")));
        assert!(commands
            .iter()
            .any(|command| command.contains("BODY.PEEK[]")));
        for command in commands {
            assert!(
                command.starts_with("LOGIN ")
                    || ["CAPABILITY", "ENABLE UIDONLY", "LOGOUT"].contains(&command)
                    || command.starts_with("EXAMINE ")
                    || (command.starts_with("UID FETCH ")
                        && (command.contains("(PARTIAL ") || command.contains("BODY.PEEK[]"))),
                "Cyrus acquisition emitted a command outside the exact read-only allowlist: {command}"
            );
        }

        let epoch = root
            .join(cyrus_identity.storage_key())
            .join(report.uid_validity.to_string());
        assert_eq!(fs::read_dir(epoch.join("records")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(epoch.join("blobs")).unwrap().count(), 0);
        let mut envelope_ids = BTreeSet::new();
        for (uid, raw) in (1_u32..).zip(raw_messages) {
            let projection = ENVELOPE_MANAGER
                .get_projection_by_uid(account_id, mailbox_id, uid)
                .unwrap()
                .expect("Cyrus message must be queryable from the canonical index");
            assert_eq!(projection.content_hash, compute_content_hash(raw));
            assert_eq!(projection.shard_id, UIDONLY_SHARD_ID);
            envelope_ids.insert(projection.envelope_id.clone());
            let (envelope, restored) =
                reattach_eml_content(account_id, projection.envelope_id).unwrap();
            assert_eq!(envelope.uid, uid);
            assert_eq!(restored.as_ref(), raw);
        }
        assert_eq!(envelope_ids.len(), 3);
        let flags_after = cyrus_flag_snapshot(port).await;
        assert_eq!(
            flags_after, flags_before,
            "acquisition must not mutate flags"
        );
    }
}
