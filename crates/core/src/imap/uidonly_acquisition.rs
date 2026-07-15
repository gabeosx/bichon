//! UID-safe, restartable mailbox acquisition.
//!
//! This module is intentionally separate from Bichon's legacy sequence-number
//! downloader. A UIDONLY session never reaches code which can issue ordinary
//! FETCH, SEARCH, STORE, COPY, or MOVE commands.

use crate::account::migration::AccountModel;
use crate::cache::imap::mailbox::MailBox;
use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::imap::manager::{AcquisitionConnection, ImapConnectionManager};
use crate::imap::session::SessionStream;
use crate::raise_error;
use async_imap::types::{PartialRange, ResponseLimits, UidOnlyUnsolicitedResponse};
use async_imap::Session;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const BODY_QUERY: &str = "(UID RFC822.SIZE BODY.PEEK[])";
const INVENTORY_QUERY: &str = "(UID RFC822.SIZE)";
const MAX_NETWORK_RETRIES: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquisitionLimits {
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
pub struct AcquisitionIdentity {
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
pub enum UidState {
    Missing,
    Pending,
    Committed { blob_hash: String, bytes: u64 },
    Vanished,
    Failed { reason: String },
    Oversized { declared: u64, limit: u64 },
}

impl UidState {
    fn reconciled(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Vanished)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UidEntry {
    pub declared_size: Option<u64>,
    pub state: UidState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcquisitionLedger {
    pub identity: AcquisitionIdentity,
    pub uid_validity: u32,
    pub snapshot_end: u32,
    pub checkpoint: Option<u32>,
    pub entries: BTreeMap<u32, UidEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub uid_validity: u32,
    pub uid_next: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryItem {
    pub uid: u32,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryPage {
    pub items: Vec<InventoryItem>,
    pub vanished: BTreeSet<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchOutcome {
    Message {
        declared_size: Option<u64>,
        raw: Vec<u8>,
    },
    Vanished,
    Missing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportFailure {
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
pub trait UidOnlyTransport {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquisitionReport {
    pub uid_validity: u32,
    pub planned: u64,
    pub processed: u64,
    pub checkpoint: Option<u32>,
    pub success: bool,
    pub states: BTreeMap<u32, UidState>,
}

struct DurableArchive {
    identity_dir: PathBuf,
    epoch_dir: PathBuf,
    ledger_path: PathBuf,
    limits: AcquisitionLimits,
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
                return Err(raise_error!(
                    format!(
                        "UIDVALIDITY changed from {} to {}; earlier UID progress is invalid and requires reconciliation",
                        existing.trim(), uid_validity
                    ),
                    ErrorCode::Incompatible
                ));
            }
        } else {
            atomic_write(&epoch_marker, uid_validity.to_string().as_bytes())?;
        }

        let epoch_dir = identity_dir.join(uid_validity.to_string());
        fs::create_dir_all(epoch_dir.join("blobs")).map_err(io_error)?;
        fs::create_dir_all(epoch_dir.join("records")).map_err(io_error)?;
        let ledger_path = epoch_dir.join("ledger.json");
        Ok(Self {
            identity_dir,
            epoch_dir,
            ledger_path,
            limits,
        })
    }

    fn load_or_create(
        &self,
        identity: AcquisitionIdentity,
        uid_validity: u32,
        snapshot_end: u32,
    ) -> BichonResult<AcquisitionLedger> {
        if self.ledger_path.exists() {
            let bytes = fs::read(&self.ledger_path).map_err(io_error)?;
            let ledger: AcquisitionLedger = serde_json::from_slice(&bytes).map_err(|e| {
                raise_error!(
                    format!("invalid UIDONLY ledger: {e}"),
                    ErrorCode::InternalError
                )
            })?;
            if ledger.identity != identity || ledger.uid_validity != uid_validity {
                return Err(raise_error!(
                    "UIDONLY ledger identity mismatch".into(),
                    ErrorCode::Incompatible
                ));
            }
            return Ok(ledger);
        }
        Ok(AcquisitionLedger {
            identity,
            uid_validity,
            snapshot_end,
            checkpoint: None,
            entries: BTreeMap::new(),
        })
    }

    fn persist_ledger(&self, ledger: &AcquisitionLedger) -> BichonResult<()> {
        let bytes = serde_json::to_vec_pretty(ledger).map_err(|e| {
            raise_error!(
                format!("cannot serialize UIDONLY ledger: {e}"),
                ErrorCode::InternalError
            )
        })?;
        atomic_write(&self.ledger_path, &bytes)
    }

    fn commit_raw(
        &self,
        ledger: &AcquisitionLedger,
        uid: u32,
        raw: &[u8],
    ) -> BichonResult<(String, u64)> {
        let hash = blake3::hash(raw).to_hex().to_string();
        let blob_path = self.epoch_dir.join("blobs").join(&hash);
        let record_path = self.epoch_dir.join("records").join(format!("{uid}.json"));

        let existing_disk = directory_size(&self.identity_dir)?;
        let additional = if blob_path.exists() {
            0
        } else {
            raw.len() as u64
        };
        if existing_disk.saturating_add(additional) > self.limits.max_disk_bytes {
            return Err(raise_error!(
                format!(
                    "UIDONLY disk ceiling {} bytes exceeded",
                    self.limits.max_disk_bytes
                ),
                ErrorCode::PayloadTooLarge
            ));
        }

        if blob_path.exists() {
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

        #[derive(Serialize)]
        struct LogicalRecord<'a> {
            identity: &'a AcquisitionIdentity,
            uid_validity: u32,
            uid: u32,
            blob_hash: &'a str,
            bytes: u64,
        }
        let record = serde_json::to_vec_pretty(&LogicalRecord {
            identity: &ledger.identity,
            uid_validity: ledger.uid_validity,
            uid,
            blob_hash: &hash,
            bytes: raw.len() as u64,
        })
        .map_err(|e| {
            raise_error!(
                format!("cannot serialize logical record: {e}"),
                ErrorCode::InternalError
            )
        })?;
        atomic_write(&record_path, &record)?;

        Ok((hash, raw.len() as u64))
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

pub async fn run_acquisition<T: UidOnlyTransport>(
    transport: &mut T,
    mailbox: &str,
    identity: AcquisitionIdentity,
    root: &Path,
    limits: AcquisitionLimits,
    token: CancellationToken,
) -> BichonResult<AcquisitionReport> {
    let started = Instant::now();
    let snapshot = transport.snapshot(mailbox).await.map_err(transport_error)?;
    let snapshot_end = snapshot.uid_next.saturating_sub(1);
    let archive = DurableArchive::open(root, &identity, snapshot.uid_validity, limits)?;
    let mut ledger = archive.load_or_create(identity, snapshot.uid_validity, snapshot_end)?;
    // A restart continues the original fixed snapshot even if UIDNEXT grew.
    let snapshot_end = ledger.snapshot_end;

    let page_size = limits.page_size.max(1);
    let mut first_uid = 1u32;
    while first_uid <= snapshot_end {
        validate_runtime(started, limits, &token)?;
        let page = transport
            .inventory_page(first_uid, snapshot_end, page_size)
            .await
            .map_err(transport_error)?;
        for uid in page.vanished {
            if let Some(entry) = ledger.entries.get_mut(&uid) {
                entry.state = UidState::Vanished;
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
            let entry = ledger.entries.entry(item.uid).or_insert(UidEntry {
                declared_size: item.size,
                state: UidState::Missing,
            });
            if entry.declared_size.is_none() {
                entry.declared_size = item.size;
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
        archive.persist_ledger(&ledger)?;
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
        let current = &ledger.entries[&uid];
        if current.state.reconciled() || matches!(current.state, UidState::Oversized { .. }) {
            continue;
        }
        if let Some(declared) = current.declared_size {
            if declared > limits.max_literal_bytes {
                ledger.entries.get_mut(&uid).unwrap().state = UidState::Oversized {
                    declared,
                    limit: limits.max_literal_bytes,
                };
                archive.persist_ledger(&ledger)?;
                continue;
            }
        }

        ledger.entries.get_mut(&uid).unwrap().state = UidState::Pending;
        archive.persist_ledger(&ledger)?;

        let mut retry = 0;
        let outcome = loop {
            match transport.fetch_uid(uid).await {
                Ok(outcome) => break Ok(outcome),
                Err(error) if error.network && retry < MAX_NETWORK_RETRIES => {
                    retry += 1;
                    transport.reconnect().await.map_err(transport_error)?;
                    let resumed = transport.snapshot(mailbox).await.map_err(transport_error)?;
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
                Err(error) => break Err(transport_error(error)),
            }
        };

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                    reason: error.to_string(),
                };
                archive.persist_ledger(&ledger)?;
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
                if declared != Some(bytes) {
                    ledger.entries.get_mut(&uid).unwrap().state = UidState::Failed {
                        reason: format!(
                            "UID {uid} declared {declared:?} bytes but returned {bytes}"
                        ),
                    };
                } else if bytes > limits.max_literal_bytes {
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
                            total_bytes = total_bytes.saturating_add(bytes);
                            ledger.entries.get_mut(&uid).unwrap().state =
                                UidState::Committed { blob_hash, bytes };
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
        archive.persist_ledger(&ledger)?;
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
        archive.persist_ledger(&ledger)?;
    }
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

pub struct SessionUidOnlyTransport {
    account_id: u64,
    session: Session<Box<dyn SessionStream>>,
    message_limit: Option<u32>,
    response_limits: ResponseLimits,
}

impl SessionUidOnlyTransport {
    pub fn new(
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

    fn drain_vanished(&self) -> BTreeSet<u32> {
        let mut vanished = BTreeSet::new();
        while let Ok(response) = self.session.uidonly_responses.try_recv() {
            if let UidOnlyUnsolicitedResponse::Vanished { uids, .. } = response {
                for range in uids {
                    vanished.extend(range);
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
            if vanished.contains(&uid) {
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

pub async fn acquire_bichon_mailbox(
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
    run_acquisition(
        &mut transport,
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
    use crate::imap::mock_server::{examine_response, MockImapServer};
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
                vanished: std::mem::take(&mut self.vanished_on_inventory),
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

    fn identity() -> AcquisitionIdentity {
        AcquisitionIdentity {
            endpoint: "imap.invalid:993".into(),
            account_id: 7,
            canonical_mailbox: "INBOX".into(),
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
        let report = run_acquisition(
            &mut transport,
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
        assert_eq!(
            fs::read_dir(epoch.join("blobs")).unwrap().count(),
            1,
            "physical body is deduplicated"
        );
        assert_eq!(
            fs::read_dir(epoch.join("records")).unwrap().count(),
            3,
            "logical UID records remain distinct"
        );
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
            outcomes: [(20, VecDeque::from([message(b"ok")]))].into(),
            vanished_on_inventory: BTreeSet::new(),
            expunge_after_first_page: None,
            reconnects: 0,
            page_requests: Vec::new(),
        };
        let report = run_acquisition(
            &mut transport,
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
        let report = run_acquisition(
            &mut first,
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
    async fn changed_uidvalidity_invalidates_prior_progress() {
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
        let error = run_acquisition(
            &mut changed,
            "INBOX",
            identity(),
            &root,
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Incompatible);
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
        archive.persist_ledger(&ledger).unwrap();

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
            let mut client = async_imap::Client::new(
                Box::new(TestStream(stream)) as Box<dyn SessionStream>
            );
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
        let report = run_acquisition(
            &mut transport,
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

        let epoch = root
            .join(cyrus_identity.storage_key())
            .join(report.uid_validity.to_string());
        assert_eq!(fs::read_dir(epoch.join("records")).unwrap().count(), 3);
        for raw in raw_messages {
            let hash = blake3::hash(raw).to_hex().to_string();
            assert_eq!(fs::read(epoch.join("blobs").join(hash)).unwrap(), raw);
        }
    }
}
