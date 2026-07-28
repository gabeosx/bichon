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

use crate::raise_error;
use crate::{
    common::signal::SIGNAL_MANAGER,
    envelope::extractor::reattach_eml_content_self_healing,
    error::{code::ErrorCode, BichonResult},
    settings::dir::DATA_DIR_MANAGER,
};
use bichon_blob::{Codec, Config, Engine};
use bytes::Bytes;

use std::{
    collections::HashSet,
    io::Cursor,
    sync::{Arc, LazyLock, Mutex as StdMutex},
};
use tokio::{
    sync::{mpsc, Mutex},
    task::{self, JoinHandle},
};

pub static BLOB_MANAGER: LazyLock<BlobManager> = LazyLock::new(BlobManager::new);

pub struct DetachedEmail {
    pub email: (String, Bytes),
    pub attachments: Option<Vec<(String, Bytes)>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DurableBlobWrite {
    pub email_hash: Option<String>,
    pub attachment_hashes: Vec<String>,
    pub bytes_written: u64,
}

pub struct BlobManager {
    sender: mpsc::Sender<DetachedEmail>,
    engine: Arc<Engine>,
    write_lock: Arc<StdMutex<()>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

fn hex_to_key(hex: &str) -> BichonResult<[u8; 32]> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex, &mut key).map_err(|e| {
        raise_error!(
            format!("invalid content hash '{hex}': {e:#?}"),
            ErrorCode::InternalError
        )
    })?;
    Ok(key)
}

impl BlobManager {
    fn store_detached_email(eml: DetachedEmail, engine: &Engine) -> BichonResult<DurableBlobWrite> {
        let mut written = DurableBlobWrite::default();
        let mut entries = Vec::new();
        let mut new_keys = HashSet::new();
        let (email_hash, email_data) = eml.email;
        let email_key = hex_to_key(&email_hash)?;
        if !engine
            .exists(&email_key)
            .map_err(|e| raise_error!(format!("{e:#?}"), ErrorCode::InternalError))?
        {
            let bytes = email_data.len() as u64;
            new_keys.insert(email_key);
            entries.push((email_key, email_data.to_vec(), Codec::Lz4));
            written.email_hash = Some(email_hash);
            written.bytes_written = written.bytes_written.saturating_add(bytes);
        }

        if let Some(attachments) = eml.attachments {
            for (attachment_hash, attachment_data) in attachments {
                let attachment_key = hex_to_key(&attachment_hash)?;
                if !new_keys.contains(&attachment_key)
                    && !engine
                        .exists(&attachment_key)
                        .map_err(|e| raise_error!(format!("{e:#?}"), ErrorCode::InternalError))?
                {
                    let bytes = attachment_data.len() as u64;
                    new_keys.insert(attachment_key);
                    entries.push((attachment_key, attachment_data.to_vec(), Codec::Lz4));
                    written.attachment_hashes.push(attachment_hash);
                    written.bytes_written = written.bytes_written.saturating_add(bytes);
                }
            }
        }

        if let Err(error) = engine
            .put_batch(&entries)
            .map_err(|e| raise_error!(format!("{e:#?}"), ErrorCode::InternalError))
        {
            let rollback_keys: Vec<_> = new_keys.into_iter().collect();
            engine.delete_batch(&rollback_keys).map_err(|rollback_error| {
                raise_error!(
                    format!(
                        "canonical blob write failed ({error}); rollback failed ({rollback_error:#?})"
                    ),
                    ErrorCode::InternalError
                )
            })?;
            return Err(error);
        }

        Ok(written)
    }

    pub async fn shutdown(&self) {
        let mut guard = self.handle.lock().await;
        if let Some(handle) = guard.take() {
            let _ = handle.await;
        }
        if let Err(e) = self.engine.shutdown() {
            tracing::error!("blob engine shutdown error: {}", e);
        }
    }

    fn process_detached_email(eml: DetachedEmail, engine: &Engine) {
        let (email_hash, email_data) = eml.email;
        let email_key = match hex_to_key(&email_hash) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("{:#?}", e);
                return;
            }
        };
        match engine.exists(&email_key) {
            Ok(false) => {
                if let Err(e) = engine.put(email_key, &email_data, Codec::Lz4) {
                    tracing::error!("CRITICAL: Failed to insert email blob: {:?}", e);
                }
            }
            Err(e) => tracing::error!("blob engine error: {:?}", e),
            Ok(true) => {
                tracing::debug!("Email blob already exists (dedup): {}", &email_hash);
            }
        }

        if let Some(attachments) = eml.attachments {
            for (a_hash, a_data) in attachments {
                let a_key = match hex_to_key(&a_hash) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::error!("{:#?}", e);
                        continue;
                    }
                };
                match engine.exists(&a_key) {
                    Ok(false) => {
                        if let Err(e) = engine.put(a_key, &a_data, Codec::Lz4) {
                            tracing::error!("CRITICAL: Failed to insert attachment blob: {:?}", e);
                        }
                    }
                    Err(e) => tracing::error!("blob engine error: {:?}", e),
                    Ok(true) => {
                        tracing::debug!("Attachment blob already exists (dedup): {}", &a_hash);
                    }
                }
            }
        }
    }

    pub fn new() -> Self {
        let blob_dir = DATA_DIR_MANAGER.storage_dir.join("blobs");

        let mut config = Config::default();
        config.default_codec = Codec::Zstd;
        config.compress_threshold = 1024;
        config.flush_interval_secs = 60;
        config.gc_interval_secs = 300;

        let engine = Engine::open(&blob_dir, config)
            .expect("Failed to initialize blob engine: Check disk space and permissions.");

        let engine = Arc::new(engine);

        let (sender, mut receiver) = mpsc::channel::<DetachedEmail>(100);
        let write_lock = Arc::new(StdMutex::new(()));

        let engine_bg = Arc::clone(&engine);
        let handler_write_lock = write_lock.clone();
        let handler = task::spawn(async move {
            let mut shutdown = SIGNAL_MANAGER.subscribe();
            loop {
                tokio::select! {
                    res = receiver.recv() => {
                        match res {
                            Some(eml) => {
                                let mut batch = vec![eml];
                                while let Ok(next_eml) = receiver.try_recv() {
                                    batch.push(next_eml);
                                }
                                let engine_bg = Arc::clone(&engine_bg);
                                let write_lock = handler_write_lock.clone();
                                if let Err(e) = tokio::task::spawn_blocking(move || {
                                    let _write_guard = write_lock.lock().unwrap();
                                    for eml in batch {
                                        Self::process_detached_email(eml, &engine_bg);
                                    }
                                }).await {
                                    tracing::error!("BlobManager: spawn_blocking join error: {:#?}", e);
                                }
                            }
                            None => {
                                tracing::info!("BlobManager: All senders dropped, closing blob storage.");
                                break;
                            }
                        }
                    }
                    _ = shutdown.recv() => {
                        receiver.close();
                        let mut remaining = Vec::new();
                        while let Some(eml) = receiver.recv().await {
                            remaining.push(eml);
                        }
                        tracing::info!(
                            "BlobManager: Shutdown signal received. Processing {} remaining tasks...",
                            remaining.len()
                        );
                        if !remaining.is_empty() {
                            let engine_bg = Arc::clone(&engine_bg);
                            let write_lock = handler_write_lock.clone();
                            if let Err(e) = tokio::task::spawn_blocking(move || {
                                let _write_guard = write_lock.lock().unwrap();
                                for eml in remaining {
                                    Self::process_detached_email(eml, &engine_bg);
                                }
                            }).await {
                                tracing::error!("BlobManager: shutdown spawn_blocking join error: {:#?}", e);
                            }
                        }
                        tracing::info!("BlobManager: All remaining tasks processed. Closing blob engine.");
                        break;
                    }
                }
            }
        });

        Self {
            sender,
            engine,
            write_lock,
            handle: Mutex::new(Some(handler)),
        }
    }

    pub async fn queue(&self, email: DetachedEmail) {
        if let Err(e) = self.sender.send(email).await {
            tracing::error!("BlobManager channel closed, email lost: {:#?}", e);
        }
    }

    /// Stores a detached message through the canonical blob engine and waits
    /// for its segment and index metadata to be durably synchronized.
    pub(crate) async fn store_durable(
        &self,
        email: DetachedEmail,
    ) -> BichonResult<DurableBlobWrite> {
        let engine = Arc::clone(&self.engine);
        let write_lock = self.write_lock.clone();
        tokio::task::spawn_blocking(move || {
            let _write_guard = write_lock.lock().unwrap();
            Self::store_detached_email(email, &engine)
        })
        .await
        .map_err(|e| raise_error!(format!("{e:#?}"), ErrorCode::InternalError))?
    }

    pub fn get_email(&self, content_hash: &str) -> BichonResult<Option<Bytes>> {
        self.get(content_hash)
    }

    pub fn get_attachment(&self, content_hash: &str) -> BichonResult<Option<Bytes>> {
        self.get(content_hash)
    }

    fn get(&self, content_hash: &str) -> BichonResult<Option<Bytes>> {
        let key = hex_to_key(content_hash)?;
        self.engine
            .get(&key)
            .map(|v| v.map(Bytes::from))
            .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InternalError))
    }

    pub fn delete<I1, I2>(
        &self,
        email_content_hashes: I1,
        attachment_content_hashes: I2,
    ) -> BichonResult<()>
    where
        I1: IntoIterator,
        I1::Item: AsRef<str>,
        I2: IntoIterator,
        I2::Item: AsRef<str>,
    {
        let mut keys: Vec<[u8; 32]> = email_content_hashes
            .into_iter()
            .map(|h| hex_to_key(h.as_ref()))
            .collect::<BichonResult<_>>()?;

        for h in attachment_content_hashes {
            keys.push(hex_to_key(h.as_ref())?);
        }

        if !keys.is_empty() {
            self.engine
                .delete_batch(&keys)
                .map_err(|e| raise_error!(format!("{:#?}", e), ErrorCode::InternalError))?;
        }
        Ok(())
    }
}

/// Returns a reader over the raw EML for an indexed message.
///
/// If the message's content blob is missing from the blob store, it is fetched
/// on demand from the IMAP server, persisted, and returned (self-healing). The
/// underlying "content not found" error is only surfaced if that on-demand
/// fetch itself fails.
pub async fn get_reader(account_id: u64, eid: String) -> BichonResult<Cursor<Bytes>> {
    let (_, data) = reattach_eml_content_self_healing(account_id, eid).await?;
    Ok(Cursor::new(data))
}
