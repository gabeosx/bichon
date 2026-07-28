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

use crate::{
    account::{
        migration::AccountModel,
        state::{DownloadState, DownloadStatus, FolderStatus},
    },
    cache::{
        imap::{
            download::flow::{fetch_and_save_by_date, fetch_and_save_full_mailbox, FetchDirection},
            mailbox::MailBox,
        },
        SEMAPHORE,
    },
    error::{code::ErrorCode, BichonResult},
    imap::uidonly_acquisition::cleanup_uidonly_mailbox_state,
    raise_error,
    settings::dir::DATA_DIR_MANAGER,
    store::tantivy::{attachment::ATTACHMENT_MANAGER, envelope::ENVELOPE_MANAGER},
};

use std::collections::BTreeSet;
use std::future::Future;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

async fn run_rebuild_sequence<R, Cleanup, DeleteEnvelope, DeleteAttachment, Reacquire>(
    cleanup: Cleanup,
    delete_envelope: DeleteEnvelope,
    delete_attachment: DeleteAttachment,
    reacquire: Reacquire,
) -> BichonResult<R>
where
    Cleanup: Future<Output = BichonResult<()>>,
    DeleteEnvelope: Future<Output = BichonResult<()>>,
    DeleteAttachment: Future<Output = BichonResult<()>>,
    Reacquire: Future<Output = BichonResult<R>>,
{
    cleanup.await?;
    delete_envelope.await?;
    delete_attachment.await?;
    reacquire.await
}

pub async fn rebuild_cache(
    account: &AccountModel,
    remote_mailboxes: &[MailBox],
    token: CancellationToken,
) -> BichonResult<()> {
    MailBox::batch_insert(remote_mailboxes)?;
    DownloadState::init_folder_details(
        account.id,
        remote_mailboxes.iter().map(|m| m.name.clone()).collect(),
    )?;

    let mut has_error = false;
    let mut last_err = None;

    for mailbox in remote_mailboxes {
        if token.is_cancelled() {
            DownloadState::update_session_status(
                account.id,
                DownloadStatus::Cancelled,
                Some("Received termination signal (User stop or System shutdown)".to_string()),
            )?;
            break;
        }
        if mailbox.exists == 0 {
            info!(
                "Account {}: Mailbox '{}' on the remote server has no emails. Skipping fetch for this mailbox.",
                account.id, &mailbox.name
            );
            DownloadState::update_folder_progress(
                account.id,
                mailbox.name.clone(),
                0,
                0,
                FolderStatus::Success,
                None,
            )?;
            continue;
        }
        let account = account.clone();
        let mailbox = mailbox.clone();

        let _global_permit = match SEMAPHORE.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => {
                error!(
                    "Failed to acquire global semaphore permit for account {} mailbox '{}': {:#?}",
                    account.id, &mailbox.name, err
                );
                continue;
            }
        };

        match fetch_and_save_full_mailbox(&account, &mailbox, token.clone()).await {
            Ok(new_highest_uid) => {
                let mut updated = mailbox.clone();
                updated.highest_uid = new_highest_uid;
                MailBox::batch_upsert(&[updated])?;
            }
            Err(err) => {
                has_error = true;
                tracing::error!("Folder sync task failed: {:#?}", err);
                last_err = Some(err);
            }
        }
    }

    if has_error {
        if let Some(e) = last_err {
            return Err(e);
        }
        return Err(raise_error!(
            "Some tasks failed".into(),
            ErrorCode::InternalError
        ));
    }
    Ok(())
}

pub async fn rebuild_cache_by_date(
    account: &AccountModel,
    remote_mailboxes: &[MailBox],
    date: &str,
    direction: FetchDirection,
    token: CancellationToken,
) -> BichonResult<()> {
    MailBox::batch_insert(remote_mailboxes)?;
    DownloadState::init_folder_details(
        account.id,
        remote_mailboxes.iter().map(|m| m.name.clone()).collect(),
    )?;

    let mut has_error = false;
    let mut last_err = None;

    for mailbox in remote_mailboxes {
        if token.is_cancelled() {
            DownloadState::update_session_status(
                account.id,
                DownloadStatus::Cancelled,
                Some("Received termination signal (User stop or System shutdown)".to_string()),
            )?;
            break;
        }
        if mailbox.exists == 0 {
            info!(
                "Account {}: Mailbox '{}' on the remote server has no emails. Skipping fetch for this mailbox.",
                account.id, &mailbox.name
            );

            DownloadState::update_folder_progress(
                account.id,
                mailbox.name.clone(),
                0,
                0,
                FolderStatus::Success,
                None,
            )?;
            continue;
        }
        let account = account.clone();
        let mailbox = mailbox.clone();
        let date = date.to_string();
        let direction = direction.clone();

        let _global_permit = match SEMAPHORE.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => {
                error!(
                    "Failed to acquire global semaphore permit for account {} mailbox '{}': {:#?}",
                    account.id, &mailbox.name, err
                );
                continue;
            }
        };
        match fetch_and_save_by_date(&account, date.as_str(), &mailbox, direction, token.clone())
            .await
        {
            Ok(new_highest_uid) => {
                let mut updated = mailbox.clone();
                updated.highest_uid = new_highest_uid;
                MailBox::batch_upsert(&[updated])?;
            }
            Err(err) => {
                has_error = true;
                tracing::error!("Folder sync task failed: {:#?}", err);
                last_err = Some(err);
            }
        }
    }

    if has_error {
        if let Some(e) = last_err {
            return Err(e);
        }
        return Err(raise_error!(
            "Some tasks failed".into(),
            ErrorCode::InternalError
        ));
    }

    Ok(())
}

pub async fn rebuild_mailbox_cache(
    account: &AccountModel,
    local_mailbox: &MailBox,
    remote_mailbox: &MailBox,
    token: CancellationToken,
) -> BichonResult<Option<u32>> {
    let names = BTreeSet::from([local_mailbox.name.clone(), remote_mailbox.name.clone()]);
    run_rebuild_sequence(
        async {
            cleanup_uidonly_mailbox_state(
                &DATA_DIR_MANAGER.storage_dir.join("uidonly-acquisition"),
                account.id,
                &names,
            )?;
            Ok(())
        },
        ENVELOPE_MANAGER.delete_mailbox_envelopes(account.id, vec![local_mailbox.id]),
        ATTACHMENT_MANAGER.delete_mailbox_attachments(account.id, vec![local_mailbox.id]),
        async {
            if remote_mailbox.exists == 0 {
                info!(
                    "Account {}: Mailbox '{}' has no emails on the remote server. The mailbox is empty, no envelopes to fetch.",
                    account.id,
                    &local_mailbox.name
                );
                DownloadState::update_folder_progress(
                    account.id,
                    remote_mailbox.name.clone(),
                    0,
                    0,
                    FolderStatus::Success,
                    None,
                )?;
                Ok(None)
            } else {
                fetch_and_save_full_mailbox(account, remote_mailbox, token).await
            }
        },
    )
    .await
}

pub async fn rebuild_mailbox_cache_by_date(
    account: &AccountModel,
    local_mailbox_id: u64,
    date: &str,
    remote: &MailBox,
    direction: FetchDirection,
    token: CancellationToken,
) -> BichonResult<Option<u32>> {
    let names = BTreeSet::from([remote.name.clone()]);
    run_rebuild_sequence(
        async {
            cleanup_uidonly_mailbox_state(
                &DATA_DIR_MANAGER.storage_dir.join("uidonly-acquisition"),
                account.id,
                &names,
            )?;
            Ok(())
        },
        ENVELOPE_MANAGER.delete_mailbox_envelopes(account.id, vec![local_mailbox_id]),
        ATTACHMENT_MANAGER.delete_mailbox_attachments(account.id, vec![local_mailbox_id]),
        async {
            if remote.exists == 0 {
                info!(
                    "Account {}: Mailbox '{}' has no emails on the remote server. The mailbox is empty, no envelopes to fetch.",
                    account.id,
                    &remote.name
                );
                DownloadState::update_folder_progress(
                    account.id,
                    remote.name.clone(),
                    0,
                    0,
                    FolderStatus::Success,
                    None,
                )?;
                Ok(None)
            } else {
                fetch_and_save_by_date(account, date, remote, direction, token).await
            }
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn rebuild_sequence_cleans_ledger_before_indexes_then_reacquires() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let record = |event: &'static str| {
            let events = events.clone();
            async move {
                events.lock().unwrap().push(event);
                Ok::<_, crate::error::BichonError>(())
            }
        };
        let reacquire_events = events.clone();
        let result = run_rebuild_sequence(
            record("cleanup-ledger"),
            record("delete-envelope-index"),
            record("delete-attachment-index"),
            async move {
                reacquire_events.lock().unwrap().push("reacquire");
                Ok(77u32)
            },
        )
        .await
        .unwrap();
        assert_eq!(result, 77);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "cleanup-ledger",
                "delete-envelope-index",
                "delete-attachment-index",
                "reacquire"
            ]
        );
    }

    #[tokio::test]
    async fn rebuild_cleanup_failure_aborts_before_canonical_deletion() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let later = |event: &'static str| {
            let events = events.clone();
            async move {
                events.lock().unwrap().push(event);
                Ok::<_, crate::error::BichonError>(())
            }
        };
        let error = run_rebuild_sequence(
            async {
                Err(raise_error!(
                    "synthetic ledger cleanup failure".into(),
                    ErrorCode::InternalError
                ))
            },
            later("delete-envelope-index"),
            later("delete-attachment-index"),
            async { Ok(()) },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("synthetic ledger cleanup failure"));
        assert!(events.lock().unwrap().is_empty());
    }
}
