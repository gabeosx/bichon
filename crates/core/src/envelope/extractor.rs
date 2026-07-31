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

use crate::account::migration::AccountModel;
use crate::cache::imap::mailbox::MailBox;
use crate::common::AddrVec;
use crate::envelope::meta::parse_bichon_metadata;
use crate::envelope::utils::normalize_subject;
use crate::error::code::ErrorCode;
use crate::error::BichonResult;
use crate::imap::executor::ImapExecutor;
use crate::message::content::AttachmentInfo;
use crate::store::blob::{
    uidonly_attachment_blob_key, uidonly_exact_raw_blob_key, DetachedEmail,
    UidOnlyAttachmentBlobKey, BLOB_MANAGER,
};
use crate::store::tantivy::attachment::ATTACHMENT_MANAGER;
use crate::store::tantivy::dedup::UIDONLY_SHARD_ID;
use crate::store::tantivy::dedup_cache::DEDUP_CACHE;
use crate::store::tantivy::envelope::ENVELOPE_MANAGER;
use crate::store::tantivy::model::{AttachmentModel, EnvelopeWithAttachments};
use crate::utils::html::extract_text;
use crate::utils::{compute_content_hash, hex_hash};
use crate::{id, store::envelope::Envelope};
use crate::{raise_error, utc_now};
use async_imap::types::Fetch;
use bytes::Bytes;
use mail_parser::{Address, HeaderName, Message, MessageParser, MimeHeaders};
use tantivy::schema::Facet;
use tantivy::TantivyDocument;
use tokio_util::sync::CancellationToken;
use tracing::error;
use uuid::Uuid;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
static FAIL_UIDONLY_AFTER_ATTACHMENTS: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn fail_uidonly_after_attachments(enabled: bool) {
    FAIL_UIDONLY_AFTER_ATTACHMENTS.store(enabled, Ordering::Release);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalProjection {
    pub envelope_id: String,
    pub content_hash: String,
    pub created: bool,
}

pub async fn extract_envelope_and_store_it(
    fetch: Fetch,
    account_id: u64,
    mailbox_id: u64,
) -> BichonResult<()> {
    let internal_date = fetch
        .internal_date()
        .map(|d| d.timestamp_millis())
        .unwrap_or(0);
    let uid = fetch.uid.unwrap_or(0);
    let body = match fetch.body() {
        Some(b) => b,
        None => {
            tracing::warn!(
                account_id,
                uid = fetch.uid,
                "FETCH response has no body, skipping message"
            );
            return Ok(());
        }
    };
    let size = fetch.size.unwrap_or(body.len() as u32);
    extract_envelope_core(
        body,
        uid,
        size,
        internal_date,
        account_id,
        mailbox_id,
        false,
        false,
        None,
        None,
    )
    .await
    .map(|_| ())
}

pub async fn extract_envelope_from_eml(
    body: &[u8],
    account_id: u64,
    mailbox_id: u64,
) -> BichonResult<()> {
    extract_envelope_core(
        body,
        0,
        body.len() as u32,
        0,
        account_id,
        mailbox_id,
        false,
        false,
        None,
        None,
    )
    .await
    .map(|_| ())
}

pub async fn extract_envelope_from_smtp(
    body: &[u8],
    account_id: u64,
    mailbox_id: u64,
) -> BichonResult<()> {
    extract_envelope_core(
        body,
        0,
        body.len() as u32,
        utc_now!(),
        account_id,
        mailbox_id,
        false,
        false,
        None,
        None,
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn project_uidonly_message(
    body: &[u8],
    uid: u32,
    size: u32,
    internal_date: i64,
    account_id: u64,
    mailbox_id: u64,
    envelope_id: String,
    shutdown: CancellationToken,
) -> BichonResult<Option<CanonicalProjection>> {
    extract_envelope_core(
        body,
        uid,
        size,
        internal_date,
        account_id,
        mailbox_id,
        true,
        true,
        Some(envelope_id),
        Some(&shutdown),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn extract_envelope_core(
    body: &[u8],
    uid: u32,
    size: u32,
    internal_date: i64,
    account_id: u64,
    mailbox_id: u64,
    durable: bool,
    preserve_uid_identity: bool,
    fixed_envelope_id: Option<String>,
    shutdown: Option<&CancellationToken>,
) -> BichonResult<Option<CanonicalProjection>> {
    //The content hash of the original raw EML
    let email_content_hash = compute_content_hash(body);
    if !preserve_uid_identity && DEDUP_CACHE.contains(account_id, mailbox_id, &email_content_hash) {
        tracing::debug!("Duplicate email detected");
        //println!("Duplicate email detected");
        return Ok(None);
    }
    let Some(message): Option<Message<'_>> = MessageParser::new().parse(body) else {
        if durable {
            return project_unparseable_uidonly(
                body,
                uid,
                size,
                internal_date,
                account_id,
                mailbox_id,
                fixed_envelope_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
                shutdown,
            )
            .await;
        }
        return Err(raise_error!(
            "Email header parse result is not available".into(),
            ErrorCode::InternalError
        ));
    };

    if let Ok(account) = AccountModel::get(account_id) {
        if let Some(ref rules) = account.archive_rules {
            let sender = message.from().and_then(|addr| {
                AddrVec::from(addr)
                    .0
                    .into_iter()
                    .next()
                    .and_then(|a| a.address)
            });
            let subject = message.subject().map(|s| s.to_string());

            let is_spam = !rules.spam_headers.is_empty()
                && rules.spam_headers.iter().any(|h| {
                    message
                        .header_raw(h.clone())
                        .map(|v| matches!(v.trim().to_lowercase().as_str(), "yes" | "true"))
                        .unwrap_or(false)
                });

            if !rules.should_archive(sender.as_deref(), subject.as_deref(), size, is_spam) {
                tracing::debug!(
                    account_id,
                    uid,
                    sender = sender.as_deref().unwrap_or("?"),
                    subject = subject.as_deref().unwrap_or("?"),
                    "Email filtered out by archive rules"
                );
                return Ok(None);
            }
        }
    }

    let preview_limit = 100;
    let text = if let Some(text) = message.body_text(0).map(|cow| cow.into_owned()) {
        text
    } else if let Some(html) = message.body_html(0).map(|cow| cow.into_owned()) {
        extract_text(html)
    } else {
        String::new()
    };

    let text = normalize_whitespace(&text, durable.then_some(16 * 1024 * 1024));
    let mut preview_chars = text.chars();
    let mut preview: String = preview_chars.by_ref().take(preview_limit).collect();
    if preview_chars.next().is_some() {
        preview.push_str("...");
    }

    let body_text = text;

    let message_id = message
        .message_id()
        .map(String::from)
        .unwrap_or_else(generate_message_id);

    let in_reply_to = message.in_reply_to().as_text().map(String::from);
    let references = extract_references(&message);
    let thread_id = compute_thread_id(in_reply_to, references, &message_id);

    let mut subject = message.subject().map(String::from).unwrap_or_default();
    if subject.contains('\u{FFFD}') {
        subject = normalize_subject(message.header_raw(HeaderName::Subject));
    }

    let date = message.date().map(|d| d.to_timestamp() * 1000).unwrap_or(0);
    let internal_date = if internal_date == 0 {
        date
    } else {
        internal_date
    };
    let parse_addrs = |addrs: Option<&Address<'_>>| {
        addrs
            .map(|addr| {
                AddrVec::from(addr)
                    .0
                    .into_iter()
                    .filter_map(|a| a.address)
                    .collect()
            })
            .unwrap_or_default()
    };

    let bcc = parse_addrs(message.bcc());
    let cc = parse_addrs(message.cc());
    let to = parse_addrs(message.to());

    let from = message
        .from()
        .and_then(|addr| AddrVec::from(addr).0.into_iter().next())
        .and_then(|add| add.address)
        .unwrap_or_else(|| "unknown".to_string());
    let attachment_count = message.attachment_count();
    let (attachments, detached_email) = prepare_detached_attachments(
        body,
        &message,
        &email_content_hash,
        account_id,
        mailbox_id,
        // External document extractors do not expose an enforceable allocator
        // budget. UIDONLY therefore skips optional attachment text/OCR during
        // acquisition; raw attachments and their metadata remain canonical.
        // This keeps the explicit projection memory ceiling meaningful.
        durable.then_some(0),
    )
    .await?;
    check_uidonly_projection_cancelled(shutdown)?;
    let envelope_id = fixed_envelope_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let now = utc_now!();

    let mut final_tags = Vec::new();

    if let Some(meta_header) = message.header_raw("X-Bichon-Metadata") {
        if let Some(bmd) = parse_bichon_metadata(meta_header) {
            if let Some(tags) = bmd.tags {
                let validated_tags: Result<Vec<String>, _> = tags
                    .iter()
                    .map(|tag| Facet::from_text(tag).map(|_| tag.clone()).map_err(|e| e))
                    .collect();

                match validated_tags {
                    Ok(valid_list) => {
                        final_tags = valid_list;
                    }
                    Err(e) => {
                        eprintln!("Tag validation failed, ignoring all tags: {:#?}", e);
                    }
                }
            }
        }
    }

    let attachment_docs: Vec<TantivyDocument> = attachments
        .iter()
        .filter(|a| !a.inline || a.content_id.is_none())
        .map(|a| {
            let has_text = a.extracted_text.is_some();
            AttachmentModel {
                id: Uuid::new_v4().to_string(),
                envelope_id: envelope_id.clone(),
                account_id,
                account_email: None,
                mailbox_id,
                mailbox_name: None,
                subject: subject.clone(),
                content_hash: a.content_hash.clone(),
                from: from.clone(),
                date,
                ingest_at: now,
                size: a.size as u64,
                ext: a.get_extension(),
                category: a.get_category().to_string(),
                content_type: a.file_type.clone(),
                shard_id: 0,
                text: a.extracted_text.clone(),
                has_text,
                is_ocr: a.extracted_is_ocr,
                page_count: a.extracted_page_count.map(|n| n as u64),
                is_indexed: has_text,
                is_message: a.is_message,
                name: a.filename.clone(),
                tags: None,
                auto_tags: None,
            }
        })
        .map(|a| a.into_document())
        .collect();

    let envelope = Envelope {
        id: envelope_id.clone(),
        message_id,
        account_id,
        mailbox_id,
        uid,
        subject,
        preview,
        from,
        to,
        cc,
        bcc,
        date,
        internal_date,
        ingest_at: now,
        size,
        thread_id,
        attachment_count,
        regular_attachment_count: attachment_docs.len(),
        tags: (!final_tags.is_empty()).then_some(final_tags),
        account_email: None,
        mailbox_name: None,
        content_hash: email_content_hash.clone(),
        account_name: None,
    };
    // 'attachments' contains both regular and inline attachments
    let ea = EnvelopeWithAttachments {
        envelope,
        attachments: Some(attachments),
    };
    let doc = ea.to_document(&body_text, if durable { UIDONLY_SHARD_ID } else { 0 })?;
    tracing::debug!(
        "[account {}][mailbox {}] extract: uid={} msg_id={} content_hash={}",
        account_id,
        mailbox_id,
        uid,
        &ea.envelope.message_id,
        &ea.envelope.content_hash,
    );
    if durable {
        BLOB_MANAGER.store_durable(detached_email).await?;
        let commit_result = async {
            check_uidonly_projection_cancelled(shutdown)?;
            ATTACHMENT_MANAGER.commit_documents(attachment_docs).await?;
            check_uidonly_projection_cancelled(shutdown)?;
            #[cfg(test)]
            if FAIL_UIDONLY_AFTER_ATTACHMENTS.load(Ordering::Acquire) {
                return Err(raise_error!(
                    "synthetic UIDONLY envelope commit failure".into(),
                    ErrorCode::InternalError
                ));
            }
            ENVELOPE_MANAGER.commit_document(doc).await?;
            check_uidonly_projection_cancelled(shutdown)
        }
        .await;
        if let Err(error) = commit_result {
            rollback_failed_uidonly_projection(
                account_id,
                &envelope_id,
                &email_content_hash,
                ea.attachments.as_deref().unwrap_or_default(),
            )
            .await?;
            return Err(error);
        }
    } else {
        BLOB_MANAGER.queue(detached_email).await;
        ENVELOPE_MANAGER.queue(doc).await;
        for doc in attachment_docs {
            ATTACHMENT_MANAGER.queue(doc).await;
        }
    }
    DEDUP_CACHE.insert(account_id, mailbox_id, &email_content_hash);
    Ok(Some(CanonicalProjection {
        envelope_id,
        content_hash: email_content_hash,
        created: true,
    }))
}

fn normalize_whitespace(input: &str, max_output_bytes: Option<usize>) -> String {
    let ceiling = max_output_bytes.unwrap_or(usize::MAX);
    let mut output = String::with_capacity(input.len().min(ceiling));
    for word in input.split_whitespace() {
        let separator = usize::from(!output.is_empty());
        if output
            .len()
            .checked_add(separator)
            .and_then(|len| len.checked_add(word.len()))
            .is_none_or(|len| len > ceiling)
        {
            break;
        }
        if separator == 1 {
            output.push(' ');
        }
        output.push_str(word);
    }
    output
}

#[allow(clippy::too_many_arguments)]
async fn project_unparseable_uidonly(
    body: &[u8],
    uid: u32,
    size: u32,
    internal_date: i64,
    account_id: u64,
    mailbox_id: u64,
    envelope_id: String,
    shutdown: Option<&CancellationToken>,
) -> BichonResult<Option<CanonicalProjection>> {
    check_uidonly_projection_cancelled(shutdown)?;
    let content_hash = compute_content_hash(body);
    let envelope = Envelope {
        id: envelope_id.clone(),
        message_id: generate_message_id(),
        account_id,
        mailbox_id,
        uid,
        subject: String::new(),
        preview: String::new(),
        from: "unknown".into(),
        to: Vec::new(),
        cc: Vec::new(),
        bcc: Vec::new(),
        date: 0,
        internal_date,
        ingest_at: utc_now!(),
        size,
        thread_id: hex_hash(&format!(
            "uidonly-unparseable-{account_id}-{mailbox_id}-{uid}"
        )),
        attachment_count: 0,
        regular_attachment_count: 0,
        tags: None,
        account_email: None,
        mailbox_name: None,
        content_hash: content_hash.clone(),
        account_name: None,
    };
    let doc = EnvelopeWithAttachments {
        envelope,
        attachments: Some(Vec::new()),
    }
    .to_document("", UIDONLY_SHARD_ID)?;
    BLOB_MANAGER
        .store_durable(DetachedEmail {
            email: (
                uidonly_exact_raw_blob_key(&content_hash),
                Bytes::copy_from_slice(body),
            ),
            attachments: Some(Vec::new()),
        })
        .await?;
    let commit_result = async {
        check_uidonly_projection_cancelled(shutdown)?;
        ENVELOPE_MANAGER.commit_document(doc).await?;
        check_uidonly_projection_cancelled(shutdown)
    }
    .await;
    if let Err(error) = commit_result {
        rollback_failed_uidonly_projection(account_id, &envelope_id, &content_hash, &[]).await?;
        return Err(error);
    }
    DEDUP_CACHE.insert(account_id, mailbox_id, &content_hash);
    Ok(Some(CanonicalProjection {
        envelope_id,
        content_hash,
        created: true,
    }))
}

fn check_uidonly_projection_cancelled(shutdown: Option<&CancellationToken>) -> BichonResult<()> {
    if shutdown.is_some_and(CancellationToken::is_cancelled) {
        Err(raise_error!(
            "UIDONLY canonical projection cancelled".into(),
            ErrorCode::InternalError
        ))
    } else {
        Ok(())
    }
}

async fn rollback_failed_uidonly_projection(
    account_id: u64,
    envelope_id: &str,
    email_content_hash: &str,
    attachments: &[AttachmentInfo],
) -> BichonResult<()> {
    let mut attachment_hashes: std::collections::HashSet<UidOnlyAttachmentBlobKey> = attachments
        .iter()
        .filter_map(|attachment| {
            let key = UidOnlyAttachmentBlobKey::from_storage_key(&attachment.content_hash);
            if key.is_none() {
                tracing::warn!(
                    envelope_id,
                    "refusing to delete a non-UIDONLY attachment key during projection rollback"
                );
            }
            key
        })
        .collect();
    let mut cleanup_errors = Vec::new();
    match ATTACHMENT_MANAGER
        .rollback_documents(account_id, envelope_id)
        .await
    {
        Ok(indexed_hashes) => attachment_hashes.extend(
            indexed_hashes
                .iter()
                .filter_map(|hash| UidOnlyAttachmentBlobKey::from_storage_key(hash)),
        ),
        Err(error) => cleanup_errors.push(error.to_string()),
    }
    if let Err(error) = ENVELOPE_MANAGER
        .rollback_uidonly_projection(
            account_id,
            envelope_id,
            email_content_hash.to_string(),
            attachment_hashes,
        )
        .await
    {
        cleanup_errors.push(error.to_string());
    }
    if cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(raise_error!(
            format!(
                "UIDONLY canonical rollback failed: {}",
                cleanup_errors.join("; ")
            ),
            ErrorCode::InternalError
        ))
    }
}

pub(crate) async fn rollback_uidonly_message(
    account_id: u64,
    envelope_id: &str,
    email_content_hash: &str,
    raw: Option<&[u8]>,
) -> BichonResult<()> {
    let mut cleanup_errors = Vec::new();
    let mut attachment_hashes: std::collections::HashSet<UidOnlyAttachmentBlobKey> = raw
        .and_then(|body| {
            MessageParser::new()
                .parse(body)
                .map(|message| (body, message))
        })
        .map(|(body, message)| {
            message
                .attachments()
                .map(|attachment| {
                    let storage_key = uidonly_attachment_storage_hash(
                        body,
                        attachment.raw_body_offset() as usize,
                        attachment.raw_end_offset() as usize,
                        attachment.contents(),
                    );
                    UidOnlyAttachmentBlobKey::from_storage_key(&storage_key)
                        .expect("UIDONLY attachment derivation must produce a namespaced key")
                })
                .collect()
        })
        .unwrap_or_default();
    match ATTACHMENT_MANAGER
        .rollback_documents(account_id, envelope_id)
        .await
    {
        Ok(hashes) => attachment_hashes.extend(
            hashes
                .iter()
                .filter_map(|hash| UidOnlyAttachmentBlobKey::from_storage_key(hash)),
        ),
        Err(error) => {
            cleanup_errors.push(error.to_string());
        }
    }
    if let Err(error) = ENVELOPE_MANAGER
        .rollback_uidonly_projection(
            account_id,
            envelope_id,
            email_content_hash.to_string(),
            attachment_hashes,
        )
        .await
    {
        cleanup_errors.push(error.to_string());
    }
    if cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(raise_error!(
            format!(
                "UIDONLY canonical rollback failed: {}",
                cleanup_errors.join("; ")
            ),
            ErrorCode::InternalError
        ))
    }
}

pub fn extract_envelope_from_nested_message(
    message: Message<'_>,
    account_id: u64,
) -> BichonResult<Envelope> {
    let text = if let Some(text) = message.body_text(0).map(|cow| cow.into_owned()) {
        text
    } else if let Some(html) = message.body_html(0).map(|cow| cow.into_owned()) {
        extract_text(html)
    } else {
        String::new()
    };

    let message_id = message
        .message_id()
        .map(String::from)
        .unwrap_or_else(generate_message_id);

    let in_reply_to = message.in_reply_to().as_text().map(String::from);
    let references = extract_references(&message);
    let thread_id = compute_thread_id(in_reply_to, references, &message_id);

    let mut subject = message.subject().map(String::from).unwrap_or_default();
    if subject.contains('\u{FFFD}') {
        subject = normalize_subject(message.header_raw(HeaderName::Subject));
    }

    let date = message.date().map(|d| d.to_timestamp() * 1000).unwrap_or(0);

    let parse_addrs = |addrs: Option<&Address<'_>>| {
        addrs
            .map(|addr| {
                AddrVec::from(addr)
                    .0
                    .into_iter()
                    .filter_map(|a| a.address)
                    .collect()
            })
            .unwrap_or_default()
    };

    let bcc = parse_addrs(message.bcc());
    let cc = parse_addrs(message.cc());
    let to = parse_addrs(message.to());

    let from = message
        .from()
        .and_then(|addr| AddrVec::from(addr).0.into_iter().next())
        .and_then(|add| add.address)
        .unwrap_or_else(|| "unknown".to_string());

    let envelope = Envelope {
        id: Default::default(),
        message_id,
        account_id,
        mailbox_id: Default::default(),
        uid: Default::default(),
        subject,
        preview: text,
        from,
        to,
        cc,
        bcc,
        date,
        internal_date: Default::default(),
        ingest_at: Default::default(),
        size: Default::default(),
        thread_id,
        attachment_count: Default::default(),
        regular_attachment_count: Default::default(),
        tags: Default::default(),
        account_email: Default::default(),
        account_name: Default::default(),
        mailbox_name: Default::default(),
        content_hash: Default::default(),
    };

    Ok(envelope)
}

pub fn compute_thread_id(
    in_reply_to: Option<String>,
    references: Option<Vec<String>>,
    message_id: &str,
) -> String {
    if in_reply_to.is_some() && references.as_ref().map_or(false, |r| !r.is_empty()) {
        return hex_hash(&references.as_ref().unwrap()[0]);
    }
    hex_hash(message_id)
}

pub fn generate_message_id() -> String {
    let ts = utc_now!();
    let pid = std::process::id();
    format!("<{:016x}.{}.{}@{}>", id!(128), ts, pid, "bichon")
}

pub fn extract_references(message: &Message<'_>) -> Option<Vec<String>> {
    match message.references() {
        mail_parser::HeaderValue::Text(cow) => Some(vec![cow.to_string()]),
        mail_parser::HeaderValue::TextList(vec) => {
            Some(vec.iter().map(|cow| cow.to_string()).collect())
        }
        _ => None,
    }
}

pub(crate) async fn prepare_detached_attachments(
    original_body: &[u8],
    message: &Message<'_>,
    eml_content_hash: &str,
    account_id: u64,
    mailbox_id: u64,
    extraction_budget: Option<usize>,
) -> BichonResult<(Vec<AttachmentInfo>, DetachedEmail)> {
    let rules = if account_id > 0 {
        AccountModel::get(account_id)
            .ok()
            .and_then(|a| a.extraction_rules)
    } else {
        None
    };

    let mailbox_name = match rules.as_ref().map(|r| !r.folders.is_empty()) {
        Some(true) => MailBox::get(mailbox_id).ok().map(|mb| mb.name),
        _ => None,
    };

    let sender = message
        .from()
        .and_then(|addr| AddrVec::from(addr).0.into_iter().next())
        .and_then(|add| add.address);

    let exact_raw = extraction_budget.is_some();
    let mut stripped_eml = if exact_raw {
        Vec::new()
    } else {
        original_body.to_vec()
    };
    let mut attachment_infos = Vec::new();
    // Step 1: Collect and sort attachment ranges in reverse to maintain offset integrity
    let mut ranges: Vec<_> = message
        .attachments()
        .map(|att| {
            (
                att.raw_body_offset() as usize,
                att.raw_end_offset() as usize,
                att,
            )
        })
        .collect();

    ranges.sort_by(|a, b| b.0.cmp(&a.0));
    let mut attachments = Vec::with_capacity(ranges.len());

    // Collect candidates for text extraction (non-inline, known document types).
    struct TextCandidate {
        content_hash: String,
        file_type: String,
        ext: String,
        bytes: Vec<u8>,
    }
    let mut text_candidates: Vec<TextCandidate> = Vec::new();
    let mut attachment_copy_bytes = 0usize;
    let mut extraction_input_bytes = 0usize;

    for (raw_start, raw_end, att) in ranges {
        // mail-parser may report attachment offsets past the body end for
        // malformed messages; clamp the range to avoid a slice panic.
        let body_len = original_body.len();
        let raw_start = raw_start.min(body_len);
        let raw_end = raw_end.min(body_len);
        let range_valid = raw_start < raw_end;

        // Legacy storage keys decoded attachment content. UIDONLY stores the
        // exact encoded MIME slice and therefore keys that exact slice. Two
        // legal encodings of the same decoded bytes must not alias, otherwise
        // deduplication can substitute the wrong wire representation and make
        // exact RFC822 readback impossible.
        let content_hash = if extraction_budget.is_some() {
            uidonly_attachment_storage_hash(
                original_body,
                att.raw_body_offset() as usize,
                att.raw_end_offset() as usize,
                att.contents(),
            )
        } else {
            compute_content_hash(att.contents())
        };

        if range_valid {
            let raw_bytes = &original_body[raw_start..raw_end];
            attachment_copy_bytes = attachment_copy_bytes
                .checked_add(raw_bytes.len())
                .ok_or_else(|| {
                    raise_error!(
                        "attachment working-set size overflow".into(),
                        ErrorCode::PayloadTooLarge
                    )
                })?;
            if extraction_budget.is_some() && attachment_copy_bytes > original_body.len() {
                return Err(raise_error!(
                    "overlapping MIME attachment ranges exceed the UIDONLY memory ceiling".into(),
                    ErrorCode::PayloadTooLarge
                ));
            }
            // The actual content stored in the blob is the raw undecoded data.
            attachments.push((content_hash.clone(), Bytes::copy_from_slice(raw_bytes)));

            // Replace raw attachment content with a hash-based placeholder
            if !exact_raw {
                let placeholder = format!("<<BICHON_DETACH_HASH:{}>>", &content_hash);
                stripped_eml.splice(raw_start..raw_end, placeholder.as_bytes().iter().cloned());
            }
        } else {
            // Invalid ranges cannot be sliced. UIDONLY still retains the
            // complete raw message independently and stores the decoded
            // attachment bytes under their matching fallback digest so
            // attachment readback remains verifiable. Keep the legacy
            // zero-length behavior unchanged.
            let bytes = if exact_raw {
                Bytes::copy_from_slice(att.contents())
            } else {
                Bytes::new()
            };
            attachments.push((content_hash.clone(), bytes));
        }

        let inline = att
            .content_disposition()
            .map(|d| d.is_inline())
            .unwrap_or_else(|| att.content_id().is_some());
        let file_type = att
            .content_type()
            .map(|ct| {
                format!(
                    "{}/{}",
                    ct.c_type.as_ref(),
                    ct.c_subtype.as_deref().unwrap_or("")
                )
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let has_cid = att.content_id().is_some();
        let att_name = att.attachment_name().map(|n| n.to_string());
        let ext = att_name
            .as_deref()
            .and_then(|n| {
                std::path::Path::new(n)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.to_ascii_lowercase())
            })
            .unwrap_or_default();

        let should_extract = rules.as_ref().map_or(true, |r| {
            r.should_extract(
                &ext,
                mailbox_name.as_deref(),
                att_name.as_deref(),
                sender.as_deref(),
            )
        });

        if !inline || !has_cid {
            let decoded_len = att.contents().len();
            if should_extract
                && extraction_budget != Some(0)
                && decoded_len <= crate::ext::text_extractor::MAX_EXTRACT_BYTES
                && crate::ext::text_extractor::should_try_extract(&file_type, &ext)
                && extraction_budget.is_none_or(|budget| {
                    extraction_input_bytes
                        .checked_add(decoded_len)
                        .is_some_and(|total| total <= budget)
                })
            {
                extraction_input_bytes += decoded_len;
                text_candidates.push(TextCandidate {
                    content_hash: content_hash.clone(),
                    file_type: file_type.clone(),
                    ext: ext.clone(),
                    bytes: att.contents().to_vec(),
                });
            }
        }

        let info = AttachmentInfo {
            filename: att.attachment_name().map(|n| n.to_string()),
            size: att.contents().len(),
            inline,
            file_type,
            content_id: att.content_id().map(|id| id.to_string()),
            content_hash: content_hash.clone(),
            is_message: att.is_message(),
            extracted_text: None,
            extracted_page_count: None,
            extracted_is_ocr: false,
        };

        attachment_infos.push(info);
    }

    // Run text extraction in a single spawn_blocking batch.
    if !text_candidates.is_empty() {
        if let Ok(mut extracted_map) = tokio::task::spawn_blocking(move || {
            let mut map: std::collections::HashMap<String, (String, Option<u32>, bool)> =
                std::collections::HashMap::new();
            let mut extracted_bytes = 0usize;
            for c in text_candidates {
                if let Some(r) =
                    crate::ext::text_extractor::extract_text(&c.file_type, &c.ext, &c.bytes)
                {
                    if extraction_budget.is_none_or(|budget| {
                        extracted_bytes
                            .checked_add(r.text.len())
                            .is_some_and(|total| total <= budget)
                    }) {
                        extracted_bytes += r.text.len();
                        map.insert(c.content_hash, (r.text, r.page_count, r.is_ocr));
                    }
                }
            }
            map
        })
        .await
        {
            for info in &mut attachment_infos {
                if let Some((text, pages, is_ocr)) = extracted_map.remove(&info.content_hash) {
                    info.extracted_text = Some(text);
                    info.extracted_page_count = pages;
                    info.extracted_is_ocr = is_ocr;
                }
            }
        }
    }
    if extraction_budget.is_some()
        && stripped_eml.len() > original_body.len().saturating_add(32 * 1024 * 1024)
    {
        return Err(raise_error!(
            "detached UIDONLY message exceeds the projection memory ceiling".into(),
            ErrorCode::PayloadTooLarge
        ));
    }
    Ok((
        attachment_infos,
        DetachedEmail {
            // UIDONLY keeps the complete original message under its content
            // hash. Detached attachment blobs remain available for canonical
            // attachment APIs, while exact-message readback never depends on
            // ambiguous placeholder substitution. The legacy path retains
            // its existing detached representation.
            email: (
                if exact_raw {
                    uidonly_exact_raw_blob_key(eml_content_hash)
                } else {
                    eml_content_hash.to_string()
                },
                if exact_raw {
                    Bytes::copy_from_slice(original_body)
                } else {
                    Bytes::from(stripped_eml)
                },
            ),
            attachments: Some(attachments),
        },
    ))
}

fn uidonly_attachment_storage_hash(
    original_body: &[u8],
    raw_start: usize,
    raw_end: usize,
    decoded: &[u8],
) -> String {
    let content_hash = if raw_start < raw_end && raw_end <= original_body.len() {
        compute_content_hash(&original_body[raw_start..raw_end])
    } else {
        // Malformed offsets are not safe to slice. The complete UIDONLY raw
        // message is still retained independently, so this fallback cannot
        // compromise exact RFC822 readback.
        compute_content_hash(decoded)
    };
    uidonly_attachment_blob_key(&content_hash)
}

pub async fn detach_and_store_attachments(
    original_body: &[u8],
    message: &Message<'_>,
    eml_content_hash: &str,
    account_id: u64,
    mailbox_id: u64,
) -> Vec<AttachmentInfo> {
    let (attachment_infos, detached_email) = prepare_detached_attachments(
        original_body,
        message,
        eml_content_hash,
        account_id,
        mailbox_id,
        None,
    )
    .await
    .expect("legacy attachment preparation remains infallible without UIDONLY budgets");
    BLOB_MANAGER.queue(detached_email).await;
    attachment_infos
}

pub fn reattach_eml_content(
    account_id: u64,
    envelope_id: String,
) -> BichonResult<(Envelope, Bytes)> {
    let e = ENVELOPE_MANAGER
        .get_envelope_by_id(account_id, &envelope_id)?
        .ok_or_else(|| {
            raise_error!(
                format!(
                    "Envelope not found: account_id={} envelope_id={}",
                    account_id, &envelope_id
                ),
                ErrorCode::ResourceNotFound
            )
        })?;

    let restored_eml = BLOB_MANAGER
        .get_canonical_email(&e.envelope.content_hash)?
        .ok_or_else(|| {
            raise_error!(
                format!(
                "Original email content not found: account_id={} envelope_id={} content_hash={}",
                account_id, &envelope_id, &e.envelope.content_hash
            ),
                ErrorCode::ResourceNotFound
            )
        })?;

    if compute_content_hash(&restored_eml) == e.envelope.content_hash {
        return Ok((e.envelope, restored_eml));
    }

    if !e.envelope.has_any_attachments() {
        return Ok((e.envelope, restored_eml));
    }

    let mut restored_eml = restored_eml.to_vec();
    let actual_count = e.attachments.as_ref().map(|a| a.len()).unwrap_or(0);
    if e.envelope.attachment_count != actual_count {
        return Err(raise_error!(
            format!(
                "Consistency check failed: envelope.attachment_count ({}) does not match attachments.len ({})",
                e.envelope.attachment_count,
                actual_count
            ),
            ErrorCode::InternalError
        ));
    }

    let mut tasks = Vec::new();
    for detail in e.attachments.unwrap() {
        let placeholder_str = format!("<<BICHON_DETACH_HASH:{}>>", &detail.content_hash);
        let pattern = placeholder_str.as_bytes();
        let pattern_len = pattern.len();

        let mut search_cursor = 0;
        while let Some(pos) = restored_eml[search_cursor..]
            .windows(pattern_len)
            .position(|window| window == pattern)
        {
            let absolute_start = search_cursor + pos;
            let absolute_end = absolute_start + pattern_len;

            tasks.push((absolute_start, absolute_end, detail.content_hash.clone()));
            search_cursor = absolute_end;
        }
    }

    tasks.sort_by(|a, b| b.0.cmp(&a.0));

    for (start, end, hash) in tasks {
        if let Some(original_data) = BLOB_MANAGER.get_attachment(&hash)? {
            restored_eml.splice(start..end, original_data.iter().cloned());
        } else {
            error!("[ERROR] Missing attachment blob for hash: {}", hash);
        }
    }

    Ok((e.envelope, Bytes::from(restored_eml)))
}

/// Returns the raw EML for an indexed message, self-healing a missing content blob.
///
/// Behaves like [`reattach_eml_content`], but when the message's content blob is
/// absent from the blob store it fetches that single message on demand from the
/// IMAP server (`UID FETCH <uid> (BODY.PEEK[])`), persists it for future requests,
/// and returns it. If the on-demand fetch itself fails, the original "content not
/// found" error from [`reattach_eml_content`] is surfaced unchanged so the caller
/// still produces its 404.
pub async fn reattach_eml_content_self_healing(
    account_id: u64,
    envelope_id: String,
) -> BichonResult<(Envelope, Bytes)> {
    let envelope = ENVELOPE_MANAGER
        .get_envelope_by_id(account_id, &envelope_id)?
        .ok_or_else(|| {
            raise_error!(
                format!(
                    "Envelope not found: account_id={} envelope_id={}",
                    account_id, &envelope_id
                ),
                ErrorCode::ResourceNotFound
            )
        })?
        .envelope;

    // Fast path: the content blob is present, reuse the regular reattach logic.
    if BLOB_MANAGER
        .get_canonical_email(&envelope.content_hash)?
        .is_some()
    {
        return reattach_eml_content(account_id, envelope_id);
    }

    // The blob is missing. Try to recover it directly from the IMAP server.
    match recover_message_blob(&envelope).await {
        Ok(raw_body) => {
            tracing::info!(
                account_id,
                envelope_id = %envelope_id,
                uid = envelope.uid,
                "Self-healed missing email content blob via on-demand IMAP fetch"
            );
            Ok((envelope, raw_body))
        }
        Err(e) => {
            tracing::warn!(
                account_id,
                envelope_id = %envelope_id,
                uid = envelope.uid,
                error = %e,
                "On-demand IMAP fetch for missing content blob failed; returning not-found"
            );
            Err(e)
        }
    }
}

/// Fetches one message from IMAP and re-stores its detached blob.
///
/// On success the freshly fetched raw RFC822 body is returned; it is also queued
/// (in detached form) into the blob store so subsequent requests hit the cache.
/// Fails if the message cannot be fetched, or if the fetched bytes do not match
/// the archived `content_hash` (the server-side message no longer matches what
/// Bichon archived, so it cannot be treated as a recovery of that blob).
async fn recover_message_blob(envelope: &Envelope) -> BichonResult<Bytes> {
    let mailbox =
        MailBox::find_mailbox(envelope.account_id, envelope.mailbox_id)?.ok_or_else(|| {
            raise_error!(
                format!(
                    "Mailbox not found: account_id={} mailbox_id={}",
                    envelope.account_id, envelope.mailbox_id
                ),
                ErrorCode::ResourceNotFound
            )
        })?;

    let mut session = ImapExecutor::create_connection(envelope.account_id).await?;
    let result = ImapExecutor::fetch_single_message_body(
        &mut session,
        &mailbox.encoded_name(),
        envelope.uid,
    )
    .await;
    session.logout().await.ok();
    let raw_body = result?;

    let fetched_hash = compute_content_hash(&raw_body);
    if fetched_hash != envelope.content_hash {
        return Err(raise_error!(
            format!(
                "Fetched message does not match archived content: expected content_hash={} got={}",
                envelope.content_hash, fetched_hash
            ),
            ErrorCode::ImapUnexpectedResult
        ));
    }

    // Re-create the detached blob (stripped EML + attachments) so the missing
    // blob is repopulated for future requests. The detached EML is queued under
    // `fetched_hash`, which equals `envelope.content_hash`.
    let message = MessageParser::new()
        .parse(raw_body.as_slice())
        .ok_or_else(|| {
            raise_error!(
                "Failed to parse fetched email content".into(),
                ErrorCode::InternalError
            )
        })?;
    detach_and_store_attachments(
        &raw_body,
        &message,
        &fetched_hash,
        envelope.account_id,
        envelope.mailbox_id,
    )
    .await;

    Ok(Bytes::from(raw_body))
}

#[cfg(test)]
mod test {
    use super::prepare_detached_attachments;
    use crate::store::blob::UidOnlyAttachmentBlobKey;
    use crate::utils::compute_content_hash;
    use html2text::config;
    use mail_parser::MessageParser;

    #[test]
    fn test_various_html_with_overflow_enabled() {
        let cases = [
            ("<p>Hello World</p>", "Simple paragraph"),
            ("<h1>Title</h1><p>Content</p>", "Heading + paragraph"),
            ("<ul><li>Item1</li><li>Item2</li></ul>", "Unordered list"),
            (
                "<strong>Bold</strong> and <em>italic</em>",
                "Inline formatting",
            ),
            (
                "<div><span>Nested</span> elements</div>",
                "Nested inline elements inside block",
            ),
            (
                "<table><tr><td>A</td><td>B</td></tr></table>",
                "Simple table",
            ),
            (
                "<pre>  preformatted text\n  line2</pre>",
                "Preformatted block",
            ),
            ("😃 emoji test", "Wide emoji"),
            ("<a href=\"#\">link</a>", "Anchor tag"),
            (
                "<blockquote><p>Quoted text</p></blockquote>",
                "Blockquote with paragraph",
            ),
        ];

        for (html, desc) in cases {
            let result = config::plain()
                .allow_width_overflow()
                .string_from_read(html.as_bytes(), 100);

            match result {
                Ok(output) => {
                    println!("✓ Rendered ({}) =>\n{}", desc, output);
                }
                Err(e) => panic!("Unexpected error for {}: {:?}", desc, e),
            }
        }
    }

    /// Verifies that [`super::detach_and_store_attachments`] does not panic
    /// when mail-parser reports attachment offsets past the raw body length.
    ///
    /// Regression test for: "range end index X out of range for slice of
    /// length Y" panic caused by a malformed email whose attachment
    /// `raw_end_offset` exceeded the actual body size.
    #[tokio::test]
    async fn detach_attachments_bounds_check() {
        let raw = concat!(
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Test\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"bnd\"\r\n",
            "\r\n",
            "--bnd\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Hello\r\n",
            "--bnd\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment; filename=\"test.bin\"\r\n",
            "\r\n",
            "AAAAABBBBBCCCCCDDDDDEEEEEAAAAABBBBBCCCCCDDDDDEEEEE\r\n",
            "--bnd--\r\n",
        )
        .as_bytes()
        .to_vec();

        let message = mail_parser::MessageParser::new()
            .parse(&raw)
            .expect("parse valid MIME message");
        assert_eq!(message.attachment_count(), 1);

        // Truncate the raw body so the attachment's raw_end_offset lies
        // past the body end — exactly the scenario reported by users.
        let truncated = &raw[..raw.len() - 20];
        assert!(truncated.len() < raw.len());

        // Must not panic.
        let infos =
            super::detach_and_store_attachments(truncated, &message, "test_content_hash", 0, 0)
                .await;

        // The attachment count must still match so the consistency check
        // in reattach_eml_content doesn't fail later.
        assert_eq!(infos.len(), 1);
    }

    #[tokio::test]
    async fn uidonly_attachment_keys_preserve_distinct_wire_encodings() {
        fn fixture(encoding: &str, payload: &str) -> Vec<u8> {
            format!(
                "From: sender@example.invalid\r\n\
                 To: archive@example.invalid\r\n\
                 MIME-Version: 1.0\r\n\
                 Content-Type: multipart/mixed; boundary=b\r\n\
                 \r\n\
                 --b\r\n\
                 Content-Type: text/plain\r\n\
                 \r\n\
                 body\r\n\
                 --b\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Disposition: attachment; filename=a.bin\r\n\
                 Content-Transfer-Encoding: {encoding}\r\n\
                 \r\n\
                 {payload}\r\n\
                 --b--\r\n"
            )
            .into_bytes()
        }

        let base64 = fixture("base64", "YWJj");
        let quoted_printable = fixture("quoted-printable", "abc");
        let base64_message = MessageParser::new().parse(&base64).unwrap();
        let quoted_message = MessageParser::new().parse(&quoted_printable).unwrap();
        assert_eq!(
            base64_message.attachments().next().unwrap().contents(),
            quoted_message.attachments().next().unwrap().contents()
        );

        let (base64_info, base64_detached) = prepare_detached_attachments(
            &base64,
            &base64_message,
            &compute_content_hash(&base64),
            0,
            0,
            Some(0),
        )
        .await
        .unwrap();
        let (quoted_info, quoted_detached) = prepare_detached_attachments(
            &quoted_printable,
            &quoted_message,
            &compute_content_hash(&quoted_printable),
            0,
            0,
            Some(0),
        )
        .await
        .unwrap();
        assert_ne!(base64_info[0].content_hash, quoted_info[0].content_hash);
        assert!(UidOnlyAttachmentBlobKey::from_storage_key(&base64_info[0].content_hash).is_some());
        assert!(UidOnlyAttachmentBlobKey::from_storage_key(&quoted_info[0].content_hash).is_some());
        assert!(
            UidOnlyAttachmentBlobKey::from_storage_key(&compute_content_hash(b"abc")).is_none(),
            "ordinary legacy attachment hashes must be rejected by UIDONLY orphan cleanup"
        );
        assert_eq!(base64_detached.email.1.as_ref(), base64);
        assert_eq!(quoted_detached.email.1.as_ref(), quoted_printable);
        assert_ne!(base64_detached.email.0, compute_content_hash(&base64));
        assert_ne!(
            quoted_detached.email.0,
            compute_content_hash(&quoted_printable)
        );
    }
}
