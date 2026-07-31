# Bichon UIDONLY protocol foundation

This internal workspace crate contains Bichon's no-fork compatibility layer for
RFC 9586 UIDONLY responses. It is deliberately separate from account routing,
archive storage, and search projection so the protocol boundary can be reviewed
and qualified independently.

The crate:

- wraps the final cleartext/TLS stream before `async_imap::Client` is created;
- passes bytes through unchanged until `ENABLE UIDONLY` is confirmed;
- translates only top-level `UIDFETCH` labels outside literals;
- attaches bounded, ordered provenance to every post-enable response;
- moves an enabled connection into a private low-level-only typestate;
- exposes typed `EXAMINE`, bounded PARTIAL inventory, exact-UID body chunk,
  `NOOP`, and `LOGOUT` operations;
- rejects raw `FETCH`, sequence `EXPUNGE`, UID mismatches, malformed literals,
  unexpected tags, cancellation, timeouts, EOF, and resource overruns; and
- provides a two-phase sparse inventory planner so callers persist a validated
  page before advancing its cursor.

It uses Bichon's existing unmodified `async-imap` source and the same released
`imap-proto` 0.16.7 package. It does not patch, vendor, or fork either
dependency, and it never enables IMAP `COMPRESS`.

## Production integration

Bichon's full-mailbox archive path probes capabilities on an ordinary bounded
connection. Servers advertising both UIDONLY and PARTIAL are moved to a fresh
connection, authenticated again, re-probed, and enabled before any mailbox is
selected. Servers without a limited acquisition extension keep the legacy IMAP
path. UIDONLY without PARTIAL, a standalone MESSAGELIMIT, or an invalid
MESSAGELIMIT fails closed because Bichon cannot claim a complete snapshot.

The integrated acquisition path fixes a mailbox snapshot at UIDNEXT - 1,
inventories sparse UID ranges with PARTIAL, and fetches each exact UID body
chunk with a `PARTIAL 1:1` result bound. It records VANISHED evidence. Its
durable identity is endpoint, account, canonical mailbox, UIDVALIDITY, and UID.
Per-UID ledger transitions are fsynced around staging and canonical projection,
and a checkpoint is written only after every canonical blob, envelope, and
attachment record passes exact readback verification. Exact RFC822 values and
encoded attachment slices use UIDONLY namespaced blob keys, avoiding collisions
with the legacy detached-message representation; malformed or empty stored
literals receive a minimal fallback envelope without changing their raw bytes.
A tagged-OK body miss is not treated as proof of deletion: Bichon performs an
exact one-UID inventory request and records absence only after that request
completes empty. Reconnects start a fresh bounded connection, re-enable UIDONLY,
reselect the mailbox, and refuse a changed UIDVALIDITY epoch or a changed
connection identity (endpoint, authenticated principal, encryption, proxy,
authentication mode, or dangerous-TLS setting). Empty full-mailbox folders use
the same capability gate and EXAMINE proof; LIST/STATUS zero counts cannot
bypass UIDONLY activation.

The ledger lives below Bichon's storage directory in `uidonly-acquisition`.
Account deletion, mailbox deletion, and full mailbox rebuild remove only the
matching ledger state. New state directories carry account and hashed mailbox
markers, so lifecycle cleanup never has to parse an unrelated ledger; valid
unmarked development-state ledgers retain a compatibility fallback, while a
corrupt unmarked directory is retained with a warning for manual review. The
canonical schema is unchanged; deterministic
UIDVALIDITY-scoped envelope IDs preserve distinct logical messages even when
their raw bodies are identical.

## Safety and operations

`AdapterLimits` bounds input, control lines, literals, complete responses, and
the ordered provenance queue. `CommandLimits` independently bounds time,
response count, cumulative wire bytes, unsolicited events, inventory pages,
body chunks, and mailbox command bytes. Protocol ambiguity, cancellation, EOF,
or any exceeded ceiling consumes and drops the typed session; it never falls
back to sequence-number behavior. Message literals and credentials are not
logged by this crate.

There is no provider-specific gate or configuration key. Routing depends only
on the server's authenticated capabilities and exact UIDONLY activation.
Activation ambiguity, partial extension support, or an exceeded limit is an
explicit acquisition failure rather than a fallback that could claim
completeness.

The production defaults admit at most 1,000,000 inventory entries, 100 GiB of
actual body transfer, 512 MiB of serialized ledger state, 120 GiB of
UIDONLY-owned staging plus durable conservative canonical reservations, and six
hours including the global semaphore wait. The configured per-message ceiling
defaults to 100 MiB; body reads use exact chunks no larger than 1 MiB. The
body-transfer meter charges literal octets before tagged command completion,
so a truncated response remains charged across reconnect and retry. The
memory ceiling is shared by the durable inventory, the remote/local difference
vectors, and one projection: the effective per-message admission size therefore
falls as mailbox cardinality grows and can be lower than the protocol literal
ceiling. Projection moves ownership of the fetch buffer, uses a conservative
five-times-raw plus 64 MiB estimate, caps normalized searchable body text at 16
MiB, and rejects overlapping MIME ranges that would copy more than the raw
message. Optional attachment text/OCR extraction is skipped during UIDONLY
acquisition because its external extractors do not expose an enforceable
allocator budget; raw attachments and metadata remain archived. These are
explicit admission and pipeline bounds, not an operating-system allocator
quota.

Each created canonical projection retains a conservative disk reservation in
the checksummed ledger across restarts; reservations intentionally overcount
shared content-addressed blobs. Canonical write or readback failure leaves the
UID unresolved and prevents checkpoint success. Committed staging is reclaimed
per UID. Inventory uses a checksummed rolling
prefix manifest, checksummed metadata and entry records, bounded local reads,
and cancellation/runtime checks during restart scans. Inventory pages are
capped by both Bichon's configured batch size and MESSAGELIMIT. Acquisition is
sequential within a mailbox and remains subject to the global mailbox
semaphore.

UIDONLY exact-message and attachment keys have distinct embedded namespace
prefixes. Failed or cancelled projection rollback deletes only prefix-validated
UIDONLY blobs whose canonical reference count is zero. Normal account, mailbox,
message, and rebuild deletion reclaims exact raw and attachment values only
after the same committed reference-count barrier; shared content remains until
its final logical record is deleted.

A lifecycle read gate spans each production UIDONLY run through mailbox
checkpoint and progress persistence. Account, mailbox, message, and rebuild
cleanup take the write side before removing acquisition state, envelopes,
blobs, or attachment indexes, then use the canonical write lock in that fixed
order. Admission revalidates the persisted account and mailbox after acquiring
the gate, and later caller bookkeeping skips a mailbox deleted in the interim.
Account deletion also blocks new scheduled and manual task registration and
joins both task classes before cleanup. Rebuild releases both write guards
before starting reacquisition.

The UIDONLY typestate is read-only: it exposes EXAMINE, UID inventory, exact
UID body reads, NOOP, and LOGOUT, with no STORE, COPY, MOVE, APPEND, EXPUNGE,
or ordinary FETCH surface. Credentials and message literals are never logged.
Raw messages and attachments are written only to Bichon's configured local
storage and indexes. This change adds no telemetry, remote storage integration,
or mailbox mutation command.

## Qualification boundary

Capability routing is provider-neutral, but the motivating Yahoo path has only
been qualified with sanitized deterministic transcripts and disposable local
Cyrus 3.12.2—not against a live Yahoo account. A read-only live qualification
of the exact merged binary remains a separate, explicitly authorized release
gate. Accounts configured with date-based partial archive windows continue to
use Bichon's legacy date-filtered path rather than claiming a complete UIDONLY
snapshot.

The first UIDONLY run intentionally does not adopt legacy records that lack
per-record UIDVALIDITY provenance. It redownloads the fixed snapshot and writes
UIDVALIDITY-scoped UIDONLY records, so an upgraded archive can temporarily show
parallel legacy and UIDONLY search results and require corresponding storage.
The suite proves linear sparse diff and rolling-manifest behavior at large
logical cardinalities; it does not claim a timed one-million-message physical
mailbox qualification. That load qualification, like live Yahoo validation,
remains an operational release exercise rather than a completeness shortcut in
the code.

## Verification

The provider-offline suite runs with:

```sh
cargo test -p bichon-uidonly --offline --locked
cargo clippy -p bichon-uidonly --offline --locked --all-targets -- -D warnings
cargo tree -p bichon-uidonly --offline --locked -i imap-proto@0.16.7
cargo test -p bichon-core --lib --no-default-features --offline --locked \
  imap::uidonly_acquisition::tests -- --test-threads=1
crates/core/tests/cyrus/run.sh
```

Coverage includes exhaustive two-chunk splits with tiny output buffers, a
deterministic TCP fake server that asserts the complete probe, activation,
EXAMINE, PARTIAL inventory, exact BODY.PEEK, reconnect/re-enable, retry, and
LOGOUT command vectors; a Yahoo-like zero-message route; sparse inventory;
metadata corruption; restart; and adversarial attribution, literal, timeout,
cancellation, injection, cross-command VANISHED, and resource-limit cases. The
disposable pinned Cyrus test verifies exact raw acquisition through Bichon's
real canonical blob/index storage, restart revalidation without re-projection,
unchanged flags, an exhaustive read-only command allowlist, and staging cleanup.

## Rollback and downgrade

Do not run an older baseline binary against an archive containing committed
UIDONLY records. The older dedup identity is `(mailbox, content_hash)` and does
not preserve UIDVALIDITY-scoped logical records, so a downgrade can collapse
distinct messages with identical bodies. A safe rollback is either to stop
full-mailbox sync while retaining this change's shard-aware read/dedup support,
or to use a separately reviewed migration/export tool that validates and
removes UIDONLY records before installing the old binary. Unfinished ledger and
staging files may be removed only when no acquisition is active and only after
canonical state has been accounted for. There is no automatic safe downgrade.
