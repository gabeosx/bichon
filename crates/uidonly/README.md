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

## Scope boundary

This crate is a first stacked contribution, not production Yahoo support.
Bichon's current archive path does not yet provide the UIDVALIDITY-scoped
logical identity, per-component durable acknowledgements, or canonical raw
readback required to route Yahoo acquisition safely. Until those follow-up
storage and integration changes land, no account uses this crate and Bichon
must not claim a complete Yahoo export.

The remaining stacked contributions are intentionally explicit:

1. add UIDVALIDITY-scoped logical identity plus durable raw/blob/index
   acknowledgements and readback verification;
2. route only capability-qualified UIDONLY accounts through this adapter while
   preserving the ordinary IMAP path and prohibiting COMPRESS on this flow;
3. bind the inventory planner to durable checkpoints, VANISHED handling,
   mailbox reselection, and bounded reconnect/backoff; and
4. qualify the integrated acquisition/storage path against fake Yahoo and
   Cyrus before any production enablement.

## Safety and operations

`AdapterLimits` bounds input, control lines, literals, complete responses, and
the ordered provenance queue. `CommandLimits` independently bounds time,
response count, cumulative wire bytes, unsolicited events, inventory pages,
body chunks, and mailbox command bytes. Protocol ambiguity, cancellation, EOF,
or any exceeded ceiling consumes and drops the typed session; it never falls
back to sequence-number behavior. Message literals and credentials are not
logged by this crate.

There is intentionally no provider gate, configuration key, schema migration,
checkpoint, or account routing in this contribution. The future routing stack
must require confirmed UIDONLY capability and exact activation; absence or
failure must remain an explicit unsupported outcome rather than a completeness
claim.

## Verification

The provider-offline suite runs with:

```sh
cargo test -p bichon-uidonly --offline --locked
cargo clippy -p bichon-uidonly --offline --locked --all-targets -- -D warnings
cargo tree -p bichon-uidonly --offline --locked -i imap-proto@0.16.7
```

It includes exhaustive two-chunk splits with tiny output buffers, a
deterministic TCP fake server that checks exact command order, sparse planner
and durability-order tests, and adversarial attribution, literal, timeout,
cancellation, injection, VANISHED, and resource-limit cases. The retained POC
has separate fake-Yahoo and Cyrus evidence; an integrated Cyrus/storage test is
still required by follow-up 4 and is not claimed here.

Rollback for this contribution is removal of the workspace member; it changes
no schema, configuration, account behavior, or archive data.
