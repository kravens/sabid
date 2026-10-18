# Local patches to libwabisabi

1. Presentation-only client requests (`wabisabi_client_create_present_request`, `client.c`
   `internal_create_real(..., presentation_only)`): the upstream C client always requests two
   zero-padded credentials; Wasabi's output registration presents credentials and requests none
   (`WabiSabiClient.CreateRequest(credentialsToPresent)`, `Delta < 0`, three proofs). The upstream
   issuer already verifies such requests. Worth upstreaming to zkSNACKs/NWabiSabi.

## ffi.c: validation state of a presentation-only request (2026-10-18)

`write_validation_state` serialized all `WABISABI_CREDENTIAL_COUNT` requested slots, but a
presentation-only request (`n_requested = 0`, output registration) fills none, so it serialized an
uninitialized group element and secp256k1's illegal-argument callback aborted the daemon in a live
round. Slots at or beyond `n_requested` are now written as zeros and skipped when read, and the
`val` locals in the FFI entry points are zeroed.

## proof.c: proof counts checked against the statement (2026-10-18)

`wabisabi_verify` indexed `responses[witness_idx]` and the nonces with counts taken from the
statement while the arrays came from the wire proof; a short proof read out of bounds. The counts
are now compared up front and a short proof fails verification.

