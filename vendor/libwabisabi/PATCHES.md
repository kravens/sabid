# Local patches to libwabisabi

1. Presentation-only client requests (`wabisabi_client_create_present_request`, `client.c`
   `internal_create_real(..., presentation_only)`): the upstream C client always requests two
   zero-padded credentials; Wasabi's output registration presents credentials and requests none
   (`WabiSabiClient.CreateRequest(credentialsToPresent)`, `Delta < 0`, three proofs). The upstream
   issuer already verifies such requests. Worth upstreaming to zkSNACKs/NWabiSabi.
