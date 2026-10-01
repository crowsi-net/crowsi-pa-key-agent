# Security policy

The PA private seed belongs only in the configured platform custody entry. Never add
seed material, exported custody payloads, authorization envelopes, or test keys
to this repository or its fixtures.

The public-state file is not proof that custody is currently reachable. Its
owner, mode, schema, key ID, revision, and public key must match the native
custody check before an authorization coordinator can use the key.

Trust-domain destruction requires a closed owner-only intent and a fresh
WebAuthn assertion from the Passkey registered to the current PA generation.
The challenge binds the exact canonical intent digest, operation ID, local
scope, expected PA public key, and impact digest. The native agent revalidates
all files and custody immediately before consuming evidence and deleting the
server-side Passkey registration, PA key, and public projection in that order.

`destroy-native` bypasses WebAuthn and exists only as an internal recovery and
test primitive. Do not expose it as a normal UI or service action. A caller must
quiesce dependent services before invoking either destruction path. Never kill,
restart or unlock a desktop secret daemon from this agent; the configured
shared OS-session state.

Every invocation is a bounded, short-lived process. Callers must terminate its
dedicated process group on timeout and must not inherit an unrestricted process
environment. Diagnosis may report a locked or unavailable store, but mutation
must fail closed in either state.

Generic authorization issuance remains disabled. The PA accepts only the
credential-enrollment operation and the exact read-only GitHub observer signing
operation. Both coordinators require a local WebAuthn P-256 assertion bound to
the exact request digest, current RP ID and origin, UV/UP flags, counter,
expiry, PA revision, workload, actor profile, and a one-use reservation.
GitHub authorization is restricted to `observe-provider`, the scoped GitHub App
credential resource, and `github-app-jwt-signing`; it cannot authorize a write
or a broader provider resource. Custody availability alone is not evidence.
Each issuance also requires a currently valid iHAT device-identity assertion and
a separately signed current-device status with a maximum 30-second lifetime.
Identity trust v2 pins independent assertion and status keys, the exact issuer,
PA audience, and Crowsi service. The two documents must match every device,
proof-key, posture, epoch, and nonce field. Their canonical digests are bound
into the WebAuthn challenge. The status nonce is atomically consumed in a durable
owner-only ledger before challenge creation; replay and concurrent reuse fail closed.
The resulting V2
authorization carries pairwise subject, device proof-key reference, posture
revision, and four scoped revocation epochs. Synced Passkey material is never
treated as a physical device identity, and no legacy fixed-subject fallback is
accepted.

`operation-authorize-once` is a separate closed endpoint port, not generic
authorization issuance. Its bounded current-only v2 stdin contains signed selected
identity, Begin, Finish, and submission-current identity exchanges, a prepared
device-transfer, exact `TargetApprove`, unsigned target proof, and the exact
Ed25519 sign intent. Bare identity/FreshUV and v1 are rejected. The PA verifies
AuthorityResponse correlation/signatures/generation, Begin-to-Finish continuity,
fresh-current stable context, every distinct key role, nonce, validity edge,
mapping, revision, class, and action against trusted time.

The finite command accepts only `operation-authorize-once --config ABS
--config-sha256 sha256:<64lowerhex>`. It opens the owner `0600` config through a
pinned owner `0700` parent-directory descriptor with `O_NOFOLLOW`, verifies the
regular-file owner, mode, link count, size, inode, parent, and supplied digest,
then parses it. The canonical root-owned trust file is fixed at
`/etc/crowsi/policy-authority/operation-authorize-once-v2.json`. It pins the
configuration key for a signed owner `0600` config. That config selects exactly
one `(opaque owner, service, target device, proof-key reference)` mapping to a
distinct custody credential ID, exact revision, and Ed25519 class. The PA signing
key remains in its independent platform-custody scope and must differ from iHAT,
configuration-signing, and mapped operation credentials. Before returning the complete signed
`OperationOnlyRequest`, the PA atomically commits its exact canonical bytes with
the strict-decoded full-request digest, raw semantic target-proof digest, and
request-ID digest in an owner `0700` fd-relative ledger. An exact retry returns
those bytes before live evidence, mapping, PA-state, or custody checks; the CLI
still validates the current fixed root, signed config, pinned config path, and
replay path. Any same-proof, same-request-ID, or field substitution fails closed.

The ledger pins issued time, the accepted PA public key and custody revision,
and the selected mapping before response construction. A prepared retry may use
only that retained old custody revision; a current replacement key cannot sign
in its place. If the old revision is unavailable, no external response is
committed and the endpoint must Cancel/reset the operation after proof expiry
before creating a new PA request. Completed bytes remain recoverable through the
bounded expiry retention window. Pre-cache v1 consumed-proof files migrate only
as one-use tombstones; they can reject the old proof but can never mint or
reconstruct a response. Exclusive OS locking serializes processes.
Owner `0600`, single-link, bounded regular files are opened fd-relative with
`O_NOFOLLOW`; temp fsync, atomic rename, and directory fsync order every commit.
A durable monotonic wall-time watermark is committed before expired receipts are
pruned, so clock-forward followed by rollback cannot re-enable a proof. Quota,
partial writes, unknown files, links, FIFOs, writable ancestors, and path
replacement fail closed. The launcher must validate a fresh PA response at
subprocess completion time, not handler-start time. The port reads no environment
configuration; its parent must still
launch the finite process with a cleared environment and a bounded timeout.
Fresh Passkey registration is disabled in the default CLI and library artifact.
All three native registration commands return
`pa-passkey-bootstrap-authorizer-not-provisioned` before custody or path access.
Existing stale credentials may use the separate rebind flow only after
a current-PA-bound, one-use UV assertion succeeds.

An explicit `owner-local-bootstrap` artifact is available only for a local,
single-user deployment that treats the owner OS session as part of the TCB. It
revalidates platform custody and the current PA revision at every native stage,
derives the PA binding internally, keeps registration evidence owner-only and
one-use, and requires the staged authenticator's separate UV possession proof.
That one fresh proof permits the initial Windows authenticator counter to remain
equal, rejects rollback, and does not relax strict counter growth after commit.
The feature is a reviewed deployment mode, not an authorization credential. It
does not claim isolation from arbitrary code already executing as the owner UID.

Lost-authenticator recovery is narrower than trust-domain destruction and is
not a bootstrap authority. It may remove only the canonical owner-local
`passkey.json` after matching the live platform custody revision, current PA public
key, fixed sibling paths, and an explicit operation phrase. It retains the PA,
public projection, provider credentials, runtime, and authenticator-held
credential. The owner UID is deliberately part of the TCB for this
availability-only revocation: same-UID malicious code could already unlink the
owner-only server record. This does not authorize registration, secret access,
or full trust destruction. A future polkit/root-owned reauthentication broker
may harden this same-UID denial-of-service boundary without changing scope.

For a deployment that excludes the owner UID from the TCB, the future authorizer
must be root-owned or polkit-mediated and issue an
atomically consumed, short-lived grant bound to the OS UID, a trusted compiled
client/release digest, the current PA generation, and the exact registration
challenge. A caller-supplied header, environment flag, same-UID Node process,
or UI visibility check is not a bootstrap authority. That deployment must also
move `passkey.json`, ceremony evidence, and the replay ledger behind a root or
dedicated-UID broker; otherwise same-UID code can bypass the authorizer by
replacing owner-writable state. The internal Cargo feature exists for proof
tests and that future privileged component.

The registration verifier parses AT data and requires the embedded COSE ES256
key to use CTAP2 canonical CBOR,
matches both credential ID and SPKI, validates any ED-marked authenticator
extension as one bounded CBOR map without duplicate names or trailing data,
then requires a second `webauthn.get`
signature by the staged key before commit. `attestation: none` does not establish
manufacturer or hardware provenance and no attestation-chain trust is claimed.
Candidate, challenge, and assertion evidence is owner-only and one-use; an old
credential file is not archived after atomic replacement.

Current owner-only JSON protects against other OS users, symlinks, and
permissive paths, but it does not provide integrity against malicious code
already running as the same UID. Such code can replace a syntactically valid
credential record. If same-UID compromise is in scope, production must move the
record behind a root/dedicated-user broker or add a PA-signed record verified on
every read. Stale-credential rebind must then require the same provenance. Until that
boundary is implemented, the owner OS session is part of the trusted computing
base.

Report any private-key output, silent key replacement, public-state/custody
mismatch acceptance, non-owner state file, or authorization issuance without
the complete evidence chain as a security defect.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
