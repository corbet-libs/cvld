# cvld door contract

One FSL-1.1-ALv2 Rust package, library and binary. No registry publishing.
The previous JavaScript tree is preserved by the annotated
`js-prototype-0.1.0-alpha.0` tag. Domain state and decisions belong to cglb and
cmnt; storage and cryptography remain in their leaves.

## Actions and transports

`src/api/mod.rs` is the action registry. Every action has a typed request and
response, exact allowed role, service scope and check/record classification.
The macro registers `/v1/<action>` POST routes. OpenAPI uses utoipa schemas;
clap and the official rmcp SDK project the same registry. Operational commands
`serve`, `openapi` and `mcp` are transport utilities, not extra domain actions.
MCP runs over local stdio and forwards to HTTP, preserving host and session
checks. It never receives a passkey private key. Requests and responses are JSON;
cryptographic leaf wire formats are opaque byte arrays.

An unknown action cannot execute. Inputs reject unknown envelope fields and
HTTP allocation is bounded. Errors are fixed categories, without leaf errors,
request data or identifiers. Checks create no member activity record; records
may alter permanent domain state. Authentication counter commits are records.
Pending ceremonies and bearer sessions are bounded, ephemeral and single-use
or expiring; restarting the process discards them.

## Global process

`cvld serve global --config <file>` owns one crlt database, cglb's issuer,
uniqueness key and durable csgn signer. Wallet authentication uses cpky at
`wallet.<domain>`. Root authentication uses a separate RP and namespace at
`api.root.<domain>`. Hosts match exactly; forwarded-host headers are ignored.
Only UV-verified passkeys create sessions. Each use rechecks its exact credential
for revocation. A member cannot request an operator role. Operator UUIDs and a
one-time initial registration capability are explicit service configuration.
Existing operator credentials prevent reuse of bootstrap across restart.

The global service calls cglb for uniqueness, gates, blind issuance, warning and
temporary suspension. It never receives a community identifier or pseudonym.
Public material contains only issuer keys, policy revision, epoch and common
expiry. Private global revocations are not sent to communities. Cglb's current
revocation mechanism advances the passport cohort epoch; it is not an individual
zero-knowledge revocation accumulator. Global providers beyond the development
gate remain leaf integrations.

The `development-gate` Cargo feature enables the synthetic gate for development
builds. A release build with that feature fails compilation. Default release
schemas, routes, commands and tools omit it.

## Runtime privacy and configuration

No logging/tracing subscriber, request logger, member metrics or identifier labels
are installed. Every action passes cthl's bounded aggregate per-action throttle;
changing an IP, handle or session cannot bypass that quota. Failed checks fail
closed. A proxy must preserve these privacy properties and provide TLS.

Configuration and secret file paths are explicit. The service does not search for
operator credentials, use a secret store implicitly or provision a deployment.
It uses a generic HTTP User-Agent. No client credential is sent across redirects.
Database access is only through crlt; the pool defaults to one connection.
Maintenance prunes expired global challenges and refreshes signed public status.
An unsuccessful refresh leaves the old expiry in force rather than extending it.

## Verification

GitHub Actions runs stable Rust formatting, strict Clippy, real libSQL/WebAuthn/
blind-passport HTTP tests, CLI and official MCP-client process round trips,
surface parity, default release tests and a negative release-feature build.
OpenAPI and the TypeScript client are regenerated and compared with committed
output. No Cargo command runs on the workstation. The optional Turso test connects
only if both TURSO_URL and TURSO_TOKEN are nonempty; use a disposable database.
