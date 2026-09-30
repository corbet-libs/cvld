# cvld

The permanent door of the cmtymeet trust stack. One Rust library and binary,
FSL-1.1-ALv2. The JavaScript/AnonCreds prototype is preserved at annotated tag
`js-prototype-0.1.0-alpha.0`. This package is not published to any registry.

The door composes the global `cglb` and community `cmnt` facades. Separate
processes and databases preserve their information boundary. The API registry
owns actions, roles and check/record classification; HTTP, OpenAPI, MCP and CLI
are projections of that registry.

## Dependency choices

Surveyed crates.io, official documentation and GitHub on 2026-09-30:

| Dependency | Why |
|---|---|
| [axum](https://github.com/tokio-rs/axum) 0.8 | Maintained Tokio HTTP routing and bounded JSON extraction. |
| [tower-http](https://github.com/tower-rs/tower-http) 0.6 | Standard CORS handling with an exact host/origin allow-list; shares the existing HTTP middleware dependency. |
| [utoipa](https://github.com/juhaku/utoipa) 6 | Rust request/response schemas and OpenAPI 3.1. |
| [rmcp](https://github.com/modelcontextprotocol/rust-sdk) 3.5 | Official Rust MCP SDK; reuse protocol and transport handling. |
| [clap](https://github.com/clap-rs/clap) 4.6 | Build subcommands directly from action metadata. |
| [openapi-typescript](https://github.com/openapi-ts/openapi-typescript) 7.13 | Generate the TypeScript interface from the emitted OpenAPI. |
| [cglb](https://github.com/corbet-libs/cglb) | Own global uniqueness, gate execution, suspension and blind issuance. |
| [cpky](https://github.com/corbet-foss/cpky) | UV-required wallet/operator WebAuthn; no new passkey implementation. |
| [cthl](https://github.com/corbet-foss/cthl) | Maintained governor-backed throttling with bounded memory. |

Storage and cryptography remain in the existing crlt, cpsd and csgn leaves.
No ORM, second authorization engine or direct cryptographic implementation is
needed. Configuration is supplied in files; the service never searches for
credentials. Rust compilation and tests run in GitHub Actions only.

## Run and call the door

Build and validate through GitHub Actions. Supply explicit configuration and
separate service databases; [the global example](examples/global.json) contains
paths and synthetic identifiers, not keys or credentials.

```sh
cvld serve global --config ./global.json
cvld openapi
cvld --url https://wallet.example.test --host wallet.example.test global_public
cvld --url https://wallet.example.test --host wallet.example.test \
  --session-file ./wallet.session passport_challenge
cvld --url https://wallet.example.test --host wallet.example.test \
  --session-file ./wallet.session mcp
```

CLI action input is `--request '<JSON>'`. MCP uses the official SDK's stdio
transport and the same HTTP client. Both require HTTPS except for loopback
integration tests; neither follows redirects. Session files contain only the
opaque bearer token. The TypeScript wrapper in `clients/ts/index.ts` uses the
committed generated types with `openapi-fetch`.

For a global service, provision a 32-byte csgn signing seed, a cpsd issuer secret
in its leaf wire format, a 32-byte uniqueness key, a COSE-signed cglb policy,
and that policy authority's public key ring. The supplied operator UUID and
initial registration capability select the root account; the caller cannot
request a role. Registering a passkey requires a real WebAuthn ceremony with
user verification. No key generation, credential discovery or deployment runs
as a side effect of starting the door.

`development-gate` is an opt-in Cargo feature for development builds. Enabling
it in a release build is a compilation error. Production builds and their
generated clients omit the synthetic gate.
