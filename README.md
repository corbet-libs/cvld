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
