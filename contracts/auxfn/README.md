# AuxFn OpenAPI contract

`openapi-http-api.public.json` is the imported public AuxFn HTTP API specification.

Sidecar request and response DTOs are owned by `sidecar-contract`. Maintainers refresh the
specification from the upstream public API artifact and verify DTO compatibility before release.
Do not edit the generated specification by hand.

The maintained importer writes `openapi-http-api.public.sha256` with the public artifact.
`just contract-check` verifies that checksum and the native token-warning and bound recovery-stage contracts.
The checksum pins the wire snapshot. Building this repository never requires AuxFn source.
