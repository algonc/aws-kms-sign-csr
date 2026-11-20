# Makefile Workflow

The `Makefile` provides build and validation targets and automates generating and signing a CSR with KMS.

## Requirements

- GNU Make and Go 1.26.0 or later.
- `golangci-lint` for `make`, `make check`, and `make lint`.
- `openssl` and AWS credentials with `kms:GetPublicKey` and `kms:Sign` for `make csr`.
- AWS CLI for `make csr CHECK_PUBLIC_KEY=true`.

## Targets

| Target | Description |
|---|---|
| `all` (default) | Runs `check` and builds the CLI. |
| `build` | Compiles the CLI with `-trimpath` into `BIN_DIR`, which defaults to `bin/`. |
| `check` | Runs `verify`, `vet`, `lint`, and `test`. |
| `verify` | Verifies downloaded Go modules. |
| `vet` | Runs `go vet` on all packages. |
| `lint` | Runs `golangci-lint` with the repository configuration. |
| `test` | Runs all Go tests with the test cache disabled. |
| `test-cover` | Runs all Go tests with coverage and the test cache disabled. |
| `fmt` | Formats Go source files. |
| `tidy` | Updates `go.mod` and `go.sum` to match the source imports. |
| `csr` | Generates a CSR, signs it with KMS, writes `signed.csr`, and prints a verification report. |
| `clean` | Runs `go clean`, removes the CLI binary, and removes `OUTPUT_DIR/.tmp` when `OUTPUT_DIR` is set. |

## Variables

Override `GO`, `GOLANGCI_LINT`, or `BIN_DIR` to select the Go command, linter command, or binary directory. The defaults are `go`, `golangci-lint`, and `bin`.

The `csr` target accepts the following variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `KEY_ID` | yes | none | KMS key ID, key ARN, or alias. |
| `REGION` | yes | none | AWS region. |
| `CONFIG` | yes | none | Path to an OpenSSL request configuration file. |
| `OUTPUT_DIR` | yes | none | Directory where `signed.csr` is written. |
| `ALGORITHM` | no | `ecdsa-sha256` | Signing algorithm. |
| `CHECK_PUBLIC_KEY` | no | `false` | Download the KMS public key and compare it to the CSR public key. |

Intermediate files are written to `OUTPUT_DIR/.tmp/`.

## Build

```sh
make build
```

## Generate And Sign A CSR

```sh
make csr \
  KEY_ID=alias/my-ec-key \
  REGION=eu-central-1 \
  CONFIG=my-service.cnf \
  OUTPUT_DIR=./output
```

The signed CSR is written to:

```text
./output/signed.csr
```

## Enable Public Key Verification

```sh
make csr \
  KEY_ID=alias/my-ec-key \
  REGION=eu-central-1 \
  CONFIG=my-service.cnf \
  OUTPUT_DIR=./output \
  CHECK_PUBLIC_KEY=true
```

When enabled, the target downloads the KMS public key, extracts the public key from the signed CSR, prints both key details, and exits non-zero if the keys differ.

## OpenSSL Config Example

```ini
[req]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no

[dn]
C  = DE
O  = Example GmbH
CN = my-service.example.com

[v3_req]
subjectAltName = DNS:my-service.example.com, DNS:api.my-service.example.com
```

## Clean

```sh
make clean OUTPUT_DIR=./output
```
