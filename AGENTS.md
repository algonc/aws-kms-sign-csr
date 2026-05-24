# AGENTS.md

## Project Overview

This repository contains `aws-kms-sign-csr`, a Go CLI that rewrites a PEM CSR to use an AWS KMS asymmetric public key and asks KMS to sign the updated `CertificationRequestInfo`. The private key must never leave KMS.

The code is currently a small single-package Go module:

- `main.go` contains the entrypoint and top-level orchestration.
- `cli.go` contains flag parsing and CLI config validation.
- `algorithm.go` contains supported signing algorithms and key-family metadata.
- `csr.go` contains CSR/ASN.1 parsing, rewriting, and signature assembly.
- `kms.go` contains the narrow KMS client interface and public-key fetch helper.
- `pem.go` contains CSR PEM input and output helpers.
- `main_test.go` contains regression tests for CSR behavior, algorithm metadata, and KMS interactions.
- `Makefile` builds the binary and provides an end-to-end CSR generation/signing workflow.
- `README.md` links to user-facing documentation under `docs/`.

## Development Commands

Use these commands from the repository root:

```sh
go fmt ./...
go test ./...
go build -o bin/aws-kms-sign-csr .
```

The Makefile equivalent for building is:

```sh
make build
```

The `make csr` workflow requires AWS credentials, `openssl`, and these variables:

```sh
make csr KEY_ID=<kms-key-id-or-alias> REGION=<aws-region> CONFIG=<openssl-cnf> OUTPUT_DIR=<dir>
```

Set `CHECK_PUBLIC_KEY=true` only when the AWS CLI is available and the caller has `kms:GetPublicKey`.

## Coding Guidelines

- Keep the project as a straightforward Go CLI unless a change clearly needs more structure.
- Run `go fmt ./...` after editing Go files.
- Prefer standard library parsing/encoding APIs for ASN.1, PEM, X.509, hashing, and flags.
- Preserve CSR subject, attributes, extensions, and output format unless the requested change explicitly says otherwise.
- Keep errors actionable and wrap lower-level failures with context.
- Do not log or persist private key material. The tool must only handle public keys, CSRs, digests, and signatures.

## Testing and Validation

- Add focused Go tests for pure logic when changing algorithm mapping, CSR parsing, key type validation, or ASN.1 encoding.
- For KMS-backed behavior, document any manual validation performed, including the key type, region, algorithm, and OpenSSL verification command.
- Before finishing changes that affect generated CSRs, verify the result with:

```sh
openssl req -in <signed.csr> -verify -noout
openssl req -in <signed.csr> -noout -text
```

## Operational Notes

- Supported signing algorithms are `ecdsa-sha256`, `ecdsa-sha384`, `ecdsa-sha512`, `rsa-sha256`, `rsa-sha384`, and `rsa-sha512`.
- RSA signatures use PKCS#1 v1.5 algorithm identifiers with explicit NULL parameters.
- ECDSA algorithm identifiers omit parameters.
- RSASSA-PSS is intentionally unsupported unless its CSR algorithm identifier and parameters are implemented correctly.
