# Makefile Workflow

The `Makefile` automates building the CLI, creating a CSR from an OpenSSL config file, signing it with KMS, and validating the result.

## Requirements

- `openssl` for CSR generation, inspection, and verification.
- AWS credentials with `kms:GetPublicKey` and `kms:Sign` for the selected key.
- AWS CLI when `CHECK_PUBLIC_KEY=true`.

## Targets

| Target | Description |
|---|---|
| `build` | Compiles the binary to `bin/aws-kms-sign-csr`. |
| `csr` | Generates a CSR, signs it with KMS, writes `signed.csr`, and prints a verification report. |
| `clean` | Removes the compiled binary and `OUTPUT_DIR/.tmp` when `OUTPUT_DIR` is set. |

## Variables

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
