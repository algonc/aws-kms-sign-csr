# aws-kms-sign-csr

`aws-kms-sign-csr` is a small CLI for creating certificate signing requests backed by an asymmetric AWS KMS key. The private key remains in KMS, and the resulting CSR can be submitted to a Certificate Authority.

## Requirements

- Go 1.26.0 or later for building from source
- AWS credentials configured for the target account
- An AWS KMS asymmetric key with `kms:GetPublicKey` and `kms:Sign` permissions

## Install

On Linux or macOS (amd64 or arm64), install the latest stable release into `~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/algonc/aws-kms-sign-csr/main/install.sh | sh
```

The installer verifies the archive against the release's SHA-256 checksum before replacing the executable. To select a release or installation directory, pass `--version TAG` or `--bin-dir DIR` to the script.

## Build

```sh
go build -o aws-kms-sign-csr ./cmd/aws-kms-sign-csr
```

Or build into `bin/` with:

```sh
make build
```

## Usage

```sh
./aws-kms-sign-csr \
  -csr original.csr \
  -key-id alias/my-kms-key \
  -algorithm ecdsa-sha256 \
  -region eu-central-1 \
  > signed.csr
```

The input CSR provides the subject and requested extensions. The signed CSR is written to standard output.

## Documentation

- [Usage guide](docs/usage.md): flags, supported algorithms, examples, validation, and limitations.
- [Makefile workflow](docs/makefile.md): automated CSR generation, signing, verification, and required variables.
- [Implementation notes](docs/implementation.md): CSR rewriting, KMS signing behavior, and ASN.1 details.
- [Release guide](docs/releasing.md): Maintainer instructions for preparing, publishing, and verifying releases.

## License

See [LICENSE](LICENSE).
