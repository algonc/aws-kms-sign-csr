# aws-kms-sign-csr

`aws-kms-sign-csr` is a small CLI for creating certificate signing requests backed by an asymmetric AWS KMS key. The private key remains in KMS, and the resulting CSR can be submitted to a Certificate Authority.

## Requirements

- Go 1.25 or later
- AWS credentials configured for the target account
- An AWS KMS asymmetric key with `kms:GetPublicKey` and `kms:Sign` permissions

## Build

```sh
go build -o aws-kms-sign-csr .
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

## License

See [LICENSE](LICENSE).
