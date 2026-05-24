# Implementation Notes

This document describes the CSR rewriting behavior and KMS signing flow. It is intended for maintainers and reviewers.

## Signing Flow

1. Read a PEM-encoded CSR from disk.
2. Fetch the KMS public key with `GetPublicKey`.
3. Replace the CSR `subjectPublicKeyInfo` with the KMS public key.
4. Hash the updated `CertificationRequestInfo`.
5. Ask KMS to sign the digest with `Sign`.
6. Reassemble the CSR with the new signature algorithm identifier and signature.
7. Write the final CSR as PEM to standard output.

The key used to create the input CSR is only needed to produce a structurally valid CSR. Its public key and signature are replaced.

## ASN.1 Behavior

- The CSR subject, attributes, and requested extensions are preserved.
- The KMS public key is parsed as `SubjectPublicKeyInfo`.
- RSA signature algorithm identifiers include explicit NULL parameters.
- ECDSA signature algorithm identifiers omit parameters.
- The final CSR signature bit string contains the signature returned by KMS.

## KMS Behavior

- The tool uses `MessageType=DIGEST` when calling `Sign`.
- The selected KMS signing algorithm must match the KMS key family.
- EC keys are accepted only with `ecdsa-*` algorithms.
- RSA keys are accepted only with `rsa-*` algorithms.

## Unsupported Behavior

RSASSA-PSS is intentionally unsupported. Adding it requires correct CSR signature algorithm identifiers and parameters for PSS, not only a new KMS signing algorithm constant.
