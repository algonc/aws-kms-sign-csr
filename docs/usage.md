# Usage Guide

## Flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `-csr` | yes | none | Path to a PEM-encoded CSR file. |
| `-key-id` | yes | none | KMS key ID, key ARN, or alias. |
| `-algorithm` | no | `ecdsa-sha256` | Signing algorithm. Must match the KMS key type. |
| `-region` | no | environment | AWS region. Falls back to the AWS SDK default region chain. |
| `-profile` | no | environment | AWS shared config profile. Falls back to the AWS SDK default credential chain. |

## Supported Algorithms

| Flag value | KMS algorithm | Key type | Signature OID |
|---|---|---|---|
| `ecdsa-sha256` | `ECDSA_SHA_256` | EC | `1.2.840.10045.4.3.2` |
| `ecdsa-sha384` | `ECDSA_SHA_384` | EC | `1.2.840.10045.4.3.3` |
| `ecdsa-sha512` | `ECDSA_SHA_512` | EC | `1.2.840.10045.4.3.4` |
| `rsa-sha256` | `RSASSA_PKCS1_V1_5_SHA_256` | RSA | `1.2.840.113549.1.1.11` |
| `rsa-sha384` | `RSASSA_PKCS1_V1_5_SHA_384` | RSA | `1.2.840.113549.1.1.12` |
| `rsa-sha512` | `RSASSA_PKCS1_V1_5_SHA_512` | RSA | `1.2.840.113549.1.1.13` |

The selected algorithm must match the KMS key family. EC keys require an `ecdsa-*` algorithm, and RSA keys require an `rsa-*` algorithm.

## Examples

### ECDSA KMS Key

```sh
openssl req -new -newkey rsa:1024 -nodes -keyout /dev/null \
  -subj "/C=DE/O=Example GmbH/CN=my-service.example.com" \
  -out /tmp/original.csr

./aws-kms-sign-csr \
  -csr /tmp/original.csr \
  -key-id alias/my-ec-key \
  -algorithm ecdsa-sha256 \
  -region eu-central-1 \
  > /tmp/signed.csr
```

### RSA KMS Key

```sh
openssl req -new -newkey rsa:1024 -nodes -keyout /dev/null \
  -subj "/C=DE/O=Example GmbH/CN=my-service.example.com" \
  -out /tmp/original.csr

./aws-kms-sign-csr \
  -csr /tmp/original.csr \
  -key-id arn:aws:kms:eu-central-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  -algorithm rsa-sha256 \
  -region eu-central-1 \
  > /tmp/signed.csr
```

### CSR With Subject Alternative Names

Create an OpenSSL request configuration:

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
subjectAltName = @alt_names

[alt_names]
DNS.1 = my-service.example.com
DNS.2 = api.my-service.example.com
```

Then generate and sign the CSR:

```sh
openssl req -new -newkey rsa:1024 -nodes -keyout /dev/null \
  -config /tmp/csr.conf \
  -out /tmp/original.csr

./aws-kms-sign-csr \
  -csr /tmp/original.csr \
  -key-id alias/my-ec-key \
  -algorithm ecdsa-sha256 \
  > /tmp/signed.csr
```

## Validation

Inspect the signed CSR:

```sh
openssl req -in /tmp/signed.csr -noout -text
```

Verify the signature:

```sh
openssl req -in /tmp/signed.csr -verify -noout
```

Expected output:

```text
Certificate request self-signature verify OK
```

Inspect the raw ASN.1 structure when debugging interoperability issues:

```sh
openssl asn1parse -in /tmp/signed.csr
```

Cross-check the CSR public key against KMS:

```sh
aws kms get-public-key \
  --key-id alias/my-ec-key \
  --region eu-central-1 \
  --query PublicKey \
  --output text | base64 -d \
  | openssl pkey -pubin -inform DER -pubout -out /tmp/kms_pub.pem

openssl req -in /tmp/signed.csr -noout -pubkey -out /tmp/csr_pub.pem

diff /tmp/kms_pub.pem /tmp/csr_pub.pem
```

## Limitations

- RSASSA-PSS is not supported.
- EC key curves are not validated locally; KMS rejects incompatible curve and hash combinations.
- Existing CSR extensions are preserved, but the tool does not add, remove, or rewrite extensions.
- Output is written to standard output. Redirect it to a file as needed.
- Each invocation signs one CSR.
