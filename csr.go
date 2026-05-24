package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// algorithmIdentifier mirrors pkix.AlgorithmIdentifier with RawValue parameters
// so NULL (RSA) vs. absent (ECDSA) round-trips correctly through asn1.Marshal.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// certificationRequestInfo is used for unmarshal only.
// asn1.RawContent captures the original DER; it is skipped by asn1.Marshal.
type certificationRequestInfo struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	PublicKey  subjectPublicKeyInfo
	Attributes asn1.RawValue `asn1:"tag:0,optional"`
}

// criForMarshal is used when re-encoding the CertificationRequestInfo with a
// replaced public key. No RawContent field so asn1.Marshal uses the live fields.
type criForMarshal struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  subjectPublicKeyInfo
	Attributes asn1.RawValue `asn1:"tag:0,optional"`
}

type certificationRequest struct {
	CertificationRequestInfo asn1.RawValue
	SignatureAlgorithm       algorithmIdentifier
	Signature                asn1.BitString
}

func buildSignedCSR(ctx context.Context, client kmsClientAPI, csrDER, kmsPubKeyDER []byte, entry algorithmEntry, keyID string) ([]byte, error) {
	// Step 1: parse outer CertificationRequest
	var outer certificationRequest
	rest, err := asn1.Unmarshal(csrDER, &outer)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR outer structure: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("unexpected trailing bytes after CSR DER")
	}

	// Step 2: parse inner CertificationRequestInfo
	var cri certificationRequestInfo
	if _, err := asn1.Unmarshal(outer.CertificationRequestInfo.FullBytes, &cri); err != nil {
		return nil, fmt.Errorf("parsing CertificationRequestInfo: %w", err)
	}

	// Step 3: parse KMS public key as SubjectPublicKeyInfo
	var kmsSPKI subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(kmsPubKeyDER, &kmsSPKI); err != nil {
		return nil, fmt.Errorf("parsing KMS public key DER: %w", err)
	}

	// Step 4: validate key type matches algorithm family
	pub, err := x509.ParsePKIXPublicKey(kmsPubKeyDER)
	if err != nil {
		return nil, fmt.Errorf("validating KMS public key: %w", err)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey:
		if entry.keyFamily != keyFamilyECDSA {
			return nil, fmt.Errorf("KMS key is ECDSA but algorithm %q expects %s", entry.kmsAlgorithm, entry.keyFamily)
		}
	case *rsa.PublicKey:
		if entry.keyFamily != keyFamilyRSA {
			return nil, fmt.Errorf("KMS key is RSA but algorithm %q expects %s", entry.kmsAlgorithm, entry.keyFamily)
		}
	default:
		return nil, fmt.Errorf("unsupported KMS key type %T", pub)
	}

	// Step 5 & 6: rebuild CertificationRequestInfo with KMS public key and re-encode
	newCRI := criForMarshal{
		Version:    cri.Version,
		Subject:    cri.Subject,
		PublicKey:  kmsSPKI,
		Attributes: cri.Attributes,
	}
	newCRIDER, err := asn1.Marshal(newCRI)
	if err != nil {
		return nil, fmt.Errorf("re-encoding CertificationRequestInfo: %w", err)
	}

	// Step 7: hash the new CertificationRequestInfo
	h := entry.newHash()
	h.Write(newCRIDER)
	digest := h.Sum(nil)

	// Step 8: sign the digest with KMS
	signOut, err := client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: entry.kmsAlgorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Sign: %w", err)
	}

	// Step 9: assemble the outer CertificationRequest
	sigAlgParams := asn1.RawValue{} // absent for ECDSA
	if entry.nullParams {
		sigAlgParams = asn1.RawValue{Tag: asn1.TagNull} // explicit NULL for RSA
	}

	newOuter := certificationRequest{
		CertificationRequestInfo: asn1.RawValue{FullBytes: newCRIDER},
		SignatureAlgorithm: algorithmIdentifier{
			Algorithm:  entry.sigOID,
			Parameters: sigAlgParams,
		},
		Signature: asn1.BitString{
			Bytes:     signOut.Signature,
			BitLength: len(signOut.Signature) * 8,
		},
	}

	// Step 10: marshal final DER
	finalDER, err := asn1.Marshal(newOuter)
	if err != nil {
		return nil, fmt.Errorf("encoding final CSR: %w", err)
	}
	return finalDER, nil
}
