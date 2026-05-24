// Copyright 2026 André Gonçalves. All rights reserved.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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

type algorithmEntry struct {
	kmsAlgorithm kmstypes.SigningAlgorithmSpec
	sigOID       asn1.ObjectIdentifier
	newHash      func() hash.Hash
	keyFamily    keyFamily
	nullParams   bool // RSA requires explicit NULL; ECDSA requires absent
}

type keyFamily string

const (
	keyFamilyECDSA keyFamily = "ECDSA"
	keyFamilyRSA   keyFamily = "RSA"
)

type kmsClientAPI interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

var algorithms = map[string]algorithmEntry{
	"ecdsa-sha256": {
		kmsAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
		sigOID:       asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
		newHash:      sha256.New,
		keyFamily:    keyFamilyECDSA,
		nullParams:   false,
	},
	"ecdsa-sha384": {
		kmsAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha384,
		sigOID:       asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3},
		newHash:      sha512.New384,
		keyFamily:    keyFamilyECDSA,
		nullParams:   false,
	},
	"ecdsa-sha512": {
		kmsAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha512,
		sigOID:       asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4},
		newHash:      sha512.New,
		keyFamily:    keyFamilyECDSA,
		nullParams:   false,
	},
	"rsa-sha256": {
		kmsAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		sigOID:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		newHash:      sha256.New,
		keyFamily:    keyFamilyRSA,
		nullParams:   true,
	},
	"rsa-sha384": {
		kmsAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		sigOID:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12},
		newHash:      sha512.New384,
		keyFamily:    keyFamilyRSA,
		nullParams:   true,
	},
	"rsa-sha512": {
		kmsAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		sigOID:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13},
		newHash:      sha512.New,
		keyFamily:    keyFamilyRSA,
		nullParams:   true,
	},
}

type config struct {
	csrFile   string
	keyID     string
	algorithm string
	region    string
	profile   string
}

func loadConfig() config {
	csrFile := flag.String("csr", "", "Path to PEM-encoded CSR file (required)")
	keyID := flag.String("key-id", "", "AWS KMS key ID, ARN, or alias (required)")
	algorithm := flag.String("algorithm", "ecdsa-sha256", "Signing algorithm: ecdsa-sha256|ecdsa-sha384|ecdsa-sha512|rsa-sha256|rsa-sha384|rsa-sha512")
	region := flag.String("region", "", "AWS region (default: from environment)")
	profile := flag.String("profile", "", "AWS credentials profile (default: from environment)")

	flag.Parse()

	if *csrFile == "" {
		fmt.Fprintln(os.Stderr, "error: --csr is required")
		flag.Usage()
		os.Exit(1)
	}
	if *keyID == "" {
		fmt.Fprintln(os.Stderr, "error: --key-id is required")
		flag.Usage()
		os.Exit(1)
	}
	if _, ok := algorithms[*algorithm]; !ok {
		var valid []string
		for k := range algorithms {
			valid = append(valid, k)
		}
		fmt.Fprintf(os.Stderr, "error: unknown algorithm %q; valid choices: %s\n", *algorithm, strings.Join(valid, ", "))
		os.Exit(1)
	}

	return config{
		csrFile:   *csrFile,
		keyID:     *keyID,
		algorithm: *algorithm,
		region:    *region,
		profile:   *profile,
	}
}

func readCSRDER(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected PEM type CERTIFICATE REQUEST, got %q", block.Type)
	}
	return block.Bytes, nil
}

func fetchKMSPublicKeyDER(ctx context.Context, client kmsClientAPI, keyID string) ([]byte, error) {
	resp, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("GetPublicKey: %w", err)
	}
	return resp.PublicKey, nil
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

func outputPEM(der []byte) {
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}); err != nil {
		fatalf("writing PEM output: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	var opts []func(*awsconfig.LoadOptions) error
	if cfg.region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.region))
	}
	if cfg.profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.profile))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		fatalf("loading AWS config: %v", err)
	}

	kmsClient := kms.NewFromConfig(awsCfg)

	csrDER, err := readCSRDER(cfg.csrFile)
	if err != nil {
		fatalf("reading CSR: %v", err)
	}

	kmsPubKeyDER, err := fetchKMSPublicKeyDER(ctx, kmsClient, cfg.keyID)
	if err != nil {
		fatalf("fetching KMS public key: %v", err)
	}

	entry := algorithms[cfg.algorithm]

	signedDER, err := buildSignedCSR(ctx, kmsClient, csrDER, kmsPubKeyDER, entry, cfg.keyID)
	if err != nil {
		fatalf("building signed CSR: %v", err)
	}

	outputPEM(signedDER)
}
