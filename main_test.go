package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var customExtensionOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5}

type fakeKMSClient struct {
	publicKeyDER []byte
	getErr       error
	signErr      error
	signFunc     func([]byte, kmstypes.SigningAlgorithmSpec) ([]byte, error)

	getCalls   int
	signCalls  int
	getKeyID   string
	signKeyID  string
	message    []byte
	messageTyp kmstypes.MessageType
	algorithm  kmstypes.SigningAlgorithmSpec
}

func (f *fakeKMSClient) GetPublicKey(_ context.Context, input *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.getCalls++
	if input.KeyId != nil {
		f.getKeyID = *input.KeyId
	}
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &kms.GetPublicKeyOutput{PublicKey: f.publicKeyDER}, nil
}

func (f *fakeKMSClient) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signCalls++
	if input.KeyId != nil {
		f.signKeyID = *input.KeyId
	}
	f.message = append([]byte(nil), input.Message...)
	f.messageTyp = input.MessageType
	f.algorithm = input.SigningAlgorithm

	if f.signErr != nil {
		return nil, f.signErr
	}
	if f.signFunc == nil {
		return nil, errors.New("unexpected Sign call")
	}

	signature, err := f.signFunc(input.Message, input.SigningAlgorithm)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: signature}, nil
}

func TestReadCSRDER(t *testing.T) {
	csrDER := makeCSR(t, testCSRTemplate(t))

	tests := []struct {
		name    string
		path    string
		pemData []byte
		wantErr string
	}{
		{
			name:    "valid CSR PEM",
			pemData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		},
		{
			name:    "invalid PEM",
			pemData: []byte("not a pem block"),
			wantErr: "no PEM block found",
		},
		{
			name:    "wrong PEM type",
			pemData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: csrDER}),
			wantErr: "expected PEM type CERTIFICATE REQUEST",
		},
		{
			name:    "missing file",
			path:    "does-not-exist.csr",
			wantErr: "reading file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if path == "" {
				path = writeTempFile(t, tt.pemData)
			}

			got, err := readCSRDER(path)
			if tt.wantErr != "" {
				requireErrorContains(t, err, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("readCSRDER returned error: %v", err)
			}
			if !bytes.Equal(got, csrDER) {
				t.Fatalf("CSR DER mismatch")
			}
		})
	}
}

func TestFetchKMSPublicKeyDER(t *testing.T) {
	wantDER := []byte{1, 2, 3}
	client := &fakeKMSClient{publicKeyDER: wantDER}

	got, err := fetchKMSPublicKeyDER(context.Background(), client, "alias/test")
	if err != nil {
		t.Fatalf("fetchKMSPublicKeyDER returned error: %v", err)
	}
	if !bytes.Equal(got, wantDER) {
		t.Fatalf("public key DER mismatch: got %x want %x", got, wantDER)
	}
	if client.getCalls != 1 {
		t.Fatalf("GetPublicKey calls = %d, want 1", client.getCalls)
	}
	if client.getKeyID != "alias/test" {
		t.Fatalf("GetPublicKey key id = %q, want alias/test", client.getKeyID)
	}

	client = &fakeKMSClient{getErr: errors.New("kms unavailable")}
	_, err = fetchKMSPublicKeyDER(context.Background(), client, "alias/test")
	requireErrorContains(t, err, "GetPublicKey")
}

func TestBuildSignedCSRECDSA(t *testing.T) {
	csrDER := makeCSR(t, testCSRTemplate(t))
	kmsKey := mustECDSAKey(t)
	kmsPubDER := mustMarshalPKIXPublicKey(t, &kmsKey.PublicKey)
	client := &fakeKMSClient{
		signFunc: func(digest []byte, algorithm kmstypes.SigningAlgorithmSpec) ([]byte, error) {
			if algorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 {
				t.Fatalf("signing algorithm = %s, want %s", algorithm, kmstypes.SigningAlgorithmSpecEcdsaSha256)
			}
			return ecdsa.SignASN1(rand.Reader, kmsKey, digest)
		},
	}

	signedDER, err := buildSignedCSR(context.Background(), client, csrDER, kmsPubDER, algorithms["ecdsa-sha256"], "alias/ecdsa")
	if err != nil {
		t.Fatalf("buildSignedCSR returned error: %v", err)
	}

	parsed := parseCSR(t, signedDER)
	if err := parsed.CheckSignature(); err != nil {
		t.Fatalf("signed CSR signature did not verify: %v", err)
	}
	if parsed.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("signature algorithm = %v, want %v", parsed.SignatureAlgorithm, x509.ECDSAWithSHA256)
	}
	assertECDSAPublicKeyEqual(t, &kmsKey.PublicKey, parsed.PublicKey)
	assertTemplatePreserved(t, parsed)
	assertECDSAAlgorithmParametersAbsent(t, signedDER)
	assertKMSDigest(t, client, "alias/ecdsa", kmstypes.SigningAlgorithmSpecEcdsaSha256, sha256Digest(parsed.RawTBSCertificateRequest))
}

func TestBuildSignedCSRRSA(t *testing.T) {
	csrDER := makeCSR(t, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "rsa.example.com",
			Organization: []string{"Example GmbH"},
			Country:      []string{"DE"},
		},
	})
	kmsKey := mustRSAKey(t)
	kmsPubDER := mustMarshalPKIXPublicKey(t, &kmsKey.PublicKey)
	client := &fakeKMSClient{
		signFunc: func(digest []byte, algorithm kmstypes.SigningAlgorithmSpec) ([]byte, error) {
			if algorithm != kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384 {
				t.Fatalf("signing algorithm = %s, want %s", algorithm, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384)
			}
			return rsa.SignPKCS1v15(rand.Reader, kmsKey, crypto.SHA384, digest)
		},
	}

	signedDER, err := buildSignedCSR(context.Background(), client, csrDER, kmsPubDER, algorithms["rsa-sha384"], "alias/rsa")
	if err != nil {
		t.Fatalf("buildSignedCSR returned error: %v", err)
	}

	parsed := parseCSR(t, signedDER)
	if err := parsed.CheckSignature(); err != nil {
		t.Fatalf("signed CSR signature did not verify: %v", err)
	}
	if parsed.SignatureAlgorithm != x509.SHA384WithRSA {
		t.Fatalf("signature algorithm = %v, want %v", parsed.SignatureAlgorithm, x509.SHA384WithRSA)
	}
	assertRSAPublicKeyEqual(t, &kmsKey.PublicKey, parsed.PublicKey)
	assertRSAAlgorithmParametersNull(t, signedDER)
	assertKMSDigest(t, client, "alias/rsa", kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384, sha384Digest(parsed.RawTBSCertificateRequest))
}

func TestBuildSignedCSRRejectsKeyFamilyMismatch(t *testing.T) {
	csrDER := makeCSR(t, testCSRTemplate(t))
	ecKey := mustECDSAKey(t)
	ecPubDER := mustMarshalPKIXPublicKey(t, &ecKey.PublicKey)
	rsaKey := mustRSAKey(t)
	rsaPubDER := mustMarshalPKIXPublicKey(t, &rsaKey.PublicKey)

	tests := []struct {
		name      string
		pubDER    []byte
		algorithm string
		wantErr   string
	}{
		{
			name:      "ECDSA key with RSA algorithm",
			pubDER:    ecPubDER,
			algorithm: "rsa-sha256",
			wantErr:   "KMS key is ECDSA",
		},
		{
			name:      "RSA key with ECDSA algorithm",
			pubDER:    rsaPubDER,
			algorithm: "ecdsa-sha256",
			wantErr:   "KMS key is RSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeKMSClient{}

			_, err := buildSignedCSR(context.Background(), client, csrDER, tt.pubDER, algorithms[tt.algorithm], "alias/test")
			requireErrorContains(t, err, tt.wantErr)
			if client.signCalls != 0 {
				t.Fatalf("Sign calls = %d, want 0", client.signCalls)
			}
		})
	}
}

func TestBuildSignedCSRRejectsUnsupportedPublicKeyType(t *testing.T) {
	csrDER := makeCSR(t, testCSRTemplate(t))
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	pubDER := mustMarshalPKIXPublicKey(t, publicKey)
	client := &fakeKMSClient{}

	_, err = buildSignedCSR(context.Background(), client, csrDER, pubDER, algorithms["ecdsa-sha256"], "alias/test")
	requireErrorContains(t, err, "unsupported KMS key type")
	if client.signCalls != 0 {
		t.Fatalf("Sign calls = %d, want 0", client.signCalls)
	}
}

func TestBuildSignedCSRErrors(t *testing.T) {
	csrDER := makeCSR(t, testCSRTemplate(t))
	kmsKey := mustECDSAKey(t)
	kmsPubDER := mustMarshalPKIXPublicKey(t, &kmsKey.PublicKey)
	trailingCSR := append(append([]byte(nil), csrDER...), 0x00)

	tests := []struct {
		name      string
		csrDER    []byte
		pubDER    []byte
		client    *fakeKMSClient
		wantErr   string
		wantSigns int
	}{
		{
			name:    "invalid CSR DER",
			csrDER:  []byte("not der"),
			pubDER:  kmsPubDER,
			wantErr: "parsing CSR outer structure",
		},
		{
			name:    "trailing CSR DER",
			csrDER:  trailingCSR,
			pubDER:  kmsPubDER,
			wantErr: "unexpected trailing bytes",
		},
		{
			name:    "invalid KMS public key DER",
			csrDER:  csrDER,
			pubDER:  []byte("not der"),
			wantErr: "parsing KMS public key DER",
		},
		{
			name:    "KMS sign error",
			csrDER:  csrDER,
			pubDER:  kmsPubDER,
			client:  &fakeKMSClient{signErr: errors.New("sign failed")},
			wantErr: "KMS Sign",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.client
			if client == nil {
				client = &fakeKMSClient{}
			}

			_, err := buildSignedCSR(context.Background(), client, tt.csrDER, tt.pubDER, algorithms["ecdsa-sha256"], "alias/test")
			requireErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestAlgorithmTable(t *testing.T) {
	tests := []struct {
		name         string
		kmsAlg       kmstypes.SigningAlgorithmSpec
		oid          asn1.ObjectIdentifier
		digestLength int
		keyFamily    keyFamily
		nullParams   bool
	}{
		{
			name:         "ecdsa-sha256",
			kmsAlg:       kmstypes.SigningAlgorithmSpecEcdsaSha256,
			oid:          asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
			digestLength: sha256.Size,
			keyFamily:    keyFamilyECDSA,
		},
		{
			name:         "ecdsa-sha384",
			kmsAlg:       kmstypes.SigningAlgorithmSpecEcdsaSha384,
			oid:          asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3},
			digestLength: sha512.Size384,
			keyFamily:    keyFamilyECDSA,
		},
		{
			name:         "ecdsa-sha512",
			kmsAlg:       kmstypes.SigningAlgorithmSpecEcdsaSha512,
			oid:          asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4},
			digestLength: sha512.Size,
			keyFamily:    keyFamilyECDSA,
		},
		{
			name:         "rsa-sha256",
			kmsAlg:       kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
			oid:          asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
			digestLength: sha256.Size,
			keyFamily:    keyFamilyRSA,
			nullParams:   true,
		},
		{
			name:         "rsa-sha384",
			kmsAlg:       kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			oid:          asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12},
			digestLength: sha512.Size384,
			keyFamily:    keyFamilyRSA,
			nullParams:   true,
		},
		{
			name:         "rsa-sha512",
			kmsAlg:       kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
			oid:          asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13},
			digestLength: sha512.Size,
			keyFamily:    keyFamilyRSA,
			nullParams:   true,
		},
	}

	if len(algorithms) != len(tests) {
		t.Fatalf("algorithm count = %d, want %d", len(algorithms), len(tests))
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, ok := algorithms[tt.name]
			if !ok {
				t.Fatalf("missing algorithm %q", tt.name)
			}
			if entry.kmsAlgorithm != tt.kmsAlg {
				t.Fatalf("KMS algorithm = %s, want %s", entry.kmsAlgorithm, tt.kmsAlg)
			}
			if !entry.sigOID.Equal(tt.oid) {
				t.Fatalf("OID = %v, want %v", entry.sigOID, tt.oid)
			}
			if entry.keyFamily != tt.keyFamily {
				t.Fatalf("keyFamily = %s, want %s", entry.keyFamily, tt.keyFamily)
			}
			if entry.nullParams != tt.nullParams {
				t.Fatalf("nullParams = %v, want %v", entry.nullParams, tt.nullParams)
			}
			hash := entry.newHash()
			if _, err := hash.Write([]byte("input")); err != nil {
				t.Fatalf("hash write failed: %v", err)
			}
			if got := len(hash.Sum(nil)); got != tt.digestLength {
				t.Fatalf("digest length = %d, want %d", got, tt.digestLength)
			}
		})
	}
}

func makeCSR(t *testing.T, template *x509.CertificateRequest) []byte {
	t.Helper()

	key := mustRSAKey(t)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	return csrDER
}

func testCSRTemplate(t *testing.T) *x509.CertificateRequest {
	t.Helper()

	customExtensionValue, err := asn1.Marshal("custom-value")
	if err != nil {
		t.Fatalf("marshaling custom extension: %v", err)
	}

	return &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "my-service.example.com",
			Organization: []string{"Example GmbH"},
			Country:      []string{"DE"},
		},
		DNSNames:       []string{"my-service.example.com", "api.my-service.example.com"},
		EmailAddresses: []string{"ops@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10")},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       customExtensionOID,
				Critical: true,
				Value:    customExtensionValue,
			},
		},
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	return key
}

func mustMarshalPKIXPublicKey(t *testing.T, publicKey any) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	return der
}

func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "csr-*.pem")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := file.Write(data); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("closing temp file: %v", err)
	}
	return file.Name()
}

func parseCSR(t *testing.T, der []byte) *x509.CertificateRequest {
	t.Helper()

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}
	return csr
}

func parseOuterCSR(t *testing.T, der []byte) certificationRequest {
	t.Helper()

	var outer certificationRequest
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		t.Fatalf("parsing outer CSR: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("outer CSR has trailing bytes: %x", rest)
	}
	return outer
}

func assertTemplatePreserved(t *testing.T, csr *x509.CertificateRequest) {
	t.Helper()

	if csr.Subject.CommonName != "my-service.example.com" {
		t.Fatalf("CommonName = %q", csr.Subject.CommonName)
	}
	if got := strings.Join(csr.Subject.Organization, ","); got != "Example GmbH" {
		t.Fatalf("Organization = %q", got)
	}
	if got := strings.Join(csr.Subject.Country, ","); got != "DE" {
		t.Fatalf("Country = %q", got)
	}
	assertStringSlicesEqual(t, csr.DNSNames, []string{"my-service.example.com", "api.my-service.example.com"}, "DNSNames")
	assertStringSlicesEqual(t, csr.EmailAddresses, []string{"ops@example.com"}, "EmailAddresses")
	if len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("IPAddresses = %v, want [192.0.2.10]", csr.IPAddresses)
	}
	extension, ok := findExtension(csr.Extensions, customExtensionOID)
	if !ok {
		t.Fatalf("custom extension %v not found", customExtensionOID)
	}
	if !extension.Critical {
		t.Fatalf("custom extension Critical = false, want true")
	}
	wantValue, err := asn1.Marshal("custom-value")
	if err != nil {
		t.Fatalf("marshaling expected custom extension: %v", err)
	}
	if !bytes.Equal(extension.Value, wantValue) {
		t.Fatalf("custom extension value = %x, want %x", extension.Value, wantValue)
	}
}

func assertStringSlicesEqual(t *testing.T, got, want []string, name string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
}

func findExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, extension := range extensions {
		if extension.Id.Equal(oid) {
			return extension, true
		}
	}
	return pkix.Extension{}, false
}

func assertECDSAPublicKeyEqual(t *testing.T, want *ecdsa.PublicKey, got any) {
	t.Helper()

	gotKey, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", got)
	}
	if gotKey.Curve != want.Curve || gotKey.X.Cmp(want.X) != 0 || gotKey.Y.Cmp(want.Y) != 0 {
		t.Fatalf("ECDSA public key mismatch")
	}
}

func assertRSAPublicKeyEqual(t *testing.T, want *rsa.PublicKey, got any) {
	t.Helper()

	gotKey, ok := got.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *rsa.PublicKey", got)
	}
	if gotKey.E != want.E || gotKey.N.Cmp(want.N) != 0 {
		t.Fatalf("RSA public key mismatch")
	}
}

func assertECDSAAlgorithmParametersAbsent(t *testing.T, der []byte) {
	t.Helper()

	outer := parseOuterCSR(t, der)
	params := outer.SignatureAlgorithm.Parameters
	if len(params.FullBytes) != 0 || params.Tag != 0 {
		t.Fatalf("ECDSA algorithm parameters = %#v, want absent", params)
	}
}

func assertRSAAlgorithmParametersNull(t *testing.T, der []byte) {
	t.Helper()

	outer := parseOuterCSR(t, der)
	params := outer.SignatureAlgorithm.Parameters
	if params.Tag != asn1.TagNull || len(params.Bytes) != 0 {
		t.Fatalf("RSA algorithm parameters = %#v, want ASN.1 NULL", params)
	}
	if !bytes.Equal(params.FullBytes, []byte{0x05, 0x00}) {
		t.Fatalf("RSA algorithm parameter DER = %x, want 0500", params.FullBytes)
	}
}

func assertKMSDigest(t *testing.T, client *fakeKMSClient, keyID string, algorithm kmstypes.SigningAlgorithmSpec, digest []byte) {
	t.Helper()

	if client.signCalls != 1 {
		t.Fatalf("Sign calls = %d, want 1", client.signCalls)
	}
	if client.signKeyID != keyID {
		t.Fatalf("Sign key id = %q, want %q", client.signKeyID, keyID)
	}
	if client.messageTyp != kmstypes.MessageTypeDigest {
		t.Fatalf("Sign message type = %s, want %s", client.messageTyp, kmstypes.MessageTypeDigest)
	}
	if client.algorithm != algorithm {
		t.Fatalf("Sign algorithm = %s, want %s", client.algorithm, algorithm)
	}
	if !bytes.Equal(client.message, digest) {
		t.Fatalf("Sign digest = %x, want %x", client.message, digest)
	}
}

func sha256Digest(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha384Digest(data []byte) []byte {
	sum := sha512.Sum384(data)
	return sum[:]
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err, want)
	}
}
