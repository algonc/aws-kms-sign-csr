// Copyright 2026 Andre Goncalves. All rights reserved.

package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"hash"
	"sort"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

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

func supportedAlgorithmNames() []string {
	names := make([]string, 0, len(algorithms))
	for name := range algorithms {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
