// Copyright 2026 Andre Goncalves. All rights reserved.

package main

import (
	"context"
	"fmt"
	"os"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

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

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
