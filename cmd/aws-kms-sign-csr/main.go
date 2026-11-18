// Copyright 2026 Andre Goncalves. All rights reserved.

package main

import (
	"context"
	"fmt"
	"io"
	"os"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfg, err := parseConfig(args, stderr)
	if err != nil {
		return err
	}

	var opts []func(*awsconfig.LoadOptions) error
	if cfg.region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.region))
	}
	if cfg.profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.profile))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	kmsClient := kms.NewFromConfig(awsCfg)
	return signCSR(ctx, cfg, kmsClient, stdout)
}

func signCSR(ctx context.Context, cfg config, kmsClient kmsClientAPI, stdout io.Writer) error {
	csrDER, err := readCSRDER(cfg.csrFile)
	if err != nil {
		return fmt.Errorf("reading CSR: %w", err)
	}

	kmsPubKeyDER, err := fetchKMSPublicKeyDER(ctx, kmsClient, cfg.keyID)
	if err != nil {
		return fmt.Errorf("fetching KMS public key: %w", err)
	}

	entry := algorithms[cfg.algorithm]

	signedDER, err := buildSignedCSR(ctx, kmsClient, csrDER, kmsPubKeyDER, entry, cfg.keyID)
	if err != nil {
		return fmt.Errorf("building signed CSR: %w", err)
	}

	if err := writeCSRPEM(stdout, signedDER); err != nil {
		return fmt.Errorf("writing PEM output: %w", err)
	}
	return nil
}
