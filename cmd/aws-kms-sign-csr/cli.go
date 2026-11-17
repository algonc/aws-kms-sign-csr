// Copyright 2026 Andre Goncalves. All rights reserved.

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

type config struct {
	csrFile   string
	keyID     string
	algorithm string
	region    string
	profile   string
}

func parseConfig(args []string, stderr io.Writer) (config, error) {
	flags := flag.NewFlagSet("aws-kms-sign-csr", flag.ContinueOnError)
	flags.SetOutput(stderr)

	csrFile := flags.String("csr", "", "Path to PEM-encoded CSR file (required)")
	keyID := flags.String("key-id", "", "AWS KMS key ID, ARN, or alias (required)")
	algorithm := flags.String("algorithm", "ecdsa-sha256", "Signing algorithm: ecdsa-sha256|ecdsa-sha384|ecdsa-sha512|rsa-sha256|rsa-sha384|rsa-sha512")
	region := flags.String("region", "", "AWS region (default: from environment)")
	profile := flags.String("profile", "", "AWS credentials profile (default: from environment)")

	if err := flags.Parse(args); err != nil {
		return config{}, err
	}

	if *csrFile == "" {
		flags.Usage()
		return config{}, fmt.Errorf("-csr is required")
	}
	if *keyID == "" {
		flags.Usage()
		return config{}, fmt.Errorf("-key-id is required")
	}
	if _, ok := algorithms[*algorithm]; !ok {
		return config{}, fmt.Errorf("unknown algorithm %q; valid choices: %s", *algorithm, strings.Join(supportedAlgorithmNames(), ", "))
	}

	return config{
		csrFile:   *csrFile,
		keyID:     *keyID,
		algorithm: *algorithm,
		region:    *region,
		profile:   *profile,
	}, nil
}
