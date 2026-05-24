package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

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
