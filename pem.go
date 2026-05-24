package main

import (
	"encoding/pem"
	"fmt"
	"os"
)

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

func outputPEM(der []byte) {
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}); err != nil {
		fatalf("writing PEM output: %v", err)
	}
}
