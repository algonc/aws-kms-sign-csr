BIN        := bin/aws-kms-sign-csr

KEY_ID           ?=
ALGORITHM        ?= ecdsa-sha256
REGION           ?=
CONFIG           ?=
OUTPUT_DIR       ?=
CHECK_PUBLIC_KEY ?= false

TMP_DIR     = $(OUTPUT_DIR)/.tmp
TMP_CSR     = $(TMP_DIR)/original.csr
TMP_SIGNED  = $(TMP_DIR)/signed.csr
TMP_KMS_PUB = $(TMP_DIR)/kms_pub.pem
TMP_CSR_PUB = $(TMP_DIR)/csr_pub.pem

.PHONY: all build csr clean

all: build

build: $(BIN)

$(BIN): main.go go.mod
	@mkdir -p bin
	go build -o $(BIN) .

csr: $(BIN)
	@# Validate required variables
	@test -n "$(KEY_ID)"    || { echo "error: KEY_ID is not set"; exit 1; }
	@test -n "$(REGION)"    || { echo "error: REGION is not set"; exit 1; }
	@test -n "$(CONFIG)"    || { echo "error: CONFIG is not set"; exit 1; }
	@test -n "$(OUTPUT_DIR)" || { echo "error: OUTPUT_DIR is not set"; exit 1; }

	@# Validate that openssl is available
	@command -v openssl >/dev/null 2>&1 || { echo "error: openssl not found in PATH"; exit 1; }

	@# Validate that the config file exists
	@test -f "$(CONFIG)" || { echo "error: config file not found: $(CONFIG)"; exit 1; }

	@# Create output and temp directories if they do not exist
	@mkdir -p "$(OUTPUT_DIR)" "$(TMP_DIR)"

	@# Generate CSR with a throwaway key — key parameters are irrelevant, only subject/extensions are kept
	@echo "==> Generating CSR from $(CONFIG)"
	openssl req -new -newkey rsa:1024 -nodes -keyout /dev/null \
	  -config "$(CONFIG)" \
	  -out "$(TMP_CSR)" 2>/dev/null

	@# Sign the CSR with the KMS key
	@echo "==> Signing CSR with KMS key $(KEY_ID)"
	$(BIN) \
	  -csr "$(TMP_CSR)" \
	  -key-id "$(KEY_ID)" \
	  -algorithm "$(ALGORITHM)" \
	  -region "$(REGION)" \
	  > "$(TMP_SIGNED)"

	@# Copy signed CSR to output directory
	cp "$(TMP_SIGNED)" "$(OUTPUT_DIR)/signed.csr"
	@echo "==> Signed CSR written to $(OUTPUT_DIR)/signed.csr"

	@# Inspect and verify the signed CSR
	@echo ""
	@echo "==> CSR contents"
	openssl req -in "$(TMP_SIGNED)" -text -noout
	@echo ""
	@echo "==> Signature verification"
	openssl req -in "$(TMP_SIGNED)" -verify -noout

	@# Optionally compare the CSR public key against the KMS public key
	@if [ "$(CHECK_PUBLIC_KEY)" = "true" ]; then \
	  echo ""; \
	  echo "==> Downloading public key from KMS"; \
	  aws kms get-public-key \
	    --key-id "$(KEY_ID)" \
	    --region "$(REGION)" \
	    --query PublicKey \
	    --output text | base64 -d \
	    | openssl pkey -pubin -inform DER -pubout -out "$(TMP_KMS_PUB)"; \
	  echo "==> Extracting public key from signed CSR"; \
	  openssl req -in "$(TMP_SIGNED)" -noout -pubkey -out "$(TMP_CSR_PUB)"; \
	  echo ""; \
	  echo "==> KMS public key details"; \
	  openssl pkey -pubin -in "$(TMP_KMS_PUB)" -text -noout; \
	  echo "==> CSR public key details"; \
	  openssl pkey -pubin -in "$(TMP_CSR_PUB)" -text -noout; \
	  echo ""; \
	  echo "==> Comparing public keys"; \
	  diff -u "$(TMP_KMS_PUB)" "$(TMP_CSR_PUB)" || { echo "error: public keys do not match"; exit 1; }; \
	  echo "Public keys match"; \
	fi

clean:
	rm -f $(BIN)
	@rmdir bin 2>/dev/null || true
	@if [ -n "$(OUTPUT_DIR)" ]; then rm -rf "$(TMP_DIR)"; fi
