#!/bin/bash
# Generate certificate artifacts for all supported signature algorithms
# and package them into artifacts_certs_r5.zip matching the pqc-certificates
# provider format.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR/artifacts_certs_r5}"
ZIP_FILE="${2:-$SCRIPT_DIR/artifacts_certs_r5.zip}"

# Build in release mode for faster SLH-DSA key generation
echo "Building kemri_toy (release)..."
cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"
KEMRI_TOY="$SCRIPT_DIR/target/release/kemri_toy"

# Create clean output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# All signature algorithms that kemri_toy can generate certificates for.
# Excludes algorithms that use todo!() (ed25519, ed448 variants).
ALGORITHMS=(
    # Pure ML-DSA
    ml-dsa44
    ml-dsa65
    ml-dsa87

    # Pure SLH-DSA SHA-2
    slh-dsa-sha2-128s
    slh-dsa-sha2-128f
    slh-dsa-sha2-192s
    slh-dsa-sha2-192f
    slh-dsa-sha2-256s
    slh-dsa-sha2-256f

    # Pure SLH-DSA SHAKE
    slh-dsa-shake-128s
    slh-dsa-shake-128f
    slh-dsa-shake-192s
    slh-dsa-shake-192f
    slh-dsa-shake-256s
    slh-dsa-shake-256f

    # Hash ML-DSA
    hash-ml-dsa44-with-sha512
    hash-ml-dsa65-with-sha512
    hash-ml-dsa87-with-sha512

    # Hash SLH-DSA SHA-2
    hash-slh-dsa-sha2-128s-with-sha256
    hash-slh-dsa-sha2-128f-with-sha256
    hash-slh-dsa-sha2-192s-with-sha512
    hash-slh-dsa-sha2-192f-with-sha512
    hash-slh-dsa-sha2-256s-with-sha512
    hash-slh-dsa-sha2-256f-with-sha512

    # Hash SLH-DSA SHAKE
    hash-slh-dsa-shake-128s-with-shake128
    hash-slh-dsa-shake-128f-with-shake128
    hash-slh-dsa-shake-192s-with-shake256
    hash-slh-dsa-shake-192f-with-shake256
    hash-slh-dsa-shake-256s-with-shake256
    hash-slh-dsa-shake-256f-with-shake256

    # Composite ML-DSA (excluding ed25519/ed448 todo! variants)
    ml-dsa44-rsa2048-pss-sha256
    ml-dsa44-rsa2048-pkcs15-sha256
    ml-dsa44-ecdsa-p256-sha256
    ml-dsa65-rsa3072-pss-sha512
    ml-dsa65-rsa4096-pss-sha512
    ml-dsa65-rsa4096-pkcs15-sha512
    ml-dsa65-ecdsa-p256-sha512
    ml-dsa65-ecdsa-p384-sha512
    ml-dsa87-ecdsa-p384-sha512
    ml-dsa87-rsa3072-pss-sha512
    ml-dsa87-rsa4096-pss-sha512
    ml-dsa87-ecdsa-p521-sha512
)

TOTAL=${#ALGORITHMS[@]}
SUCCESS=0
FAIL=0
FAILED_ALGS=()

for alg in "${ALGORITHMS[@]}"; do
    echo -n "Generating $alg... "
    if "$KEMRI_TOY" --generate-cert --sig "$alg" --output-folder "$OUTPUT_DIR" 2>/dev/null; then
        echo "ok"
        SUCCESS=$((SUCCESS + 1))
    else
        echo "FAILED"
        FAIL=$((FAIL + 1))
        FAILED_ALGS+=("$alg")
    fi
done

echo ""
echo "Generated $SUCCESS/$TOTAL algorithms successfully."
if [ $FAIL -gt 0 ]; then
    echo "Failed algorithms:"
    for alg in "${FAILED_ALGS[@]}"; do
        echo "  - $alg"
    done
fi

# Count generated files
FILE_COUNT=$(find "$OUTPUT_DIR" -type f | wc -l | tr -d ' ')
echo "Total files: $FILE_COUNT"

# Create zip
rm -f "$ZIP_FILE"
(cd "$(dirname "$OUTPUT_DIR")" && zip -r "$ZIP_FILE" "$(basename "$OUTPUT_DIR")" -x '*.DS_Store' -x '__MACOSX/*')

echo ""
echo "Artifacts packaged: $ZIP_FILE"
