#!/bin/sh
# Check private key consistency for all ML DSA PKITS variant artifacts.
#
# For each PKCS12 in each ML DSA PKITS variant:
#   1. Extract the private key with openssl (same method as dump_ee_keys.sh)
#   2. Run kemri_toy --check-private-key against the corresponding EE cert

set -e

PKITS_TARGET="${1:-$HOME/devel/redhound/pcp-rs/target}"
KEMRI_TOY="${2:-$HOME/devel/junk/kemri_toy/target/debug/kemri_toy}"

TMPDIR_KEYS=$(mktemp -d)
trap 'rm -rf "$TMPDIR_KEYS"' EXIT

pass=0
fail=0
skip=0

for variant_dir in "$PKITS_TARGET"/pkits_ml_dsa_*/; do
    variant=$(basename "$variant_dir")
    p12_dir="$variant_dir/pkcs12"
    cert_dir="$variant_dir/certs"

    if [ ! -d "$p12_dir" ]; then
        echo "[SKIP] No pkcs12 dir for $variant"
        continue
    fi

    echo ""
    echo "=== $variant ==="

    for p12 in "$p12_dir"/*.p12; do
        base=$(basename "$p12" .p12)

        # Strip _both / _expanded / _seed suffix to find the matching cert
        cert_name=$(echo "$base" | sed 's/_both$//;s/_expanded$//;s/_seed$//')
        cert_file="$cert_dir/${cert_name}.der"

        if [ ! -f "$cert_file" ]; then
            echo "[SKIP] $base — no cert: $cert_file"
            skip=$((skip + 1))
            continue
        fi

        # Extract key to PEM then convert to DER (mirrors dump_ee_keys.sh)
        pem_out="$TMPDIR_KEYS/${base}.pem"
        der_out="$TMPDIR_KEYS/${base}.der"

        if ! openssl pkcs12 -in "$p12" -nodes -nocerts -passin pass:password \
                -out "$pem_out" 2>/dev/null; then
            echo "[SKIP] $base — openssl pkcs12 extraction failed"
            skip=$((skip + 1))
            continue
        fi

        if ! openssl pkey -in "$pem_out" -outform DER -out "$der_out" 2>/dev/null; then
            echo "[SKIP] $base — openssl pkey DER conversion failed"
            skip=$((skip + 1))
            continue
        fi

        # Run kemri_toy private key consistency check
        if "$KEMRI_TOY" --input-file "$der_out" \
                        --ee-cert-file "$cert_file" \
                        --check-private-key 2>&1; then
            echo "[PASS] $base"
            pass=$((pass + 1))
        else
            echo "[FAIL] $base"
            fail=$((fail + 1))
        fi

        rm -f "$pem_out" "$der_out"
    done
done

echo ""
echo "=== Summary ==="
echo "  Pass: $pass"
echo "  Fail: $fail"
echo "  Skip: $skip"
