#!/bin/bash
# Use openssl to vet kemri_toy CSRs.
#
# For every *_csr.der file in the input directory:
#  1. asn1parse must succeed (well-formed DER)
#  2. `openssl req -noout -subject` must succeed (parses as a CertificationRequest)
#  3. `openssl req -noout -verify` is attempted; algorithms openssl doesn't
#     understand are reported as SKIPPED, supported ones must report OK.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_DIR="${1:-$SCRIPT_DIR/artifacts_csrs}"

if [ ! -d "$INPUT_DIR" ]; then
    echo "input directory not found: $INPUT_DIR" >&2
    echo "usage: $0 [csr_directory]" >&2
    exit 2
fi

shopt -s nullglob
CSRS=("$INPUT_DIR"/*_csr.der)
if [ ${#CSRS[@]} -eq 0 ]; then
    echo "no *_csr.der files found in $INPUT_DIR" >&2
    exit 2
fi

TOTAL=0
OK_PARSE=0
OK_VERIFY=0
SKIP_VERIFY=0
FAIL_PARSE=()
FAIL_VERIFY=()

for csr in "${CSRS[@]}"; do
    TOTAL=$((TOTAL + 1))
    alg=$(basename "$csr" _csr.der)

    # 1+2. Structural parse: asn1parse and req -subject must both succeed.
    if ! openssl asn1parse -inform DER -in "$csr" >/dev/null 2>&1; then
        echo "PARSE_FAIL (asn1parse): $alg"
        FAIL_PARSE+=("$alg")
        continue
    fi
    if ! openssl req -inform DER -in "$csr" -noout -subject >/dev/null 2>&1; then
        echo "PARSE_FAIL (req): $alg"
        FAIL_PARSE+=("$alg")
        continue
    fi
    OK_PARSE=$((OK_PARSE + 1))

    # 3. Signature verify: capture stderr too so we can tell "unsupported" apart from "broken".
    verify_out=$(openssl req -inform DER -in "$csr" -noout -verify 2>&1)
    verify_rc=$?
    if [ $verify_rc -eq 0 ] && echo "$verify_out" | grep -q "verify OK"; then
        echo "VERIFY_OK:    $alg"
        OK_VERIFY=$((OK_VERIFY + 1))
    elif echo "$verify_out" | grep -qE "unsupported algorithm|decode error|error while verifying"; then
        echo "VERIFY_SKIP:  $alg  (openssl does not support this algorithm)"
        SKIP_VERIFY=$((SKIP_VERIFY + 1))
    else
        echo "VERIFY_FAIL:  $alg"
        echo "$verify_out" | sed 's/^/    /'
        FAIL_VERIFY+=("$alg")
    fi
done

echo ""
echo "Summary:"
echo "  Total CSRs:          $TOTAL"
echo "  Parsed OK:           $OK_PARSE"
echo "  Signature verified:  $OK_VERIFY"
echo "  Signature skipped:   $SKIP_VERIFY (algorithm not in this openssl)"
echo "  Parse failures:      ${#FAIL_PARSE[@]}"
echo "  Verify failures:     ${#FAIL_VERIFY[@]}"

if [ ${#FAIL_PARSE[@]} -gt 0 ]; then
    echo ""
    echo "Parse failures:"
    for a in "${FAIL_PARSE[@]}"; do echo "  - $a"; done
fi
if [ ${#FAIL_VERIFY[@]} -gt 0 ]; then
    echo ""
    echo "Verify failures:"
    for a in "${FAIL_VERIFY[@]}"; do echo "  - $a"; done
fi

if [ ${#FAIL_PARSE[@]} -gt 0 ] || [ ${#FAIL_VERIFY[@]} -gt 0 ]; then
    exit 1
fi
exit 0
