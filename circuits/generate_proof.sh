#!/bin/bash
# @file generate_proof.sh
# @description Generates a ZK proof for a circuit with given inputs
# @usage ./generate_proof.sh <circuit_name> <input.json> [output_dir]
#
# Example: ./generate_proof.sh AgeThreshold test/age_input.json
#
# Outputs:
#   - <output_dir>/proof.json - The ZK proof
#   - <output_dir>/public.json - Public inputs/outputs
#   - <output_dir>/calldata.txt - Solidity calldata for on-chain verification

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${CIRCUITS_DIR}/build"
KEYS_DIR="${CIRCUITS_DIR}/keys"

# Check arguments
if [ -z "$1" ] || [ -z "$2" ]; then
    echo -e "${RED}Error: Missing arguments${NC}"
    echo "Usage: ./generate_proof.sh <circuit_name> <input.json> [output_dir]"
    echo "Example: ./generate_proof.sh AgeThreshold test/age_input.json"
    exit 1
fi

CIRCUIT_NAME="$1"
INPUT_FILE="$2"
OUTPUT_DIR="${3:-${BUILD_DIR}/proofs/${CIRCUIT_NAME}}"

# Resolve input file path
if [[ "$INPUT_FILE" != /* ]]; then
    INPUT_FILE="${CIRCUITS_DIR}/${INPUT_FILE}"
fi

# Check required files
WASM_FILE="${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm"
ZKEY_FILE="${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey"

if [ ! -f "$WASM_FILE" ]; then
    echo -e "${RED}Error: WASM file not found: ${WASM_FILE}${NC}"
    echo "Run ./compile.sh ${CIRCUIT_NAME} first"
    exit 1
fi

if [ ! -f "$ZKEY_FILE" ]; then
    echo -e "${RED}Error: Proving key not found: ${ZKEY_FILE}${NC}"
    echo "Run ./setup.sh ${CIRCUIT_NAME} first"
    exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}Error: Input file not found: ${INPUT_FILE}${NC}"
    exit 1
fi

# Create output directory
mkdir -p "${OUTPUT_DIR}"

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Generating proof: ${CIRCUIT_NAME}${NC}"
echo -e "${YELLOW}========================================${NC}"
echo "Input file: ${INPUT_FILE}"
echo "Output dir: ${OUTPUT_DIR}"

# Generate witness
echo -e "\n${GREEN}[1/4] Generating witness...${NC}"
WITNESS_FILE="${OUTPUT_DIR}/witness.wtns"

node "${BUILD_DIR}/${CIRCUIT_NAME}_js/generate_witness.js" \
    "$WASM_FILE" \
    "$INPUT_FILE" \
    "$WITNESS_FILE"

# Generate proof
echo -e "\n${GREEN}[2/4] Generating Groth16 proof...${NC}"
START_TIME=$(date +%s.%N)

npx snarkjs groth16 prove \
    "$ZKEY_FILE" \
    "$WITNESS_FILE" \
    "${OUTPUT_DIR}/proof.json" \
    "${OUTPUT_DIR}/public.json"

END_TIME=$(date +%s.%N)
PROOF_TIME=$(echo "$END_TIME - $START_TIME" | bc)

echo "Proof generation time: ${PROOF_TIME}s"

# Verify proof locally
echo -e "\n${GREEN}[3/4] Verifying proof locally...${NC}"
VERIFICATION_KEY="${KEYS_DIR}/${CIRCUIT_NAME}_verification_key.json"

npx snarkjs groth16 verify \
    "$VERIFICATION_KEY" \
    "${OUTPUT_DIR}/public.json" \
    "${OUTPUT_DIR}/proof.json"

# Generate Solidity calldata
echo -e "\n${GREEN}[4/4] Generating Solidity calldata...${NC}"
npx snarkjs zkey export soliditycalldata \
    "${OUTPUT_DIR}/public.json" \
    "${OUTPUT_DIR}/proof.json" > "${OUTPUT_DIR}/calldata.txt"

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${GREEN}Proof generated successfully!${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""
echo "Output files:"
echo "  - ${OUTPUT_DIR}/proof.json"
echo "  - ${OUTPUT_DIR}/public.json"
echo "  - ${OUTPUT_DIR}/calldata.txt"
echo ""
echo "Public signals:"
cat "${OUTPUT_DIR}/public.json"
echo ""
echo ""
echo "To verify on-chain:"
echo "  1. Deploy ${CIRCUIT_NAME}Verifier.sol"
echo "  2. Call verifyProof() with calldata from calldata.txt"

# Cleanup witness file (optional - contains private data)
# rm -f "${OUTPUT_DIR}/witness.wtns"
