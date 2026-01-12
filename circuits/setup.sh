#!/bin/bash
# @file setup.sh
# @description Performs trusted setup for a compiled circuit
# @usage ./setup.sh <circuit_name> [ptau_file]
#
# Example: ./setup.sh AgeThreshold
# Example: ./setup.sh AgeThreshold pot15_final.ptau
#
# Outputs:
#   - keys/<circuit>_0000.zkey - Initial proving key
#   - keys/<circuit>_final.zkey - Final proving key (after contribution)
#   - keys/<circuit>_verification_key.json - Verification key
#   - contracts/verifiers/<circuit>Verifier.sol - Solidity verifier

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${CIRCUITS_DIR}/build"
KEYS_DIR="${CIRCUITS_DIR}/keys"
CONTRACTS_DIR="${CIRCUITS_DIR}/../contracts/verifiers"
PTAU_DIR="${CIRCUITS_DIR}/ptau"

# Default Powers of Tau file (pot12 supports up to 2^12 = 4096 constraints)
# For larger circuits, use pot14, pot16, etc.
DEFAULT_PTAU="pot12_final.ptau"

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}Error: No circuit name provided${NC}"
    echo "Usage: ./setup.sh <circuit_name> [ptau_file]"
    echo "Example: ./setup.sh AgeThreshold"
    exit 1
fi

CIRCUIT_NAME="$1"
PTAU_FILE="${2:-$DEFAULT_PTAU}"
R1CS_FILE="${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"

# Check if R1CS exists
if [ ! -f "$R1CS_FILE" ]; then
    echo -e "${RED}Error: R1CS file not found: ${R1CS_FILE}${NC}"
    echo "Run ./compile.sh ${CIRCUIT_NAME} first"
    exit 1
fi

# Create directories
mkdir -p "${KEYS_DIR}"
mkdir -p "${CONTRACTS_DIR}"
mkdir -p "${PTAU_DIR}"

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Setting up circuit: ${CIRCUIT_NAME}${NC}"
echo -e "${YELLOW}========================================${NC}"

# Check for Powers of Tau file
PTAU_PATH="${PTAU_DIR}/${PTAU_FILE}"
if [ ! -f "$PTAU_PATH" ]; then
    echo -e "\n${BLUE}Powers of Tau file not found: ${PTAU_PATH}${NC}"
    echo -e "Downloading from Hermez ceremony..."

    # Determine which ptau to download based on filename
    PTAU_NUM=$(echo "$PTAU_FILE" | grep -oP 'pot\K[0-9]+' || echo "12")
    PTAU_URL="https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_${PTAU_NUM}.ptau"

    echo "Downloading: ${PTAU_URL}"
    curl -L -o "$PTAU_PATH" "$PTAU_URL" || {
        echo -e "${RED}Failed to download Powers of Tau file${NC}"
        echo "You can manually download from:"
        echo "  https://github.com/iden3/snarkjs#7-prepare-phase-2"
        exit 1
    }
fi

echo -e "\n${GREEN}[1/5] Starting Groth16 setup...${NC}"
npx snarkjs groth16 setup "$R1CS_FILE" "$PTAU_PATH" "${KEYS_DIR}/${CIRCUIT_NAME}_0000.zkey"

echo -e "\n${GREEN}[2/5] Contributing to ceremony...${NC}"
# In production, multiple parties should contribute
# For development, we use a deterministic contribution
echo "Development contribution" | npx snarkjs zkey contribute \
    "${KEYS_DIR}/${CIRCUIT_NAME}_0000.zkey" \
    "${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey" \
    --name="Development Contribution" -v

echo -e "\n${GREEN}[3/5] Exporting verification key...${NC}"
npx snarkjs zkey export verificationkey \
    "${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey" \
    "${KEYS_DIR}/${CIRCUIT_NAME}_verification_key.json"

echo -e "\n${GREEN}[4/5] Generating Solidity verifier...${NC}"
npx snarkjs zkey export solidityverifier \
    "${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey" \
    "${CONTRACTS_DIR}/${CIRCUIT_NAME}Verifier.sol"

# Update Solidity version in generated verifier
echo -e "\n${GREEN}[5/5] Updating Solidity version...${NC}"
sed -i 's/pragma solidity \^0\.6\.11/pragma solidity \^0\.8\.28/' \
    "${CONTRACTS_DIR}/${CIRCUIT_NAME}Verifier.sol"

# Add license identifier
sed -i '1s/^/\/\/ SPDX-License-Identifier: GPL-3.0\n/' \
    "${CONTRACTS_DIR}/${CIRCUIT_NAME}Verifier.sol"

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${GREEN}Setup complete!${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""
echo "Output files:"
echo "  - ${KEYS_DIR}/${CIRCUIT_NAME}_final.zkey (Proving key)"
echo "  - ${KEYS_DIR}/${CIRCUIT_NAME}_verification_key.json"
echo "  - ${CONTRACTS_DIR}/${CIRCUIT_NAME}Verifier.sol"
echo ""
echo "Next steps:"
echo "  1. Generate proof: ./generate_proof.sh ${CIRCUIT_NAME} <input.json>"
echo "  2. Deploy verifier contract: npx hardhat run scripts/deploy-verifier.ts"
