#!/bin/bash
# @file compile.sh
# @description Compiles a circom circuit and generates artifacts
# @usage ./compile.sh <circuit_name>
#
# Example: ./compile.sh AgeThreshold
#
# Outputs:
#   - build/<circuit>.r1cs - Rank-1 Constraint System
#   - build/<circuit>.wasm - WebAssembly witness generator
#   - build/<circuit>.sym - Symbol file for debugging

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CIRCUITS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${CIRCUITS_DIR}/build"
NODE_MODULES="${CIRCUITS_DIR}/../node_modules"

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}Error: No circuit name provided${NC}"
    echo "Usage: ./compile.sh <circuit_name>"
    echo "Example: ./compile.sh AgeThreshold"
    exit 1
fi

CIRCUIT_NAME="$1"
CIRCUIT_FILE="${CIRCUITS_DIR}/${CIRCUIT_NAME}.circom"

# Check if circuit file exists
if [ ! -f "$CIRCUIT_FILE" ]; then
    echo -e "${RED}Error: Circuit file not found: ${CIRCUIT_FILE}${NC}"
    exit 1
fi

# Create build directory
mkdir -p "${BUILD_DIR}"

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Compiling circuit: ${CIRCUIT_NAME}${NC}"
echo -e "${YELLOW}========================================${NC}"

# Check if circom is installed
if ! command -v circom &> /dev/null; then
    echo -e "${RED}Error: circom is not installed${NC}"
    echo "Install with: npm install -g circom"
    echo "Or: cargo install circom"
    exit 1
fi

# Compile circuit
echo -e "\n${GREEN}[1/3] Compiling circom circuit...${NC}"
circom "$CIRCUIT_FILE" \
    --r1cs \
    --wasm \
    --sym \
    --output "$BUILD_DIR" \
    -l "$NODE_MODULES"

# Check compilation results
R1CS_FILE="${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"
WASM_DIR="${BUILD_DIR}/${CIRCUIT_NAME}_js"

if [ ! -f "$R1CS_FILE" ]; then
    echo -e "${RED}Error: R1CS file was not generated${NC}"
    exit 1
fi

echo -e "\n${GREEN}[2/3] Analyzing constraints...${NC}"
# Get constraint info using snarkjs
if command -v snarkjs &> /dev/null; then
    echo "R1CS Info:"
    npx snarkjs r1cs info "$R1CS_FILE"
else
    echo "snarkjs not found, skipping constraint analysis"
fi

echo -e "\n${GREEN}[3/3] Build complete!${NC}"
echo -e "Output files:"
echo -e "  - ${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"
echo -e "  - ${BUILD_DIR}/${CIRCUIT_NAME}.sym"
echo -e "  - ${WASM_DIR}/"

# Print constraint count
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${GREEN}Circuit compiled successfully!${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Run setup: ./setup.sh ${CIRCUIT_NAME}"
echo "  2. Generate proof: ./generate_proof.sh ${CIRCUIT_NAME} <input.json>"
