// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {
    ICompoundProofVerifier,
    ICompoundProof3Verifier,
    ICompoundProof4Verifier
} from "../verifiers/IGroth16Verifier.sol";

/**
 * @title MockCompoundVerifier
 * @notice Mock compound proof verifier for testing
 * @dev Implements all compound proof verifier interfaces (2, 3, 4 disclosures)
 */
contract MockCompoundVerifier is
    ICompoundProofVerifier,
    ICompoundProof3Verifier,
    ICompoundProof4Verifier
{
    /// @notice Whether to accept all proofs (for positive path testing)
    bool public acceptAll;

    /// @notice Counter for verification calls (for testing)
    uint256 public verificationCount;

    /// @notice Last public signals received (for inspection)
    uint256[] public lastPubSignals;

    /// @notice Events
    event ProofVerified(uint256 numDisclosures, bool result);

    constructor() {
        acceptAll = true;
    }

    /**
     * @notice Set whether to accept all proofs
     * @param _acceptAll True to accept all proofs
     */
    function setAcceptAll(bool _acceptAll) external {
        acceptAll = _acceptAll;
    }

    /**
     * @notice Verify a compound proof with 2 disclosures
     */
    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[11] calldata _pubSignals
    ) external override returns (bool) {
        verificationCount++;

        // Store public signals for inspection
        delete lastPubSignals;
        for (uint i = 0; i < 11; i++) {
            lastPubSignals.push(_pubSignals[i]);
        }

        emit ProofVerified(2, acceptAll);
        return acceptAll;
    }

    /**
     * @notice Verify a compound proof with 3 disclosures
     * @dev Implements ICompoundProof3Verifier
     */
    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[16] calldata _pubSignals
    ) external override returns (bool) {
        verificationCount++;

        // Store public signals for inspection
        delete lastPubSignals;
        for (uint i = 0; i < 16; i++) {
            lastPubSignals.push(_pubSignals[i]);
        }

        emit ProofVerified(3, acceptAll);
        return acceptAll;
    }

    /**
     * @notice Verify a compound proof with 4 disclosures
     * @dev Implements ICompoundProof4Verifier
     */
    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[21] calldata _pubSignals
    ) external override returns (bool) {
        verificationCount++;

        // Store public signals for inspection
        delete lastPubSignals;
        for (uint i = 0; i < 21; i++) {
            lastPubSignals.push(_pubSignals[i]);
        }

        emit ProofVerified(4, acceptAll);
        return acceptAll;
    }

    /**
     * @notice Reset verification counter
     */
    function resetCounter() external {
        verificationCount = 0;
    }

    /**
     * @notice Get last received public signals
     */
    function getLastPubSignals() external view returns (uint256[] memory) {
        return lastPubSignals;
    }
}
