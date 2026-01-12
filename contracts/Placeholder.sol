// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/**
 * @title Placeholder
 * @notice Temporary placeholder contract to verify Hardhat compilation works
 * @dev This file will be removed when actual contracts are implemented
 */
contract Placeholder {
    string public constant VERSION = "0.1.0-alpha";

    function getVersion() external pure returns (string memory) {
        return VERSION;
    }
}
