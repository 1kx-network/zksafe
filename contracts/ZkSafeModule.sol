// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.12;

import {UltraVerifier} from "../circuits/contract/circuits/plonk_vk.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "hardhat/console.sol";

/* @title ZkSafeModule
 * @dev This contract implements a module for Gnosis Safe that allows for zk-SNARK verification of transactions.
 */
contract ZkSafeModule {
    UltraVerifier verifier;

    constructor(UltraVerifier _verifier) {
        verifier = _verifier;
    }

    function zkSafeModuleVersion() public pure returns (string memory) {
        return "ZkSafeModule/v0.0.1";
    }

    // Basic representation of a Gnosis Safe transaction supported by zkSafe.
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
    }

    /*
     * @dev Enables a module on a Gnosis Safe contract.
     * @param module The address of the module to enable.
     */
    function enableModule(address module) external {
        address payable thisAddr = payable(address(this));
        GnosisSafe(thisAddr).enableModule(module);
    }

    function increaseNonce(uint256 nonce) public {
        // Nonce should be at 0x05 slot, but better verify this assumption.
        assembly {
            // Load the current nonce.
            let currentNonce := sload(0x05)
            // Check that the nonce is correct.
            if iszero(eq(currentNonce, nonce)) {
                revert(0, 0)
            }
            sstore(0x05, add(currentNonce, 1))
        }
    }

    /*
     * @dev Verifies a zk-SNARK proof for a Gnosis Safe transaction.
     * @param safeContract The address of the Gnosis Safe contract.
     * @param txHash The hash of the transaction to be verified.
     * @param proof The zk-SNARK proof.
     * @return True if the proof is valid, false otherwise.
     */
    function verifyZkSafeTransaction(
        GnosisSafe safeContract,
        bytes32 txHash,
        bytes calldata proof
    ) public view returns (bool) {
        // Construct the input to the circuit.
        // We need 33 + 6 * 20 = 153 bytes of public inputs.
        bytes32[] memory publicInputs = new bytes32[](1 + 32 + 6 * 20);

        // Threshold
        uint threshold = safeContract.getThreshold();
        require(threshold > 0, "Threshold must be greater than 0");
        require(threshold < 256, "Threshold must be less than 256");
        publicInputs[0] = bytes32(threshold);

        // Each byte of the transaction hash is given as a separate uint256 value.
        // TODO: this is super inefficient, fix by making the circuit take compressed inputs.
        for (uint256 i = 0; i < 32; i++) {
            publicInputs[i + 1] = bytes32(uint256(uint8(txHash[i])));
        }

        address[] memory owners = safeContract.getOwners();
        require(owners.length > 0, "No owners");
        require(owners.length <= 6, "Too many owners");

        // Each Address is unpacked into 20 separate bytes, each of which is given as a separate uint256 value.
        // TODO: this is super inefficient, fix by making the circuit take compressed inputs.
        for (uint256 i = 0; i < owners.length; i++) {
            for (uint256 j = 0; j < 20; j++) {
                publicInputs[i * 20 + j + 33] = bytes32(
                    uint256(uint8(bytes20(owners[i])[j]))
                );
            }
        }
        for (uint256 i = owners.length; i < 6; i++) {
            for (uint256 j = 0; j < 20; j++) {
                publicInputs[i * 20 + j + 33] = bytes32(0);
            }
        }
        // Get the owners of the Safe by calling into the Safe contract.
        return verifier.verify(proof, publicInputs);
    }

    /*
     * @dev Sends a transaction to a Gnosis Safe contract.
     * @param safeContract The address of the Gnosis Safe contract.
     * @param transaction The transaction to be sent.
     * @param proof The zk-SNARK proof.
     * @return True if the transaction was successful, false otherwise.
     */
    function sendZkSafeTransaction(
        GnosisSafe safeContract,
        // The Safe address to which the transaction will be sent.
        Transaction calldata transaction,
        // The proof blob.
        bytes calldata proof
    ) public payable virtual returns (bool) {
        uint256 nonce = safeContract.nonce();
        bytes32 txHash = keccak256(
            safeContract.encodeTransactionData(
                // Transaction info
                transaction.to,
                transaction.value,
                transaction.data,
                transaction.operation,
                0,
                // Payment info
                0,
                0,
                address(0),
                address(0),
                // Signature info
                nonce
            )
        );
        require(verifyZkSafeTransaction(safeContract, txHash, proof), "Invalid proof");
        // All checks are successful, can execute the transaction.

        // Safe doesn't increase the nonce for module transactions, so we need to take care of that.
        bytes memory data = abi.encodeWithSignature("increaseNonce(uint256)", nonce);
        // We increase nonce by having Safe call us back at the increaseNonce() method as delegatecall
        safeContract.execTransactionFromModule(
            payable(address(this)),
            0,
            data,
            Enum.Operation.DelegateCall
        );
        // must check this, as it can fail on an incompatible Safe contract version.
        require(safeContract.nonce() == nonce + 1, "Nonce not increased");

        // All clean: can run the transaction.
        return safeContract.execTransactionFromModule(
            transaction.to,
            transaction.value,
            transaction.data,
                transaction.operation
            );
    }
}
