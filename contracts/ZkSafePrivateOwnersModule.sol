// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.12;

import {HonkVerifier as PublicOwnersVerifier} from "../noir/target/Verifier.sol";
import {HonkVerifier as PrivateOwnersVerifier} from "../noir/target/PrivateOwnersVerifier.sol";
import "@safe-global/safe-contracts/contracts/common/Enum.sol";
import "@safe-global/safe-contracts/contracts/Safe.sol";
import "hardhat/console.sol";


/* @title ZkSafePrivateOwnersModule
 * @dev This contract implements a module for Safe that allows for zk-SNARK verification of transactions,
 *      hiding the owners of the Safe.
 */
contract ZkSafePrivateOwnersModule {
    PublicOwnersVerifier publicVerifier;  // Verifier for the public owners circuit.
    PrivateOwnersVerifier privateVerifier;  // Verifier for the private owners circuit.
    address immutable zkSafeModuleAddress;

    struct zkSafeConfig {
        // Owner root
        bytes32 ownersRoot;

        // Threshold
        uint256 threshold;
    }

    // if the Safe doesn't have private owners configured, ownersRoot will be bytes32(0).
    mapping(Safe => zkSafeConfig) public safeToConfig;

    constructor(PublicOwnersVerifier _publicVerifier, PrivateOwnersVerifier _privateVerifier) {
        publicVerifier = _publicVerifier;
        privateVerifier = _privateVerifier;
        zkSafeModuleAddress = address(this);
    }

    function zkSafeModuleVersion() public pure returns (string memory) {
        return "ZkSafeModule/v2.0.0";
    }

    // Basic representation of a Safe{Wallet} transaction supported by zkSafe.
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
    }

    /*
     * @dev Enables a module on a Safe contract.
     * @param ownersRoot Owners Merkle tree root.
     * @param threshold Number of required confirmations for a zkSafe transaction.
    */
    function enableModule(bytes32 ownersRoot, uint256 threshold) external {
        updateZkMultisigConf(ownersRoot, threshold);
    }

     /*
     * @dev Update the zk multisg config for the msg.sender, which should be a zkSafe that wants to implement this module
     * @param ownersRoot Owners Merkle tree root.
     * @param threshold Number of required signaures.
     */
    function updateZkMultisigConf(bytes32 ownersRoot, uint256 threshold) external {
        require(threshold >= 1 , "Threshold must be 1 or more");
        require(threshold < 256, "Threshold must be less than 256");

        safeToConfig[Safe(payable(msg.sender))] = zkSafeConfig({
            ownersRoot: ownersRoot,
            threshold: threshold
        });
    }

    function increaseNonce(uint256 nonce) public {
        // only let call this via delegate call
        require(address(this) != zkSafeModuleAddress);

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
     * @dev Verifies a zk-SNARK proof for a Safe transaction with private owners.
     * @param safeContract The address of the Gnosis Safe contract.
     * @param txHash The hash of the transaction to be verified.
     * @param proof The zk-SNARK proof for the private owners circuit.
     * @return True if the proof is valid, false otherwise.
     */
    function verifyZkSafeTransaction(
        Safe safeContract,
        bytes32 txHash,
        bool usePrivateOwners,
        bytes calldata proof
    ) public view returns (bool) {
        zkSafeConfig memory currentSafeConfig = safeToConfig[safeContract];

        // Construct the input to the circuit.
        uint inputsSize = usePrivateOwners ?
            (1 + 32 + 1)  // threshold + txHash + ownersRoot
            :
            (1 + 32 + 10 * 20); // threshold + txHash + owners (max 10 owners, each unpacked into 20 bytes)
        bytes32[] memory publicInputs = new bytes32[](inputsSize);

        // Threshold
        publicInputs[0] = bytes32(uint256(currentSafeConfig.threshold));

        // Each byte of the transaction hash is given as a separate uint256 value.
        for (uint256 i = 0; i < 32; i++) {
            publicInputs[i+1] = bytes32(uint256(uint8(txHash[i])));
        }

        if (usePrivateOwners) {
            // ownersRoot
            publicInputs[33] = bytes32(currentSafeConfig.ownersRoot);
            return privateVerifier.verify(proof, publicInputs);
        } else {

            // Get the owners of the Safe by calling into the Safe contract.
            address[] memory owners = safeContract.getOwners();
            require(owners.length > 0, "No owners");
            require(owners.length <= 10, "Too many owners");

            // Each Address is unpacked into 20 separate bytes, each of which is given as a separate uint256 value.
            // TODO: this is super inefficient, fix by making the circuit take compressed inputs.
            for (uint256 i = 0; i < owners.length; i++) {
                for (uint256 j = 0; j < 20; j++) {
                    publicInputs[i * 20 + j + 33] = bytes32(
                                                            uint256(uint8(bytes20(owners[i])[j]))
                    );
                }
            }
            for (uint256 i = owners.length; i < 10; i++) {
                for (uint256 j = 0; j < 20; j++) {
                    publicInputs[i * 20 + j + 33] = bytes32(0);
                }
            }

            // Get the owners of the Safe by calling into the Safe contract.
            return publicVerifier.verify(proof, publicInputs);
        }
    }

    /*
     * @dev Sends a transaction to a Safe contract.
     * @param safeContract The address of the Safe contract.
     * @param transaction The transaction to be sent.
     * @param proof The zk-SNARK proof.
     * @return True if the transaction was successful, false otherwise.
     */
    function sendZkSafeTransaction(
        Safe safeContract,
        // The Safe address to which the transaction will be sent.
        Transaction calldata transaction,
        // Whether to use the private owners verifier
        bool usePrivateOwners,
        // The proof blob.
        bytes calldata proof
    ) public virtual returns (bool result) {
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
        require(verifyZkSafeTransaction(safeContract, txHash, usePrivateOwners, proof), "Invalid proof");
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
        result = safeContract.execTransactionFromModule(
            transaction.to,
            transaction.value,
            transaction.data,
            transaction.operation
        );

        require(result, "Execution of the transaction from zkSafe module failed");
    }
}
