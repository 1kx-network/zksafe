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
    address immutable zkSafeModuleAddress;

    struct zkSafeConfig {
        // Owner root
        bytes32 ownersRoot;
        // Threshhold
        uint256 threshold;
    }

    mapping(GnosisSafe => zkSafeConfig) public safeToConfig;

    constructor(UltraVerifier _verifier) {
        verifier = _verifier;
        zkSafeModuleAddress = address(this);
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
     * @param ownersRoot Owners Merkle tree root.
     * @param threshold Number of required confirmations for a zkSafe transaction.
    */
    function enableModule(bytes32 ownersRoot, uint256 threshold) external {
        address payable thisAddr = payable(address(this));
        GnosisSafe(thisAddr).enableModule(zkSafeModuleAddress);
        
        // Initialize zkMultisg config
        ZkSafeModule(zkSafeModuleAddress).updateZkMultisigConf(
            ownersRoot, threshold
        );
    }

     /*
     * @dev Update the zk multisg config for the msg.sender, which should be a zkSafe that wants to implement this module
     * @param module The address of the module to enable.
     */
    function updateZkMultisigConf(bytes32 ownersRoot, uint256 threshold) external {
        //require(threshold > 0, "Threshold must be greater than 0");
        require(threshold < 256, "Threshold must be less than 256");

        safeToConfig[GnosisSafe(payable(msg.sender))] = zkSafeConfig({
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
     * @dev Verifies a zk-SNARK proof for a Gnosis Safe transaction.
     * @param safeContract The address of the Gnosis Safe contract.
     * @param txHash The hash of the transaction to be verified.
     * @param proof The zk-SNARK proof.
     * @return True if the proof is valid, false otherwise.
     */
    function verifyZkSafeTransaction(
        address safeContract,
        bytes32 txHash,
        bytes calldata proof
    ) public view returns (bool) {

        zkSafeConfig memory currentSageConfig = safeToConfig[GnosisSafe(payable(safeContract))];
        
        // Construct the input to the circuit.
        // We need 34 array position for public inputs.
        bytes32[] memory publicInputs = new bytes32[](1 + 32 + 1);

  
        // Threshold       
        publicInputs[0] = bytes32(uint256(currentSageConfig.threshold));

        // Each byte of the transaction hash is given as a separate uint256 value.
        // TODO: this is super inefficient, fix by making the circuit take compressed inputs.
        for (uint256 i = 0; i < 32; i++) {
            publicInputs[i+1] = bytes32(uint256(uint8(txHash[i])));
        }

        // ownersRoot
        publicInputs[33] = bytes32(currentSageConfig.ownersRoot);

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
    ) public virtual returns (bool) {
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
        require(verifyZkSafeTransaction(address(safeContract), txHash, proof), "Invalid proof");
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

        // All clean: can run the    
        bool result = safeContract.execTransactionFromModule(
            transaction.to,
            transaction.value,
            transaction.data,
            transaction.operation
        );

        require(result, "Execution of the transction from zkSafe module failed");
    }
}
