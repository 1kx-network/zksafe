// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Uncomment this line to use console.log
// import "hardhat/console.sol";


// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../circuits/contract/circuits/plonk_vk.sol";
import "@safe-global/safe-contracts/contracts/base/Enum.sol";

contract ZkSafeModule {
    UltraVerifier verifier;

    function sendZkSafeTransaction(
        // The Safe address to which the transaction will be sent.
        address safe,

        // The transaction data payload.
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,

        // The proof data
        bytes memory proof
    ) public returns (bool) {

        
        
        // Get the owners of the Safe by calling into the Safe contract.
        return verifier.verifyProof(a, b, c, input);
    }

}
