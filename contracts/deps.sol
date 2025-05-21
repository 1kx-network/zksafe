// SPDX-License-Identifier: UNKNOWN 
/**
 * This file is for test cases only.
 *
 * By importing these files here, the compiler creates the artifacts which then get used by the deployment script.
 * This allows us to spin up a safe within our test environment to execute our unit tests.
 */

pragma solidity ^0.8.12;
 
import "@safe-global/safe-contracts/contracts/accessors/SimulateTxAccessor.sol";
import "@safe-global/safe-contracts/contracts/base/Executor.sol";
import "@safe-global/safe-contracts/contracts/common/Enum.sol";
import "@safe-global/safe-contracts/contracts/libraries/SignMessageLib.sol";
import "@safe-global/safe-contracts/contracts/external/SafeMath.sol";
import "@safe-global/safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import "@safe-global/safe-contracts/contracts/handler/TokenCallbackHandler.sol";
import "@safe-global/safe-contracts/contracts/handler/HandlerContext.sol";
import "@safe-global/safe-contracts/contracts/libraries/CreateCall.sol";
import "@safe-global/safe-contracts/contracts/libraries/MultiSend.sol";
import "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import "@safe-global/safe-contracts/contracts/proxies/SafeProxy.sol";
import "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import "@safe-global/safe-contracts/contracts/proxies/IProxyCreationCallback.sol";
import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/SafeL2.sol";
