// SPDX-License-Identifier: UNKNOWN 
/**
 * This file is for test cases only.
 *
 * By importing these files here, the compiler creates the artifacts which then get used by the deployment script.
 * This allows us to spin up a safe within our test environment to execute our unit tests.
 */

pragma solidity ^0.8.12;
 
import "@gnosis.pm/safe-contracts/contracts/accessors/SimulateTxAccessor.sol";
import "@gnosis.pm/safe-contracts/contracts/base/Executor.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import "@gnosis.pm/safe-contracts/contracts/examples/libraries/GnosisSafeStorage.sol";
import "@gnosis.pm/safe-contracts/contracts/examples/libraries/SignMessage.sol";
import "@gnosis.pm/safe-contracts/contracts/external/GnosisSafeMath.sol";
import "@gnosis.pm/safe-contracts/contracts/handler/CompatibilityFallbackHandler.sol";
import "@gnosis.pm/safe-contracts/contracts/handler/DefaultCallbackHandler.sol";
import "@gnosis.pm/safe-contracts/contracts/handler/HandlerContext.sol";
import "@gnosis.pm/safe-contracts/contracts/libraries/CreateCall.sol";
import "@gnosis.pm/safe-contracts/contracts/libraries/MultiSend.sol";
import "@gnosis.pm/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxy.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/IProxyCreationCallback.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafeL2.sol";
