import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("ZkSafe", (m) => {
    const GnosisSafe = m.contract("GnosisSafe", []);
    const GnosisSafeL2 = m.contract("GnosisSafeL2", []);
    const GnosisSafeProxyFactory = m.contract("GnosisSafeProxyFactory", []);
    const DefaultCallbackHandler = m.contract("DefaultCallbackHandler", []);
    const CompatibilityFallbackHandler = m.contract("CompatibilityFallbackHandler", []);
    const CreateCall = m.contract("CreateCall", []);
    const MultiSend = m.contract("MultiSend", []);
    const MultiSendCallOnly = m.contract("MultiSendCallOnly", []);
    const SignMessageLib = m.contract("SignMessageLib", []);


    return { GnosisSafe, GnosisSafeL2, GnosisSafeProxyFactory, DefaultCallbackHandler, CompatibilityFallbackHandler, CreateCall, MultiSend, MultiSendCallOnly, SignMessageLib };
});
