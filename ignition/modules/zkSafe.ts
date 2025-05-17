import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("zkSafe", (m) => {
  const verifier = m.contract("HonkVerifier", []);
  const zkSafeModule = m.contract("ZkSafeModule", [verifier]);
  return { zkSafeModule, verifier };
});
