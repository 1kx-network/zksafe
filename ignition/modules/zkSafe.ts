import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("zkSafe_v2", (m) => {
  const verifier = m.contract("HonkVerifier", []);
  const zkSafeModule = m.contract("ZkSafeModule", [verifier]);
  return { zkSafeModule, verifier };
});
