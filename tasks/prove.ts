import { ethers } from "hardhat";

async function main() {
  const sig = "0x1234123412341234a123412341234";

  console.log("Signature: ", sig);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
