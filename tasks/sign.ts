import { ethers } from "hardhat";
import { vars } from "hardhat/config";
import { ReadLine } from "readline";
import readline from "readline";
import { stdin, stdout } from "process";

async function main() {
  const mywallet = new ethers.Wallet(vars.get("PRIVATE_KEY"));
  const mywalletAddress = mywallet.address;
  console.log("My wallet address: ", mywalletAddress);

  const rl = readline.createInterface({input: stdin, output: stdout});
  let transaction = {};
  rl.question("To: ", (to) => {
    transaction["to"] = to;
  });
  
  rl.question("Value: ", (value) => {
    transaction["value"] = value;
  });
  
  rl.question("Calldata: ", (data) => {
    transaction["data"] = data;
  });
  rl.close();

  // Sign transaction using safe-core-sdk.
  const safe = Safe.create({ ethSigner: mywallet });

  const sig = "0x1234123412341234a123412341234";

  console.log("Signature: ", sig);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

