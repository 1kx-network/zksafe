import { HardhatUserConfig } from "hardhat/types";
import "hardhat-deploy";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-ignition";
import "@nomicfoundation/hardhat-chai-matchers";

import { BigNumber } from "@ethersproject/bignumber";
import { DeterministicDeploymentInfo } from "hardhat-deploy/dist/types";
import { getSingletonFactoryInfo } from "@gnosis.pm/safe-singleton-factory";

import { zksend, sign, prove, createZkSafe } from "./zksafe/zksafe";

// copied from @safe-global/safe-contracts
const deterministicDeployment = (network: string): DeterministicDeploymentInfo => {
    const info = getSingletonFactoryInfo(parseInt(network));
    if (!info) {
        throw new Error(`
        Safe factory not found for network ${network}. You can request a new deployment at https://github.com/safe-global/safe-singleton-factory.
        For more information, see https://github.com/safe-global/safe-contracts#replay-protection-eip-155
      `);
    }
    return {
        factory: info.address,
        deployer: info.signerAddress,
        funding: BigNumber.from(info.gasLimit).mul(BigNumber.from(info.gasPrice)).toString(),
        signedTx: info.transaction,
    };
};

task("zksend", "Send a zksafe transaction with a proof")
    .addParam("safe", "Address of the Safe")
    .addParam("to", "Address of the recipient")
    .addParam("value", "Value to send")
    .addParam("data", "Calldata to send")
    .addParam("proof", "The proof")
    .setAction(async (taskArgs, hre) => zksend(hre, taskArgs.safe, taskArgs.to, taskArgs.value, taskArgs.data, taskArgs.proof));

task("prove", "Prove a zksafe transaction") 
    .addParam("safe", "Address of the Safe")
    .addParam("txhash", "Transaction hash")
    .addParam("signatures", "Signatures (comma separated)")
    .setAction(async (taskArgs, hre) => prove(hre, taskArgs.safe, taskArgs.txhash, taskArgs.signatures));
    
task("sign", "Sign Safe transaction")
    .addParam("safe", "Address of the Safe")
    .addParam("to", "Address of the recipient")
    .addParam("value", "Value to Send")
    .addParam("data", "Calldata to send")
    .setAction(async (taskArgs, hre) => sign(hre, taskArgs.safe, taskArgs.to, taskArgs.value, taskArgs.data));

task("createZkSafe", "Create a ZkSafe")
    .addParam("owners", "Comma separated list of owners")
    .addParam("threshold", "Threshold")
    .setAction(async (taskArgs, hre) => createZkSafe(hre, taskArgs.owners.split(","), taskArgs.threshold));

const getAccounts = function(): string[] {
    let accounts = [];
    accounts.push(vars.get("DEPLOYER_PRIVATE_KEY"));
    accounts.push(vars.get("SAFE_OWNER_PRIVATE_KEY"));
    return accounts;
}

const config: HardhatUserConfig = {
    solidity: {
        version: "0.8.12",
        settings: {
            optimizer: {  enabled: true, runs: 200 }
        }
    },
    namedAccounts: {
        deployer: {
            default: 0,
        },
        users: {
            default: 1,
        },
    },
    networks: {
        localhost: {
            url: "http://127.0.0.1:8545",
            accounts: getAccounts(),
        },
        gnosis: {
            url:  "https://gnosis-pokt.nodies.app",
            accounts: getAccounts(),
        },
        buildbear: {
            url:  "https://rpc.buildbear.io/1kx",
            accounts: getAccounts(),
        },
    },
    mocha: {
        timeout: 100000000
    },
    deterministicDeployment,
};

export default config;
