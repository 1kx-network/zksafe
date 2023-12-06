import { HardhatUserConfig } from "hardhat/types";
import "hardhat-deploy";
// import "@nomiclabs/hardhat-ethers";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-chai-matchers";

import { BigNumber } from "@ethersproject/bignumber";
import { DeterministicDeploymentInfo } from "hardhat-deploy/dist/types";
import { getSingletonFactoryInfo } from "@gnosis.pm/safe-singleton-factory";


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
            url: "http://127.0.0.1:8545"
        },
        tenderly: {
            url: "https://rpc.vnet.tenderly.co/devnet/my-first-devnet/0091b33c-f503-4310-a6f8-8e4ee34b818d"
        }
    },
    mocha: {
        timeout: 100000000
    },
    deterministicDeployment,
};

export default config;
