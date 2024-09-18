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
        mainnet: {
            url: "http://192.168.1.4:8545",
            accounts: getAccounts(),
        },
        localhost: {
            url: "http://127.0.0.1:8545",
        },
        gnosis: {
            url: "https://gnosis.drpc.org",
            accounts: getAccounts(),
        },
        bsc: {
            url: "https://bsc-dataseed.binance.org/",
            accounts: getAccounts(),
        },
        polygon: {
            url: vars.get("POLYGON_RPC", ""),
            accounts: getAccounts(),
        },
        sepolia: {
            url: "https://rpc.sepolia.org/",
            accounts: getAccounts(),
        },
        telos: {
             url: "https://mainnet-asia.telos.net/evm",
             accounts: getAccounts(),
        },
        arbitrum: {
            url: "https://1rpc.io/arb",
            accounts: getAccounts(),
        },
        optimism: {
            url: "https://1rpc.io/op",
            accounts: getAccounts(),
        },
        buildbear: {
            url:  "https://rpc.buildbear.io/1kx",
            accounts: getAccounts(),
        },
        base: {
            url: "https://base.rpc.subquery.network/public",
            accounts: getAccounts(),
            initialBaseFeePerGas: 5000000000, // 5 gwei
            gasPrice: 25000000000, // 25 gwei (base fee + priority fee)
        },
        scroll: {
            url: "https://scroll.drpc.org",
            accounts: getAccounts(),
        }
    },
    etherscan: {
        customChains: [
         {
            network: "gnosis",
            chainId: 100,
            urls: {
              // 3) Select to what explorer verify the contracts
              // Gnosisscan
              apiURL: "https://api.gnosisscan.io/api",
              browserURL: "https://gnosisscan.io/",
            },
          },
          {
            network: "bsc",
            chainId: 56,
            urls: {
              apiURL: "https://api.bscscan.com/api",
              browserURL: "https://bscscan.com/",
            },
          },
          {
            network: "polygon",
            chainId: 137,
            urls: {
              apiURL: "https://api.polygonscan.com/api",
              browserURL: "https://polygonscan.com/",
            },
          },
          {
            network: "scroll",
            chainId: 534352,
            urls: {
              apiURL: "https://api.scrollscan.com/api",
              browserURL: "https://scrollscan.com/",
            },
          }
        ],
        apiKey: {
            gnosis: vars.get("GNOSISSCAN_API_KEY", ""),
            sepolia: vars.get("ETHERSCAN_API_KEY", ""),
            mainnet: vars.get("ETHERSCAN_API_KEY", ""),
            bsc: vars.get("BSCSCAN_API_KEY", ""),
            polygon: vars.get("POLYGONSCAN_API_KEY", ""),
            arbitrumOne: vars.get("ARBISCAN_API_KEY", ""),
            mainnet: vars.get("ETHERSCAN_API_KEY", ""),
            optimisticEthereum: vars.get("OPTIMISTIC_API_KEY", ""),
            scroll: vars.get("SCROLLSCAN_API_KEY", ""),
            base: vars.get("BASESCAN_API_KEY", ""),
        },
    },
    ignition: {
        strategyConfig: {
            create2: {
                // salt: "0x0Ccb2b6675A60EC6a5c20Fb0631Be8EAF3Ba2dCD" + "00" + "69eb570cb274b0ebea0271",
                salt: "0x00000000000000000000000000000000000000000069eb570cb274b0ebea0275",
            }
        }
    },
    mocha: {
        timeout: 100000000
    },
    deterministicDeployment,
};

export default config;
