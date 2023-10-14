import { HardhatUserConfig } from "hardhat/types";
import "hardhat-deploy";

const config: HardhatUserConfig = {
    solidity: {
        version: "0.8.21",
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
};

export default config;
