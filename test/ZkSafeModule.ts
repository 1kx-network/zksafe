import { getSafeWithOwners } from "./setup";
import hre, { ethers } from "hardhat";
import { expect } from "chai";

describe("ZkSafeModule", function () {
    let signers = [];

    let safe;;

    before(async function () {
        signers = (await ethers.getSigners()).slice(0, 10);
        // Deploy Safe
        let owners = signers.map((signer) => signer.address);
        console.log("owners", owners);
        safe = await getSafeWithOwners();
    });

    it("Should fail to verify a nonexistent contract", async function () {
        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        const zkSafeModule = await ZkSafeModule.deploy("0x0000000000000000000000000000000000000000");

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }
    
        expect(zkSafeModule.sendZkSafeTransaction(
            "0x0000000000000000000000000000000000000000",
            transaction,
            "0x", // proof
        )).to.be.reverted;
    });
});