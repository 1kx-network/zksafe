import { getSafeWithOwners } from "./setup";
import hre, { ethers } from "hardhat";
import { expect } from "chai";
import { Safe, ZkSafeModule } from "../typechain-types";
import { ContractFactory } from "ethers";

describe("ZkSafeModule", function () {
    let signers = [];
    let safe: Safe;
    let zkSafeModule: ZkSafeModule;

    before(async function () {
        signers = (await ethers.getSigners()).slice(0, 10);
        // Deploy Safe
        let owners = signers.map((signer) => signer.address);
        console.log("owners", owners);
        safe = await getSafeWithOwners(owners, 3);

        const verifierContractFactory = await ethers.getContractFactory("UltraVerifier");
        const verifierContract = await verifierContractFactory.deploy();

        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        zkSafeModule = await ZkSafeModule.deploy(verifierContract.getAddress());

    });

    it("Should fail to verify a nonexistent contract", async function () {
        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        const zkSafeModule = await ZkSafeModule.deploy(safe.getAddress());

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

    it("Should fail a bastic transaction with a wrong proof", async function () {
        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        const zkSafeModule = await ZkSafeModule.deploy(safe.getAddress());

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        expect(zkSafeModule.sendZkSafeTransaction(
            safe.getAddress(),
            transaction,
            "0x", // proof
        )).to.be.revertedWith("Invalid proof");
    });


});
