const { expect } = require("chai");

describe("ZkSafeModule", function () {
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