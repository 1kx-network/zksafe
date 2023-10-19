// import { getSafeWithOwners } from "./setup";
import hre, { ethers, network } from 'hardhat';
import { expect } from "chai";
import { Safe, ZkSafeModule } from "../typechain-types";

// See https://noir-lang.org/typescript/ as an example.
// Most of the code is just copy-pasted as recommended there.
import circuit from '../circuits/target/circuits.json';
import { decompressSync } from 'fflate';
import { Crs, Barretenberg, RawBuffer } from '@aztec/bb.js';
import { executeCircuit, compressWitness } from '@noir-lang/acvm_js';
import { AddressLike, BigNumberish, BytesLike } from "ethers";
import { SafeTransaction } from "@safe-global/safe-contracts";
// import Safe, { SafeAccountConfig, SafeFactory } from "@safe-global/protocol-kit";
import { EthersAdapter, SafeFactory, SafeAccountConfig } from '@safe-global/protocol-kit';
// import { getAccounts } from "@safe-global/protocol-kit/tests/utils/setupTestNetwork";
import dotenv from 'dotenv';
import { getSafeWithOwners } from './setup';

dotenv.config();

function getOwnerAdapters(): EthersAdapter[] {
    let owners = new Array();
    console.log("OWNER_1_PRIVATE_KEY", process.env.OWNER_1_PRIVATE_KEY!);
    console.log("WTF: ", hre.ethers.Wallet);
    console.log("ethers.Provider", ethers.Provider);
    let provider: ethers.Provider = ethers.provider;
    const owner1Signer = new hre.ethers.Wallet(process.env.OWNER_1_PRIVATE_KEY!, hre.ethers.provider);
    const owner2Signer = new hre.ethers.Wallet(process.env.OWNER_2_PRIVATE_KEY!, hre.ethers.provider);
    const owner3Signer = new hre.ethers.Wallet(process.env.OWNER_3_PRIVATE_KEY!, hre.ethers.provider);
    owners.push(new EthersAdapter({ ethers, signerOrProvider: owner1Signer }));
    owners.push(new EthersAdapter({ ethers, signerOrProvider: owner2Signer }));
    owners.push(new EthersAdapter({ ethers, signerOrProvider: owner3Signer }));
    return owners;
}

// A lot of Noir magic taken from https://noir-lang.org/typescript/
async function initCircuits() {
    const acirBuffer = Buffer.from(circuit.bytecode, 'base64');
    const acirBufferUncompressed = decompressSync(acirBuffer);
    console.log("Uncompressed buffer length: ", acirBufferUncompressed.length);

    console.log("initializing Barretenberg api");
    const api = await Barretenberg.new(4);

    console.log("Barretenberg api initialized");
    const [exact, circuitSize, subgroup] = await api.acirGetCircuitSizes(acirBufferUncompressed);
    console.log("Found group circuit size", circuitSize, "subgroup", subgroup, "exact", exact);

    const subgroupSize = Math.pow(2, Math.ceil(Math.log2(circuitSize)));
    const crs = await Crs.new(subgroupSize + 1);
    await api.commonInitSlabAllocator(subgroupSize);
    await api.srsInitSrs(new RawBuffer(crs.getG1Data()), crs.numPoints, new RawBuffer(crs.getG2Data()));

    const acirComposer = await api.acirNewAcirComposer(subgroupSize);

    // Note that in the browser you need to init the ACVM, as described in https://noir-lang.org/typescript/
    return [api, acirComposer, acirBuffer];
}

// Here we need to supply both signers and signatures.
async function generateWitness(safe: Safe, txn: SafeTransaction, signatures: BytesLike[], acirBuffer: Buffer): Promise<Uint8Array> {
    // Calcualte transaction hash using Safe Sdk

    
    // From the signatures, determine the signer addresses using ecrecover.

    // Generate
    const initialWitness = new Map<number, string>();
    const witnessMap = await executeCircuit(acirBuffer, initialWitness, () => {
        throw Error('unexpected oracle');
    });

    const txHash = await safe.getTransactionHash(txn);

    const witnessBuff = compressWitness(witnessMap);
    return witnessBuff;
}

describe("ZkSafeModule", function () {
    let ownerAdapters: EthersAdapter[];
    let safeContract: SafeContract;
    let zkSafeModule: ZkSafeModule;
    let safe: Safe;

    let api: any;
    let acirComposer: any;
    let acirBuffer: Buffer;

    before(async function () {
        ownerAdapters = getOwnerAdapters();
        // Deploy Safe
        let owners = await Promise.all(ownerAdapters.map((oa) => oa.getSigner()?.getAddress()));
        console.log("owners", owners);

        safe = await getSafeWithOwners(owners, 2);

        // const safeFactory = await SafeFactory.create({ ethAdapter: ownerAdapters[0] });
        // const safeAccountConfig: SafeAccountConfig =  {
        //     owners,
        //     threshold: 2
        // };
        // safe = await safeFactory.deploySafe({ safeAccountConfig })
        const safeAddress = await safe.address;
        console.log("safeAddress", safeAddress);

        const verifierContractFactory = await ethers.getContractFactory("UltraVerifier");
        const verifierContract = await verifierContractFactory.deploy();
        console.log("verifierContract", verifierContract.address);

        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        zkSafeModule = await ZkSafeModule.deploy(verifierContract.address);
        console.log("zlSafeModule", zkSafeModule.address);

        [api, acirComposer, acirBuffer] = await initCircuits();
    });

    it("Should fail to verify a nonexistent contract", async function () {

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

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        expect(zkSafeModule.sendZkSafeTransaction(
            safe.address,
            transaction,
            "0x", // proof
        )).to.be.revertedWith("Invalid proof");
    });

    it("Should succeed verification of a basic transaction", async function () {

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }



        // To generate proof, we need:
        //   1) instance of the prover
        //   2) calculating the hash of the transaction (Safe SDK?)
        //   3) convert the inputs into the format compatible with the prover.
        //   4) call the prover

        expect(zkSafeModule.sendZkSafeTransaction(
            safe.address,
            transaction,
            "0x", // proof
        )).to.be.revertedWith("Invalid proof");
    });


});
