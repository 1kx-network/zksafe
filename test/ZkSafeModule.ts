import { getSafeWithOwners } from "./setup";
import { Signer } from '@ethersproject/abstract-signer';
import { Wallet } from '@ethersproject/wallet';
import hre, { ethers, waffle } from 'hardhat';
import { expect } from "chai";
import { Safe as SafeContract, ZkSafeModule } from "../typechain-types";

// See https://noir-lang.org/typescript/ as an example.
// Most of the code is just copy-pasted as recommended there.
import circuit from '../circuits/target/circuits.json';
import { decompressSync } from 'fflate';
import { Crs, newBarretenbergApiAsync, RawBuffer } from '@aztec/bb.js';
import { executeCircuit, compressWitness } from '@noir-lang/acvm_js';
import { AddressLike, BigNumberish, BytesLike } from "ethers";
import { SafeTransaction } from "@safe-global/safe-contracts";
import Safe, { SafeAccountConfig, SafeFactory } from "@safe-global/protocol-kit";
import { EthersAdapter } from '@safe-global/protocol-kit';
// import { getAccounts } from "@safe-global/protocol-kit/tests/utils/setupTestNetwork";

interface Account {
  signer: Signer
  address: string
}

function getAccounts(): Account[] {
  const wallets = waffle.provider.getWallets()
  const accounts: Account[] = []
  for (let i = 0; i < 10; i++) {
    const wallet: Wallet = wallets[i]
    const account: Account = { signer: wallet as Signer, address: wallet.address }
    accounts.push(account)
  }
  return accounts
}

// A lot of Noir magic taken from https://noir-lang.org/typescript/
async function initCircuits() {
    const acirBuffer = Buffer.from(circuit.bytecode, 'base64');
    const acirBufferUncompressed = decompressSync(acirBuffer);

    const api = await newBarretenbergApiAsync(4);

    const [exact, circuitSize, subgroup] = await api.acirGetCircuitSizes(acirBufferUncompressed);
    const subgroupSize = Math.pow(2, Math.ceil(Math.log2(circuitSize)));
    const crs = await Crs.new(subgroupSize + 1);
    await api.commonInitSlabAllocator(subgroupSize);
    await api.srsInitSrs(new RawBuffer(crs.getG1Data()), crs.numPoints, new RawBuffer(crs.getG2Data()));
    
    const acirComposer = await api.acirNewAcirComposer(subgroupSize);

    // Note that in the browser you need to init the ACVM, as described in https://noir-lang.org/typescript/
    
    return [api, acirComposer];
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
    let signers;
    let safeContract: SafeContract;
    let zkSafeModule: ZkSafeModule;
    let safe: Safe;

    before(async function () {
        signers = (await getAccounts()).slice(0, 10);
        // Deploy Safe
        let owners = signers.map((signer) => signer.address);
        console.log("owners", owners);
        safeContract = await getSafeWithOwners(owners, 3);
        const ethAdapter = new EthersAdapter({ ethers, signerOrProvider: signers[0] as Signer });
        safe = await Safe.create({ethAdapter, safeAddress: await safeContract.getAddress()});

        const verifierContractFactory = await ethers.getContractFactory("UltraVerifier");
        const verifierContract = await verifierContractFactory.deploy();

        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        zkSafeModule = await ZkSafeModule.deploy(verifierContract.getAddress());

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

        // To generate proof, we need:
        //   1) instance of the prover
        //   2) calculating the hash of the transaction (Safe SDK?)
        //   3) convert the inputs into the format compatible with the prover.
        //   4) call the prover

        expect(zkSafeModule.sendZkSafeTransaction(
            safe.getAddress(),
            transaction,
            "0x", // proof
        )).to.be.revertedWith("Invalid proof");
    });


});
