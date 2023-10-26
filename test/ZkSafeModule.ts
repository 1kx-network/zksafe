// import { getSafeWithOwners } from "./setup";
import hre, { ethers, network, deployments } from 'hardhat';
import { expect } from "chai";
import { ZkSafeModule } from "../typechain-types";

// See https://noir-lang.org/typescript/ as an example.
// Most of the code is just copy-pasted as recommended there.
import circuit from '../circuits/target/circuits.json';
import { decompressSync } from 'fflate';
import { Crs, Barretenberg, RawBuffer } from '@aztec/bb.js';
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { executeCircuit, compressWitness } from '@noir-lang/acvm_js';
import { Noir } from '@noir-lang/noir_js';
import { BytesLike } from "ethers";
import { EthersAdapter, SafeFactory, SafeContractEthers, SafeAccountConfig } from '@safe-global/protocol-kit';
import Safe from '@safe-global/protocol-kit';
import { SafeTransaction, SafeTransactionData } from '@safe-global/safe-core-sdk-types';

import dotenv from 'dotenv';
import { getSafeWithOwners } from './setup';

dotenv.config();

async function getOwnerAdapters(): Promise<EthersAdapter[]> {
    return (await ethers.getSigners()).slice(0, 3).map((signer) => new EthersAdapter({ ethers, signerOrProvider: signer }));
}

// A lot of Noir magic taken from https://noir-lang.org/typescript/
// async function initCircuits() {
//     const acirBuffer = Buffer.from(circuit.bytecode, 'base64');
//     const acirBufferUncompressed = decompressSync(acirBuffer);
//     console.log("Uncompressed buffer length: ", acirBufferUncompressed.length);

//     console.log("initializing Barretenberg api");
//     const api = await Barretenberg.new(4);

//     console.log("Barretenberg api initialized");
//     const [exact, circuitSize, subgroup] = await api.acirGetCircuitSizes(acirBufferUncompressed);
//     console.log("Found group circuit size", circuitSize, "subgroup", subgroup, "exact", exact);

//     const subgroupSize = Math.pow(2, Math.ceil(Math.log2(circuitSize)));
//     const crs = await Crs.new(subgroupSize + 1);
//     await api.commonInitSlabAllocator(subgroupSize);
//     await api.srsInitSrs(new RawBuffer(crs.getG1Data()), crs.numPoints, new RawBuffer(crs.getG2Data()));

//     const acirComposer = await api.acirNewAcirComposer(subgroupSize);

//     // Note that in the browser you need to init the ACVM, as described in https://noir-lang.org/typescript/
//     return [api, acirComposer, acirBuffer, acirBufferUncompressed];
// }

// Here we need to supply both signers and signatures.
// async function generateWitness(safe: Safe, txn: SafeTransaction, signatures: BytesLike[], acirBuffer: Buffer): Promise<Uint8Array> {
//     // Calcualte transaction hash using Safe Sdk
//     const txHash = await safe.getTransactionHash(txn);
    
//     // From the signatures, determine the signer pubkeys using ecrecover.
//     const signerPubKeys = signatures.map((sig) => ethers.utils.recoverPublicKey(txHash, sig));

//     // Generate witness suitable for feeding into the ACVM.
//     // This means: 
//     const initialWitness = new Map<number, string>();
//     initialWitness
//     const witnessMap = await executeCircuit(acirBuffer, initialWitness, () => {
//         throw Error('unexpected oracle');
//     });

//     const witnessBuff = compressWitness(witnessMap);
//     return witnessBuff;
// }

/// Extract x and y coordinates from a serialized ECDSA public key.
function extractCoordinates(serializedPubKey: string): { x: string[], y: string[] } {
    // Ensure the key starts with '0x04' which is typical for an uncompressed key.
    if (!serializedPubKey.startsWith('0x04')) {
        throw new Error('The public key does not appear to be in uncompressed format.');
    }

    // The next 64 characters after the '0x04' are the x-coordinate.
    let xHex = serializedPubKey.slice(4, 68);

    // The following 64 characters are the y-coordinate.
    let yHex = serializedPubKey.slice(68, 132);

    // Convert the hex string to a byte array.
    let xBytes = Array.from(Buffer.from(xHex, 'hex')).map((b) => b.toString());
    let yBytes = Array.from(Buffer.from(yHex, 'hex')).map((b) => b.toString());
    return { x: xBytes, y: yBytes };
}

function extractRSFromSignature(signatureHex: string): string[] {
    if (signatureHex.length !== 132 || !signatureHex.startsWith('0x')) {
        throw new Error('Signature should be a 130-character hex string starting with 0x.');
    }
    return Array.from(Buffer.from(signatureHex.slice(2, 130), 'hex')).map((b) => b.toString());
}

function addressToArray(address: string): string[] {
    if (address.length !== 42 || !address.startsWith('0x')) {
        throw new Error('Address should be a 40-character hex string starting with 0x.');
    }
    return Array.from(ethers.utils.arrayify(address)).map((b) => b.toString());
}

function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}

describe("ZkSafeModule", function () {
    let ownerAdapters: EthersAdapter[];
    // let safeContract: SafeContract;
    let zkSafeModule: ZkSafeModule;
    let safe: Safe;

    // Old Noir Way
    let api: any;
    let acirComposer: any;
    let acirBuffer: Buffer;
    let acirBufferUncompressed: Buffer;

    // New Noir Way
    let noir: Noir;
    let correctProof: Uint8Array;

    async function generateProof(witness: Uint8Array) {
        const proof = await api.acirCreateProof(
          acirComposer,
          acirBufferUncompressed,
          decompressSync(witness),
          false,
        );
        return proof;
    }


    before(async function () {
        ownerAdapters = await getOwnerAdapters();
        // Deploy Safe
        let owners = await Promise.all(ownerAdapters.map((oa) => (oa.getSigner()?.getAddress() as string)));
        console.log("owners", owners);

        await deployments.fixture();

        const deployedSafe = await deployments.get("GnosisSafeL2");
        const deployedSafeFactory = await deployments.get("GnosisSafeProxyFactory");
        const deployedMultiSend = await deployments.get("MultiSend");
        const deployedMultiSendCallOnly = await deployments.get("MultiSendCallOnly");
        const deployedCompatibilityFallbackHandler = await deployments.get("CompatibilityFallbackHandler");
        const deployedSignMessageLib = await deployments.get("SignMessageLib");
        const deployedCreateCall = await deployments.get("CreateCall");
//        const deployedSimulateTxAccessor = await deployments.get("SimulateTxAccessor");
        const chainId: number = await ownerAdapters[0].getChainId();
        const contractNetworks = {
            [chainId]: {
                    safeMasterCopyAddress: deployedSafe.address,
                    safeProxyFactoryAddress: deployedSafeFactory.address,
                    multiSendAddress: deployedMultiSend.address,
                    multiSendCallOnlyAddress: deployedMultiSendCallOnly.address,
                    fallbackHandlerAddress: deployedCompatibilityFallbackHandler.address,
                    signMessageLibAddress: deployedSignMessageLib.address,
                    createCallAddress: deployedCreateCall.address,
                    simulateTxAccessorAddress: ethers.constants.AddressZero,
            }
        };
        const safeFactory = await SafeFactory.create({ ethAdapter: ownerAdapters[0], contractNetworks });
        console.log("safeFactory", safeFactory);

        const safeAccountConfig: SafeAccountConfig =  {
            owners: owners,
            threshold: 2,
        };

        safe = await safeFactory.deploySafe({ safeAccountConfig });

        // const safeFactory = await SafeFactory.create({ ethAdapter: ownerAdapters[0] });
        // const safeAccountConfig: SafeAccountConfig =  {
        //     owners,
        //     threshold: 2
        // };
        // safe = await safeFactory.deploySafe({ safeAccountConfig })
        const safeAddress = await safe.getAddress();
        console.log("safeAddress", safeAddress);

        const verifierContractFactory = await ethers.getContractFactory("UltraVerifier");
        const verifierContract = await verifierContractFactory.deploy();
        console.log("verifierContract", verifierContract.address);

        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        zkSafeModule = await ZkSafeModule.deploy(verifierContract.address);
        console.log("zkSafeModule", zkSafeModule.address);

        // [api, acirComposer, acirBuffer, acirBufferUncompressed] = await initCircuits();

        // New Noir Way
        const backend = new BarretenbergBackend(circuit);
        noir = new Noir(circuit, backend);
        await noir.init();
        console.log("noir backend initialzied");
    });


    it("Should succeed verification of a basic transaction", async function () {

        const nonce = await safe.getNonce();
        console.log("Safe nonce", nonce);
        const threshold = await safe.getThreshold();
        console.log("Safe threshold", threshold);
        const safeTransactionData : SafeTransactionData = {
            to: ethers.constants.AddressZero,
            value: "0x0",
            data: "0x",
            operation: 0,
            // default fields below
            safeTxGas: "0x0",
            baseGas: "0x0",
            gasPrice: "0x0",
            gasToken: ethers.constants.AddressZero,
            refundReceiver: ethers.constants.AddressZero,
            nonce, 
        }

        console.log("owners", await safe.getOwners());

        console.log("transaction", safeTransactionData);
        console.log("safe", safe);
        // const result = await safe.approveHash("wtf");
        // console.log("approveHash result", result);
        console.log("safe modules", await safe.getModules());
        const transaction = await safe.createTransaction({ safeTransactionData });
        const txHash = await safe.getTransactionHash(transaction);
        console.log("txHash", txHash);

        // Let's generate three signatures for the owners of the Safe.
        // ok, our siganture is a EIP-712 signature, so we need to sign the hash of the transaction.
        let safeTypedData = {
            safeAddress: await safe.getAddress(),
            safeVersion: await safe.getContractVersion(),
            chainId: await ownerAdapters[0].getChainId(),
            safeTransactionData: safeTransactionData,
        }; 
        const sig1 = await ownerAdapters[0].signTypedData(safeTypedData);
        const sig2 = await ownerAdapters[1].signTypedData(safeTypedData);
        const sig3 = await ownerAdapters[2].signTypedData(safeTypedData);

        // const witness = await generateWitness(safe, transaction, [sig1, sig2, sig3], acirBuffer);
        // To generate proof, we need:
        //   1) instance of the prover
        //   2) calculating the hash of the transaction (Safe SDK?)
        //   3) convert the inputs into the format compatible with the prover.
        //   4) call the prover
        //   5) convert the outputs into the format compatible with the verifier.

        // type Address = [u8; 20];
        // type Signature = [u8; 64];
        // type Hash = [u8; 32];
        // struct  PubKey {
        //    x: [u8; 32],
        //    y: [u8; 32],
        // }
        // fn main(threshold: pub u8, signers: [PubKey; 10], signatures: [Signature; 10], hash: pub Hash, owners: pub [Address; 10])

        console.log("WTF ");

        const zero_pubkey = { x: new Array(32).fill("0"), y: new Array(32).fill("0") };
        const zero_signature = new Array(64).fill("0");
        const zero_address = new Array(20).fill("0");

        const input = {
            threshold: await safe.getThreshold(),
            signers: padArray([sig1, sig2, sig3].map((sig) => extractCoordinates(ethers.utils.recoverPublicKey(txHash, sig))), 10, zero_pubkey),
            signatures: padArray([sig1, sig2, sig3].map(extractRSFromSignature), 10, zero_signature),
            hash: Array.from(ethers.utils.arrayify(txHash)).map((b) => b.toString()),
            owners: padArray((await safe.getOwners()).map(addressToArray), 10, zero_address),
        };
        console.log("input", JSON.stringify(input));
        correctProof = await noir.generateFinalProof(input);
        // console.log("correctProof", correctProof);

        // expect(zkSafeModule.sendZkSafeTransaction(
        //     await safe.getAddress(),
        //     transaction,
        //     correctProof
        // )).to.not.be.reverted;
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
            safe.getAddress(),
            transaction,
            "0x", // proof
        )).to.be.revertedWith("Invalid proof");
    });

});
