import hre, { ethers, network, deployments } from 'hardhat';
import { expect } from "chai";
import { ZkSafeModule } from "../typechain-types";

import circuit from '../circuits/target/circuits.json';
import { decompressSync } from 'fflate';
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import { EthersAdapter, SafeFactory, SafeAccountConfig } from '@safe-global/protocol-kit';
import Safe from '@safe-global/protocol-kit';
import { SafeTransactionData } from '@safe-global/safe-core-sdk-types';

import dotenv from 'dotenv';

dotenv.config();

async function getOwnerAdapters(): Promise<EthersAdapter[]> {
    return (await ethers.getSigners()).slice(0, 3).map((signer) => new EthersAdapter({ ethers, signerOrProvider: signer }));
}

/// Extract x and y coordinates from a serialized ECDSA public key.
function extractCoordinates(serializedPubKey: string): { x: number[], y: number[] } {
    // Ensure the key starts with '0x04' which is typical for an uncompressed key.
    if (!serializedPubKey.startsWith('0x04')) {
        throw new Error('The public key does not appear to be in uncompressed format.');
    }

    // The next 64 characters after the '0x04' are the x-coordinate.
    let xHex = serializedPubKey.slice(4, 68);

    // The following 64 characters are the y-coordinate.
    let yHex = serializedPubKey.slice(68, 132);

    // Convert the hex string to a byte array.
    let xBytes = Array.from(Buffer.from(xHex, 'hex'));
    let yBytes = Array.from(Buffer.from(yHex, 'hex'));
    return { x: xBytes, y: yBytes };
}

function extractRSFromSignature(signatureHex: string): number[] {
    if (signatureHex.length !== 132 || !signatureHex.startsWith('0x')) {
        throw new Error('Signature should be a 130-character hex string starting with 0x.');
    }
    return Array.from(Buffer.from(signatureHex.slice(2, 130), 'hex'));
}

function addressToArray(address: string): number[] {
    if (address.length !== 42 || !address.startsWith('0x')) {
        throw new Error('Address should be a 40-character hex string starting with 0x.');
    }
    return Array.from(ethers.utils.arrayify(address));
}

function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}

describe("ZkSafeModule", function () {
    let ownerAdapters: EthersAdapter[];
    // let safeContract: SafeContract;
    let zkSafeModule: ZkSafeModule;
    let safe: Safe;
    let verifierContract: any;

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
        const safeAccountConfig: SafeAccountConfig =  {
            owners: owners,
            threshold: 2,
        };

        const verifierContractFactory = await ethers.getContractFactory("UltraVerifier");
        verifierContract = await verifierContractFactory.deploy();
        console.log("verifierContract", verifierContract.address);

        const ZkSafeModule = await ethers.getContractFactory("ZkSafeModule");
        zkSafeModule = await ZkSafeModule.deploy(verifierContract.address);
        console.log("zkSafeModule", zkSafeModule.address);

        safeAccountConfig.to = zkSafeModule.address;
        const iface = new ethers.utils.Interface(["function enableModule(address module)"]);
        safeAccountConfig.data = iface.encodeFunctionData("enableModule", [zkSafeModule.address]);

        safe = await safeFactory.deploySafe({ safeAccountConfig });
        const safeAddress = await safe.getAddress();
        console.log("safeAddress", safeAddress);

        // [api, acirComposer, acirBuffer, acirBufferUncompressed] = await initCircuits();

        // New Noir Way
        const backend = new BarretenbergBackend(circuit);
        noir = new Noir(circuit, backend);
        await noir.init();
        console.log("noir backend initialzied");
    });


    it("Should succeed verification of a basic transaction", async function () {

        const nonce = await safe.getNonce();
        const threshold = await safe.getThreshold();
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
        console.log("transaction", safeTransactionData);
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

        const zero_pubkey = { x: new Array(32).fill(0), y: new Array(32).fill(0) };
        const zero_signature = new Array(64).fill(0);
        const zero_address = new Array(20).fill(0);

        const signatures = [sig1, sig2, sig3];
        
        // Sort signatures by address - this is how the Safe contract does it.
        signatures.sort((sig1, sig2) => ethers.utils.recoverAddress(txHash, sig1).localeCompare(ethers.utils.recoverAddress(txHash, sig2)));

        const input = {
            threshold: await safe.getThreshold(),
            signers: padArray(signatures.map((sig) => extractCoordinates(ethers.utils.recoverPublicKey(txHash, sig))), 3, zero_pubkey),
            signatures: padArray(signatures.map(extractRSFromSignature), 3, zero_signature),
            hash: Array.from(ethers.utils.arrayify(txHash)),
            owners: padArray((await safe.getOwners()).map(addressToArray), 6, zero_address),
        };
        console.log("input", JSON.stringify(input));
        correctProof = await noir.generateFinalProof(input);
        console.log("correctProof", correctProof);

        const verification = await noir.verifyFinalProof(correctProof);
        expect(verification).to.be.true;
        console.log("verification in JS succeeded");


        const safeAddress = await safe.getAddress();
        const directVerification = await verifierContract.verify(correctProof["proof"], [...correctProof["publicInputs"].values()]);
        console.log("directVerification", directVerification);

        const contractVerification = await zkSafeModule.verifyZkSafeTransaction(safeAddress, txHash, correctProof["proof"]);
        console.log("contractVerification", contractVerification);

        console.log("safe: ", safe);
        console.log("transaction: ", transaction);
        const txn = await zkSafeModule.sendZkSafeTransaction(
            safeAddress,
            { to: transaction["data"]["to"],
              value: ethers.BigNumber.from(transaction["data"]["value"]),
              data: transaction["data"]["data"],
              operation: transaction["data"]["operation"],
            },
            correctProof["proof"],
            { gasLimit: 2000000 }
        );

        expect(txn).to.not.be.reverted;
    });

    xit("Should fail to verify a nonexistent contract", async function () {

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        const txn = zkSafeModule.sendZkSafeTransaction(
            "0x0000000000000000000000000000000000000000",
            transaction,
            "0x", // proof
        );

        expect(txn).to.be.reverted;
    });

    xit("Should fail a basic transaction with a wrong proof", async function () {
        
        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        const txn = await zkSafeModule.sendZkSafeTransaction(
            await safe.getAddress(),
            transaction,
            "0x0000000000000000", // proof
            { gasLimit: 20000000 }
        );

        // expect(txn).to.be.revertedWith("Invalid proof");
    });

});
