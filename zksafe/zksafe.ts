import Safe from '@safe-global/protocol-kit';
import { EthersAdapter, SafeFactory, SafeAccountConfig } from '@safe-global/protocol-kit';
import { SafeTransactionData } from '@safe-global/safe-core-sdk-types';


import circuit from '../circuits/target/circuits.json';
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import { ethers } from "ethers";

import ZkSafeModule from "../ignition/modules/zkSafe";

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
        throw new Error('Signature should be a 132-character hex string starting with 0x.');
    }
    return Array.from(Buffer.from(signatureHex.slice(2, 130), 'hex'));
}

function addressToArray(address: string): number[] {
    if (address.length !== 42 || !address.startsWith('0x')) {
        throw new Error('Address should be a 40-character hex string starting with 0x.');
    }
    return Array.from(ethers.getBytes(address));
}

function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}

export async function zksend(hre, safeAddr: string, to: string, value: string, data: string, proof: string) {
    // Sign transaction using safe-core-sdk.
    const [mywallet] = await hre.ethers.getSigners();
    // const mywallet = new hre.ethers.Wallet(vars.get("SAFE_OWNER_PRIVATE_KEY"), ethers.provider);
    const mywalletAddress = mywallet.address;
    console.log("My wallet address: ", mywalletAddress);

    // Sign transaction using safe-core-sdk.
    const ethAdapter = new EthersAdapter({ ethers, signerOrProvider: mywallet });
    console.log("connecting to safe");
    const safe = await Safe.create({ ethAdapter, safeAddress: safeAddr });
    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const safeAddress = await safe.getAddress();
    console.log("connected to safe ", safeAddress);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", ethers.formatEther(await safe.getBalance()));

    const modules = await safe.getModules();
    let zkSafeModule = null;
    for (let i = 0; i < modules.length; i++) {
        const address = ethers.getAddress(modules[i]);
        console.log("Checking module: ", address);
        const ZkSafeModule = await hre.ethers.getContractFactory("ZkSafeModule");
        const module = await ZkSafeModule.attach(address);
        try {
            const version = await module.zkSafeModuleVersion();
            console.log("ZkSafe version: ", version);
            zkSafeModule = module;
            break;
        } catch (e) {
            console.log("Not a ZkSafe module", e);
        }
    }
    if (!zkSafeModule) {
        throw new Error("ZkSafeModule not found on Safe `${safeAddress}`");
    }

    const txn = await zkSafeModule.sendZkSafeTransaction(
        safeAddress,
        {
            to,
            value: BigInt(value),
            data,
            operation: 0
        },
        proof,
        { gasLimit: 2000000 }
    );
    console.log("Transaction hash: ", txn.hash);
    const result = txn.wait();
    console.log("Transaction result: ", await result);
}

export async function prove(hre, safeAddr: string, txHash: string, signatures_: string) {
    const [mywallet] = await hre.ethers.getSigners();
    // const mywallet = new hre.ethers.Wallet(vars.get("SAFE_OWNER_PRIVATE_KEY"), ethers.provider);
    const ethAdapter = new EthersAdapter({ ethers, signerOrProvider: mywallet });
    console.log("connecting to safe");
    const safe = await Safe.create({ ethAdapter, safeAddress: safeAddr });
    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", ethers.formatEther(await safe.getBalance()));

    const backend = new BarretenbergBackend(circuit);
    const noir = new Noir(circuit, backend);
    await noir.init();
    console.log("noir backend initialzied");

    console.log("proving ...");
    const zero_pubkey = { x: new Array(32).fill(0), y: new Array(32).fill(0) };
    const zero_signature = new Array(64).fill(0);
    const zero_address = new Array(20).fill(0);
    const signatures = signatures_.split(",");

    // Sort signatures by address - this is how the Safe contract does it.
    signatures.sort((sig1, sig2) => ethers.recoverAddress(txHash, sig1).localeCompare(ethers.recoverAddress(txHash, sig2)));
    const input = {
        threshold: await safe.getThreshold(),
        signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(txHash, sig))), 3, zero_pubkey),
        signatures: padArray(signatures.map(extractRSFromSignature), 3, zero_signature),
        hash: Array.from(ethers.getBytes(txHash)),
        owners: padArray((await safe.getOwners()).map(addressToArray), 6, zero_address),
    };
    const correctProof = await noir.generateFinalProof(input);
    console.log("Proof: ", ethers.hexlify(correctProof.proof));
}

export async function sign(hre, safeAddr: string, to: string, value: string, data: string) {
    // Sign transaction using safe-core-sdk.
    const [mywallet] = await hre.ethers.getSigners();
    console.log("initialized my wallet");
    const mywalletAddress = mywallet.address;
    console.log("My wallet address: ", mywalletAddress);

    // Sign transaction using safe-core-sdk.
    const ethAdapter = new EthersAdapter({ ethers, signerOrProvider: mywallet });
    console.log("connecting to safe");
    const safe = await Safe.create({ ethAdapter, safeAddress: safeAddr });
    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", ethers.formatEther(await safe.getBalance()));

    const safeTransactionData: SafeTransactionData = {
        to,
        value,
        data,
        operation: 0,
        // default fields below
        safeTxGas: "0x0",
        baseGas: "0x0",
        gasPrice: "0x0",
        gasToken: ethers.ZeroAddress,
        refundReceiver: ethers.ZeroAddress,
        nonce: await safe.getNonce(),
    };

    console.log("transaction", safeTransactionData);
    const transaction = await safe.createTransaction({ transactions: [safeTransactionData] });
    const txHash = await safe.getTransactionHash(transaction);
    console.log("txHash", txHash);

    const safeSig = await safe.signTypedData(transaction);

    console.log("Signature: ", safeSig.data);
}

export async function createZkSafe(hre, owners: string[], threshold: number) {
    const [mywallet] = await hre.ethers.getSigners();
    console.log("initialized my wallet");
    const mywalletAddress = mywallet.address;
    console.log("My wallet address: ", mywalletAddress);

    // Sign transaction using safe-core-sdk.
    const ethAdapter = new EthersAdapter({ ethers, signerOrProvider: mywallet });

    const safeFactory = await SafeFactory.create({ ethAdapter: ethAdapter });
    const safeAccountConfig: SafeAccountConfig =  {
        owners,
        threshold,
    };

    const { zkSafeModule } = await hre.ignition.deploy(ZkSafeModule);
    const zkSafeModuleAddress = await zkSafeModule.getAddress();
    console.log("zkSafeModule: ", zkSafeModuleAddress);

    safeAccountConfig.to = zkSafeModuleAddress;
    const iface = new ethers.Interface(["function enableModule(address module)"]);
    safeAccountConfig.data = iface.encodeFunctionData("enableModule", [zkSafeModuleAddress]);

    const safe = await safeFactory.deploySafe({ safeAccountConfig });
    const safeAddress = await safe.getAddress();
    console.log("Created zkSafe at address: ", safeAddress);
}
