import Safe from '@safe-global/protocol-kit';
import { EthersAdapter, SafeFactory, SafeAccountConfig } from '@safe-global/protocol-kit';
import { SafeTransactionData, TransactionOptions } from '@safe-global/safe-core-sdk-types';


import circuit from '../circuits/target/circuits.json';
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import { ethers, toBeHex } from "ethers";
import { vars } from "hardhat/config";

import ZkSafeModule from "../ignition/modules/zkSafe";
import { IMT } from '@zk-kit/imt';
import { poseidon } from '@iden3/js-crypto';

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
    const mywallet = new hre.ethers.Wallet(vars.get("SAFE_OWNER_PRIVATE_KEY"), hre.ethers.provider);
    const mywalletAddress = mywallet.address;
    console.log("My wallet address: ", mywalletAddress);

    // Sign transaction using safe-core-sdk.
    const ethAdapter = new EthersAdapter({ ethers, signerOrProvider: mywallet });
    console.log("connecting to safe");
    const safe = await Safe.create({ ethAdapter, safeAddress: safeAddr });
    const version = await safe.getContractVersion();
    const safeAddress = await safe.getAddress();
    console.log("connected to safe ", safeAddress);
    console.log("  version: ", version);
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

export async function prove(hre, safeAddr: string, txHash: string, signatures_: string, zkSafeModulePrivateOwners: string[], ownersAddressesFormat: number) {
    const mywallet = new hre.ethers.Wallet(vars.get("SAFE_OWNER_PRIVATE_KEY"), hre.ethers.provider);
    const ethAdapter = new EthersAdapter({ ethers, signerOrProvider: mywallet });
    console.log("connecting to safe");
    const safe = await Safe.create({ ethAdapter, safeAddress: safeAddr });
    const version = await safe.getContractVersion();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
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
    
    // New Noir Way
    const backend = new BarretenbergBackend(circuit);
    const noir = new Noir(circuit);
    console.log("noir backend initialzied");

    console.log("proving ...");
    const nil_pubkey = {
        x: Array.from(ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
        y: Array.from(ethers.getBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    };
    // Our Nil signature is a signature with r and s set to the G point
    const nil_signature = Array.from(
        ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
    const zero_address = new Array(20).fill(0);
    const signatures = signatures_.split(",");

    // Sort signatures by address - this is how the Safe contract does it.
    signatures.sort((sig1, sig2) => ethers.recoverAddress(txHash, sig1).localeCompare(ethers.recoverAddress(txHash, sig2)));
    
    const modulePrivateOwnersTree = new IMT(poseidon.hash, 3, 0, 2)
    for (var privateOwner of zkSafeModulePrivateOwners) {
        /*0: Normal address
          1: Poseidon Hash address*/
        if(ownersAddressesFormat == 0)
            modulePrivateOwnersTree.insert(poseidon.hash([BigInt(privateOwner)]))
        else if (ownersAddressesFormat == 1) 
            modulePrivateOwnersTree.insert(BigInt(privateOwner))
        else
            throw new Error("Invalid owner addresses format variable value (0: Normal address) or (1: Poseidon Hash address)");
    }
    const ownersIndicesProof: number[] = []
    const ownersPathsProof: any[][] = []
    for (var signature of signatures) {
        const recoveredAddress = ethers.recoverAddress(txHash,signature)
        const index= await modulePrivateOwnersTree.indexOf(poseidon.hash([BigInt(recoveredAddress)]));
        const addressProof= await modulePrivateOwnersTree.createProof(index);
        addressProof.siblings = addressProof.siblings.map((s) => s[0])
        await ownersIndicesProof.push(Number("0b" + await addressProof.pathIndices.join("")))
        await ownersPathsProof.push(addressProof.siblings)
    }

    const input = {
        threshold:   toBeHex((await zkSafeModule.safeToConfig(safeAddr)).threshold),
        signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(txHash, sig))), 4, nil_pubkey),
        signatures: padArray(signatures.map(extractRSFromSignature), 4, nil_signature),
        txn_hash: Array.from(ethers.getBytes(txHash)),
        owners_root:  (await zkSafeModule.safeToConfig(safeAddr)).ownersRoot,
        indices: padArray(ownersIndicesProof.map(indice => toBeHex(indice)), 4, "0x0"),
        siblings: padArray(ownersPathsProof.map(paths => paths.map(path => toBeHex(path))), 4, ["0x0", "0x0", "0x0"])
    };

    console.log('logs', 'Generating witness... ⌛');
    const { witness, returnValue } = await noir.execute(input);
    console.log('logs', 'Generating proof... ✅');
    const correctProof = await backend.generateProof(witness);
    console.log("proof", ethers.hexlify(correctProof.proof));
}

export async function sign(hre, safeAddr: string, to: string, value: string, data: string) {
    // Sign transaction using safe-core-sdk.
    const mywallet = new hre.ethers.Wallet(vars.get("SAFE_OWNER_PRIVATE_KEY"), hre.ethers.provider);
    console.log("mywallet: ", mywallet);
    console.log("initialized my wallet");
    const mywalletAddress = mywallet.address;
    console.log("My wallet address: ", mywalletAddress);

    // Sign transaction using safe-core-sdk.
    const ethAdapter = new EthersAdapter({ ethers, signerOrProvider: mywallet });
    console.log("connecting to safe");
    const safe = await Safe.create({ ethAdapter, safeAddress: safeAddr });
    const version = await safe.getContractVersion();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
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

export async function createZkSafe(hre, owners: string[], threshold: number, zkSafeModulePrivateOwners: string[], zkSafeModuleThreshold: number) {
    const mywallet = new hre.ethers.Wallet(vars.get("DEPLOYER_PRIVATE_KEY"), hre.ethers.provider);
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

    const modulePrivateOwnersTree = new IMT(poseidon.hash, 3, 0, 2)
    for (var privateOwner of zkSafeModulePrivateOwners) {
        modulePrivateOwnersTree.insert(poseidon.hash([BigInt(privateOwner)]))
    }
    safeAccountConfig.to = zkSafeModuleAddress;
    const iface = new ethers.Interface(["function enableModule(bytes32 ownersRoot, uint256 threshold)"]);
    safeAccountConfig.data = iface.encodeFunctionData("enableModule", [toBeHex(modulePrivateOwnersTree.root), zkSafeModuleThreshold]);

    /*const options: TransactionOptions = {
        maxFeePerGas: 80000000000,
        maxPriorityFeePerGas: 40000000000
    }*/
    const safe = await safeFactory.deploySafe({ safeAccountConfig/*, options */});
    const safeAddress = await safe.getAddress();
    console.log("Created zkSafe at address: ", safeAddress);
    console.log("Private owners addresses: ", modulePrivateOwnersTree.leaves);
}
