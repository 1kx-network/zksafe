import hre, { deployments } from 'hardhat';
import { expect } from "chai";
import { WalletClient, PublicClient, zeroAddress, parseEther, encodeFunctionData, toHex, fromHex, concatHex, Account, toBytes, recoverMessageAddress, recoverPublicKey } from "viem";
import Safe, {
    ContractNetworksConfig,
    PredictedSafeProps,
    SafeAccountConfig,
} from '@safe-global/protocol-kit';

import { ZkSafeModule } from "../typechain-types";

import circuit from '../circuits/target/circuits.json';
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import { MetaTransactionData, SafeSignature, OperationType } from "@safe-global/types-kit";

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
    return Array.from(toBytes(address));
}

function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}

describe("ZkSafeModule", function () {

    let namedAccounts: { [name: string]: string };
    let accounts: WalletClient[];
    let safeAddress: `0x${string}`;
    let zkSafeModuleAddress: `0x${string}`;

    let publicClient: PublicClient;
    let walletClient: WalletClient;
    let usersWalletClient: WalletClient;

    let safe: Safe;
    let zkSafeModule: ZkSafeModule;
    let verifierContract: any;

    let createSafeFromWalletAddress: (wallet: WalletClient, safeAddress: string) => Promise<Safe>;
    let signTransactionFromUser: (wallet: WalletClient, safe: Safe, txHash: string) => Promise<SafeSignature>;

    // New Noir Way
    let noir: Noir;
    let correctProof: Uint8Array;

    before(async function () {
        await deployments.fixture();

        // Get deployer account
        accounts = await hre.viem.getWalletClients();
        publicClient = await hre.viem.getPublicClient();

        // Configure for consistent gas estimation
        const originalEstimateGas = publicClient.estimateGas;
        publicClient.estimateGas = async (args: any) => {
            // Use a cached/fixed value for gas estimation
            return BigInt("0x1000000");
        };

        namedAccounts = await hre.getNamedAccounts();
        walletClient = accounts[0];
        usersWalletClient = accounts[1];

        const deploymentAddresses = Object.fromEntries(
            await Promise.all(
                Object.entries({
                    safeSingletonAddress: "SafeL2",
                    safeProxyFactoryAddress: "SafeProxyFactory",
                    multiSendAddress: "MultiSend",
                    multiSendCallOnlyAddress:  "MultiSendCallOnly",
                    fallbackHandlerAddress: "CompatibilityFallbackHandler",
                    signMessageLibAddress:  "SignMessageLib",
                    createCallAddress:  "CreateCall",
                }).map(async ([key, value]) => [key, (await deployments.get(value)).address])
            )
        );

        const chainIdStr = walletClient.chain?.id.toString() ?? "1";
        console.log("chainId: ", chainIdStr);
        
        const contractNetworks: ContractNetworksConfig = {
            [chainIdStr]: {
                ...deploymentAddresses,
                simulateTxAccessorAddress: zeroAddress,
                safeWebAuthnSignerFactoryAddress: zeroAddress,
                safeWebAuthnSharedSignerAddress: zeroAddress,
            }
        };

        createSafeFromWalletAddress = async (wallet: WalletClient, safeAddress: string): Promise<Safe> => {
            return await Safe.init({
                provider: wallet.transport,
                signer: wallet.account?.address,
                safeAddress,
                contractNetworks,
            });
        }
        
        const safeAccountConfig: SafeAccountConfig =  {
            owners: [namedAccounts.users],
            threshold: 1,
        };
        const predictedSafe: PredictedSafeProps = {
            safeAccountConfig,
        };

        safe = await Safe.init({
            provider: walletClient.transport,
            predictedSafe,
            contractNetworks,
        });
        // [api, acirComposer, acirBuffer, acirBufferUncompressed] = await initCircuits();

        safeAddress = await safe.getAddress() as `0x${string}`;
        const deploymentTransaction = await safe.createSafeDeploymentTransaction();

        const transactionHash = await walletClient.sendTransaction({
            account: walletClient.account as Account,
            chain: walletClient.chain,
            to: deploymentTransaction.to,
            value: parseEther(deploymentTransaction.value),
            data: deploymentTransaction.data as `0x${string}`,
        });

        const transactionReceipt = await publicClient.waitForTransactionReceipt({
            hash: transactionHash
        });

        expect(transactionReceipt.status).to.be.equal("success");
        console.log("Safe created at: ", safeAddress);
        expect(await safe.isSafeDeployed()).to.be.true;

        // Now when the Safe is deployed, reinitialize protocol-kit Safe wrapper as
        // initialized Safe.
        safe = await createSafeFromWalletAddress(usersWalletClient, safeAddress);

        signTransactionFromUser = async (wallet: WalletClient, safe: Safe, txHash: string): Promise<SafeSignature> => {
            const userSafe = await createSafeFromWalletAddress(wallet, await safe.getAddress());
            return await userSafe.signHash(txHash);
        };

        // New Noir Way
        const backend = new BarretenbergBackend(circuit);
        noir = new Noir(circuit, backend);
        await noir.init();
        console.log("noir backend initialzied");
    });


    it("Should succeed verification of a basic transaction", async function () {

        const nonce = await safe.getNonce();
        const threshold = await safe.getThreshold();
        const safeTransactionData = {
            to: zeroAddress,
            value: "0x0",
            data: "0x",
            operation: 0,
            // default fields below
            safeTxGas: "0x0",
            baseGas: "0x0",
            gasPrice: "0x0",
            gasToken: zeroAddress,
            refundReceiver: zeroAddress,
            nonce, 
        }
        console.log("transaction", safeTransactionData);
        const transaction = await safe.createTransaction({ transactions: [safeTransactionData] });
        const txHash = await safe.getTransactionHash(transaction);
        console.log("txHash", txHash);

        // Let's generate three signatures for the owners of the Safe.
        // ok, our siganture is a EIP-712 signature, so we need to sign the hash of the transaction.
        let safeTypedData = {
            safeAddress: await safe.getAddress(),
            safeVersion: await safe.getContractVersion(),
            chainId: await safe.getChainId(),
            safeTransactionData: safeTransactionData,
        }; 
        const sig1 = await signTransactionFromUser(accounts[0], safe, txHash);
        const sig2 = await signTransactionFromUser(accounts[1], safe, txHash);
        const sig3 = await signTransactionFromUser(accounts[2], safe, txHash);

        const nil_pubkey = {
            x: Array.from(toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            y: Array.from(toBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        };
        // Our Nil signature is a signature with r and s set to 
        const nil_signature = Array.from(
            toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
        const zero_address = new Array(20).fill(0);

        const signatures = [sig2, sig3]; // sig1 is not included, threshold of 2 should be enough.
        
        // Sort signatures by address - this is how the Safe contract does it.
        const sortedSignatures = await Promise.all(signatures.map(async (sig) => {
            const addr = await recoverMessageAddress({ 
                message: { raw: txHash as `0x${string}` }, 
                signature: sig.data as `0x${string}` 
            });
            return { sig, addr };
        }));
        sortedSignatures.sort((a, b) => a.addr.localeCompare(b.addr));
        const sortedSigs = sortedSignatures.map(s => s.sig);

        const input = {
            threshold: await safe.getThreshold(),
            signers: padArray(await Promise.all(sortedSigs.map(async (sig) => {
                const pubKey = await recoverPublicKey({ 
                    hash: txHash as `0x${string}`,
                    signature: sig.data as `0x${string}` 
                });
                return extractCoordinates(pubKey);
            })), 10, nil_pubkey),
            signatures: padArray(sortedSigs.map(sig => extractRSFromSignature(sig.data as `0x${string}`)), 10, nil_signature),
            txn_hash: Array.from(toBytes(txHash as `0x${string}`)),
            owners: padArray((await safe.getOwners()).map(addressToArray), 10, zero_address),
        };
        const proof = await noir.generateFinalProof(input);
        console.log("correctProof", proof);

        const verification = await noir.verifyFinalProof(proof);
        expect(verification).to.be.true;
        console.log("verification in JS succeeded");


        const safeAddress = await safe.getAddress();
        const directVerification = await verifierContract.verify(proof.proof, [...proof.publicInputs.values()]);
        console.log("directVerification", directVerification);

        const contractVerification = await zkSafeModule.verifyZkSafeTransaction(safeAddress, txHash, proof.proof);
        console.log("contractVerification", contractVerification);

        console.log("safe: ", safe);
        console.log("transaction: ", transaction);
        const txn = await zkSafeModule.sendZkSafeTransaction(
            safeAddress,
            { to: transaction.data.to,
              value: BigInt(transaction.data.value),
              data: transaction.data.data,
              operation: transaction.data.operation,
            },
            proof.proof,
            { gasLimit: 2000000 }
        );

        let receipt = txn.wait();
        expect(txn).to.not.be.rejected;
        let newNonce = await safe.getNonce();
        expect(newNonce).to.equal(nonce + 1);
    });

    it("Should fail to verify a nonexistent contract", async function () {

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

        expect(txn).to.be.rejected;
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
            { gasLimit: 2000000 }
        );

        expect(txn).to.be.rejectedWith("Invalid proof");
    });

});
