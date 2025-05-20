import hre, { deployments } from 'hardhat';
import { expect } from "chai";
import assert = require('assert');
import { WalletClient, PublicClient, zeroAddress, parseEther, encodeFunctionData, toHex, fromHex, concatHex, Account, toBytes, fromBytes, recoverAddress, recoverPublicKey, Hex, getContract } from "viem";
import Safe, {
    ContractNetworksConfig,
    PredictedSafeProps,
    SafeAccountConfig,
} from '@safe-global/protocol-kit';
import { MetaTransactionData, SafeSignature, SafeTransaction, OperationType, SafeTransactionData } from "@safe-global/types-kit";

import ZkSafeModule from "../ignition/modules/zkSafe";

import circuit from '../circuits/target/circuits.json';
import { UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { extractCoordinates, extractRSFromSignature, addressToArray, padArray, prove, proveTransactionSignatures } from '../zksafe/zksafe';

const DEFAULT_TRANSACTION = {
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
}

function makeSafeTransaction(nonce: number, fields: Partial<SafeTransactionData>) {
    return { nonce, ...DEFAULT_TRANSACTION, ...fields }
}

async function getContractNetworks(chainId: number): Promise<ContractNetworksConfig> {
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
    )
    return {
        [chainId.toString()]: {
            ...deploymentAddresses,
            simulateTxAccessorAddress: zeroAddress,
            safeWebAuthnSignerFactoryAddress: zeroAddress,
            safeWebAuthnSharedSignerAddress: zeroAddress,
        }
    }
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
    let zkSafeModule: any;
    let verifierContract: any;

    let createSafeFromWalletAddress:  (wallet: WalletClient, safeAddress: string) => Promise<Safe>;
    let signTransactionFromUser: (wallet: WalletClient, safe: Safe, transaction: SafeTransaction) => Promise<SafeSignature>;

    // New Noir Way
    let noir: Noir;
    let backend: UltraHonkBackend;

    before(async function () {
        await deployments.fixture();

        const result = await hre.ignition.deploy(ZkSafeModule);
        zkSafeModule = result.zkSafeModule;
        verifierContract = result.verifier;

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
        const chainId = walletClient.chain?.id ?? 1;

        createSafeFromWalletAddress = async (wallet: WalletClient, safeAddress: string): Promise<Safe> => {
            return await Safe.init({
                provider: wallet.transport,
                signer: wallet.account?.address,
                safeAddress,
                contractNetworks: await getContractNetworks(chainId),
            });
        }

        const calldata = encodeFunctionData({
            abi: [{
                name: 'enableModule',
                type: 'function',
                stateMutability: 'nonpayable',
                inputs: [{ name: 'module', type: 'address' }],
                outputs: []
            }],
            functionName: 'enableModule',
            args: [zkSafeModule.address]
        });

        safe = await Safe.init({
            provider: walletClient.transport,
            predictedSafe: {
                safeAccountConfig: {
                    owners: [(accounts[0].account as Account).address,
                               (accounts[1].account as Account).address,
                               (accounts[2].account as Account).address],
                    threshold: 1,
                    to: zkSafeModule.address,
                    data: calldata,
                }
            },
            contractNetworks: await getContractNetworks(chainId),
        });

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

        signTransactionFromUser = async (wallet: WalletClient, safe: Safe, transaction: SafeTransaction): Promise<SafeSignature> => {
            const userSafe = await createSafeFromWalletAddress(wallet, await safe.getAddress());
            const signerAddress = await userSafe.getSafeProvider().getSignerAddress();
            const signedTransaction = await userSafe.signTransaction(transaction);
            return signedTransaction.getSignature(signerAddress!)!;
        };

        // New Noir Way
        backend = new UltraHonkBackend(circuit.bytecode);
        noir = new Noir(circuit, backend);
        await noir.init();
    });

    function readjustSigFromEthSign(signature: SafeSignature): Hex {
        const sig = toBytes(signature.data);
        if (sig[64] > 30) {
           sig[64] -= 4;
        }
        return fromBytes(sig, 'hex');
    }

    it("Should succeed verification of a basic transaction", async function () {

        const nonce = await safe.getNonce();
        const threshold = await safe.getThreshold();
        const metaTransaction = makeSafeTransaction(nonce, {});
        const transaction = await safe.createTransaction({ transactions: [metaTransaction] });
        const txHash = await safe.getTransactionHash(transaction);

        const sig1 = await signTransactionFromUser(accounts[0], safe, transaction);
        const sig2 = await signTransactionFromUser(accounts[1], safe, transaction);
        const sig3 = await signTransactionFromUser(accounts[2], safe, transaction);
        const signatures = [sig2.data as Hex, sig3.data as Hex]; // sig1 is not included, threshold of 2 should be enough.
        const proof = await proveTransactionSignatures(safe, signatures, txHash as Hex);

        // Convert Uint8Array proof to hex string for contract call
        const proofHex = `0x${Buffer.from(proof.proof).toString('hex')}`;
        const directVerification = await verifierContract.read.verify([proofHex, proof.publicInputs]);

        const contractVerification = await zkSafeModule.read.verifyZkSafeTransaction([await safe.getAddress(), txHash, proofHex]);
        const txn = await zkSafeModule.write.sendZkSafeTransaction([
            safeAddress,
            { to: transaction.data.to,
              value: BigInt(transaction.data.value),
              data: transaction.data.data,
              operation: transaction.data.operation,
            },
            proofHex, // Use truncated proof for transaction
        ]);

        const receipt = await publicClient.waitForTransactionReceipt({ hash: txn });
        expect(receipt.status).to.equal('success');
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

        await expect(zkSafeModule.write.sendZkSafeTransaction([
          "0x0000000000000000000000000000000000000000",
          transaction,
          "0x", // empty proof
        ])).to.be.rejected;
    });

    it("Should fail a basic transaction with a wrong proof", async function () {

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        await expect(zkSafeModule.write.sendZkSafeTransaction([
            await safe.getAddress(),
            transaction,
            "0x" + "0".repeat(2 * 440 * 32), // invalid proof (440 * 32 zeros)
        ])).to.be.rejectedWith(/custom error/);
    });
});
