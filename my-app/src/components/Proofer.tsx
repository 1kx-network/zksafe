// ProveTransactionComponent.tsx
import React, { useEffect, useState } from "react";
import { ethers } from "ethers";
import { Noir, ProofData } from "@noir-lang/noir_js";
import circuit from "../../../circuits/target/circuits.json"; // Adjust the path as necessary
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import {
  Box,
  Button,
  Input,
  VStack,
  useToast,
  Heading,
  Spinner,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  FormLabel,
} from "@chakra-ui/react";

function padArray(arr: any[], length: number, fill: any = 0) {
  return arr.concat(Array(length - arr.length).fill(fill));
}

function extractCoordinates(serializedPubKey: string): {
  x: number[];
  y: number[];
} {
  // Ensure the key starts with '0x04' which is typical for an uncompressed key.
  if (!serializedPubKey.startsWith("0x04")) {
    throw new Error(
      "The public key does not appear to be in uncompressed format."
    );
  }

  // The next 64 characters after the '0x04' are the x-coordinate.
  let xHex = serializedPubKey.slice(4, 68);

  // The following 64 characters are the y-coordinate.
  let yHex = serializedPubKey.slice(68, 132);

  // Convert the hex string to a byte array.
  let xBytes = Array.from(Buffer.from(xHex, "hex"));
  let yBytes = Array.from(Buffer.from(yHex, "hex"));
  return { x: xBytes, y: yBytes };
}

function addressToArray(address: string): number[] {
  if (address.length !== 42 || !address.startsWith("0x")) {
    throw new Error(
      "Address should be a 40-character hex string starting with 0x."
    );
  }
  return Array.from(ethers.getBytes(address));
}

function extractRSFromSignature(signatureHex: string): number[] {
  if (signatureHex.length !== 132 || !signatureHex.startsWith("0x")) {
    throw new Error(
      "Signature should be a 132-character hex string starting with 0x."
    );
  }
  return Array.from(Buffer.from(signatureHex.slice(2, 130), "hex"));
}

const ProofeTransactionComponent: React.FC = () => {
  const [safeAddr, setSafeAddr] = useState("");
  const [txHash, setTxHash] = useState("");
  const [signatures_, setSignatures] = useState("");
  const [proof, setProof] = useState<ProofData>();
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [threshold, setThreshold] = useState(1);
  const [safeowners, setSafeOwners] = useState<string>("");

  useEffect(() => {
    if (proof) {
      toast({
        title: "Proof generated",
        description: `Proof: ${JSON.stringify(proof)}`,
        status: "success",
        duration: 9000,
        isClosable: true,
      });
      console.log("Proof:", proof);
    }
  }, [proof]);

  const prove = async () => {
    setLoading(true);
    console.log("Proving transaction...");
    toast({
      title: "Proving transaction",
      description: "Proving transaction...",
      status: "info",
      duration: 5000,
      isClosable: true,
    });
    //@ts-ignore
    const backend = new BarretenbergBackend(circuit);
    console.log("Backend initialized...");
    toast({
      title: "Backend initialized",
      description: "Backend initialized...",
      status: "info",
      duration: 5000,
      isClosable: true,
    });
    //@ts-ignore
    const noir = new Noir(circuit, backend);
    await noir.init();
    console.log("Noir initialized...");
    toast({
      title: "Noir initialized",
      description: "Noir initialized...",
      status: "info",
      duration: 5000,
      isClosable: true,
    });

    const nil_pubkey = {
      x: Array.from(
        ethers.getBytes(
          "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
      ),
      y: Array.from(
        ethers.getBytes(
          "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
      ),
    };
    // Our Nil signature is a signature with r and s set to the G point
    const nil_signature = Array.from(
      ethers.getBytes(
        "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
      )
    );
    const zero_address = new Array(20).fill(0);
    const signatures = signatures_.split(",");
    signatures.sort((sig1, sig2) =>
      ethers
        .recoverAddress(txHash, sig1)
        .localeCompare(ethers.recoverAddress(txHash, sig2))
    );
    const owners_ = safeowners.split(",");
    const input = {
      threshold: threshold, // Set the threshold as necessary
      signers: padArray(
        signatures.map((sig) =>
          extractCoordinates(ethers.SigningKey.recoverPublicKey(txHash, sig))
        ),
        10,
        nil_pubkey
      ),
      signatures: padArray(
        signatures.map(extractRSFromSignature),
        10,
        nil_signature
      ),
      txn_hash: Array.from(ethers.getBytes(txHash)),
      owners: padArray(owners_.map(addressToArray), 10, zero_address),
    };
    console.log("Input:", input);
    console.log("Generating proof...");
    toast({
      title: "Generating proof",
      description: "Generating proof...",
      status: "info",
      duration: 5000,
      isClosable: true,
    });
    const correctProof = await noir.generateFinalProof(input);
    setProof(correctProof);
    // Implement the logic to generate and log the proof as in the original prove function
    toast({
      title: "Proof generated",
      description: "Proof successfully generated",
      status: "success",
      duration: 5000,
      isClosable: true,
    });
    setLoading(false);
  };

  return (
    <Box p={5}>
      <VStack spacing={4} align="stretch">
        <Heading size="lg">Proof Generation with Aztec Noir Example</Heading>
        <Input
          value={safeAddr}
          onChange={(e) => setSafeAddr(e.target.value)}
          placeholder="Safe Address"
        />
        <Input
          value={safeAddr}
          onChange={(e) => setSafeOwners(e.target.value)}
          placeholder="Safe Owners (comma-separated)"
        />
        <FormLabel htmlFor="threshold">Safe Threshold (1-12)</FormLabel>
        <NumberInput
          defaultValue={1}
          min={1}
          max={12}
          keepWithinRange={true}
          clampValueOnBlur={false}
        >
          <NumberInputField
            onChange={(e) => setThreshold(parseInt(e.target.value))}
            placeholder="Threshold (1-12)"
          />
          <NumberInputStepper>
            <NumberIncrementStepper />
            <NumberDecrementStepper />
          </NumberInputStepper>
        </NumberInput>
        <Input
          value={txHash}
          onChange={(e) => setTxHash(e.target.value)}
          placeholder="Transaction Hash"
        />
        <Input
          value={signatures_}
          onChange={(e) => setSignatures(e.target.value)}
          placeholder="Signatures (comma-separated)"
        />

        <Button colorScheme="blue" onClick={prove}>
          Prove Transaction
        </Button>
      </VStack>
      {loading && (
        <Box mt={5}>
          <Heading size="md">Loading...(this can take a few minutes)</Heading>
          <Spinner />
        </Box>
      )}
      {proof && ( // Display the proof if it exists
        <Box mt={5}>
          <Heading size="md">Proof</Heading>
          <pre>{JSON.stringify(proof, null, 2)}</pre>
        </Box>
      )}
    </Box>
  );
};

export default ProofeTransactionComponent;
