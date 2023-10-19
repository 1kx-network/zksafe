# zkSafe is Safe with zk hiding of owners and signers.

zkSafe works by using the separate Safe module, which verifies zk proofs and submit transactions. To start using zkSafe, install the following address as a module.


## Testing

```
yarn install
npx hardhat node
npx hardhat deploy --network localhost
npx hardhat test --network localhost
```


## Usage
TODO add addresses for various networks.


## Hiding signers

This is the first stage of hiding. To hide singers, we collect signatures then produce a zk proof of having verified the signatures and that the owners have been in the list of owners.

## Hiding all owners

Hiding the owner list itself is achieved via storing a commitment to the set of owners in the smart contract, and verifying the proof of ownership in the transaction verification.


