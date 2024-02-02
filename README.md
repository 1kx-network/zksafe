# zkSafe is Safe module allowing owners signing Safe transactions without doxxing themselves

WARNING: don't use it for production and/or large amounts yet. This is an Alpha version.

When you use (Gnosis) Safe, signers of transactins leave the trace both onchain and in the Safe's REST API.  Anyone in the world is able to see exactly which addresses signed a given transaction.
In many cases, this is not desirable.

zkSafe allows Safe owners to collectively sign transactions, without revealing who exactly  signed it.  The zkSafe module only ensures that there's a proof of:
  1. At least threshold number of valid transactions signatures
  2. That are pairwise disinct (i.e. you can't reach threshold by including the signature twice)
  3. Each of which is done by one of the Safe's owners.

Once the module sees such a proof accompanying a Safe transaction, the module can safely execute it.

Currently, zkSafe doesn't hide the owners themselves. The whole world can still see who the Safe owners are. Only the signers of specific transactions are hidden.  In the future zkSafe will also hide the list of owners.


## Testing

```
yarn install
npx hardhat node
npx hardhat deploy --network localhost
npx hardhat test --network localhost
```


## Usage

### Creating a zkSafe

First, compile the project so that the Ultraverifier Solidity code is produced:

```
npx hardhat compile
```

One can add the zkSafe module to any existing Safe thus enabling the option of zk singing.
The addresses of the modules are:


* Sepolia: 0x6BCB4994265AF42e73533f2565DF85CdF30aafF9
* Gnosis Chain: 0xB7F27A6aFd3F9bCB8EBA9dCe8126e876B78CD443

_TODO_ add other networks.


#### Manually adding zkSafe

Send the following transaction using Safe's Transaction Builder:

```
To: your safe address
Value: 0
Calldata: 0x610b59250000000000000000000000006bcb4994265af42e73533f2565df85cdf30aaff9
```

Calldata corresponds to `enableModule(address)`. Substitute the ending hex digits with the address of the zkSafe module.
Sign this transaction with threshold number of owners and execute it it.

#### Creating a new Safe with zkSafe module enabled

Alternatively one can create a Safe with the zk module enabled using the following hardhat task `createZkSafe`, for example:

```
$ npx hardhat createZkSafe --network <mainnet|gnosis|sepolia> --owners 0x0Ccb2b6675A60EC6a5c20Fb0631Be8EAF3Ba2dCD,0x48129F999598675F40A6d36Cec58a623b8c0228d,0x6804a7411adFAEB185d4dE27a04e5B6281160822 --threshold 2 
initialized my wallet
My wallet address:  0x0Ccb2b6675A60EC6a5c20Fb0631Be8EAF3Ba2dCD
zkSafeModule:  0xec2dE1dfa3C2e1435823732E7390eFcF1b1B05B1
Created zkSafe at address:  0xE437407d73cb2e57F0dA6Dbe822e498a4Acc1c16
```

Note the last address that the command returns - this is the address of your Safe. You can use it via the Safe UI normally, and using hardhat tasks for zk signing.


### Creating a new transaction

ZkSafe doesn't require any usual UI flow for transaction.  The owners signing a transaction need to agree on the transaction parameters (to, value, calldata) offline. The reason for this is that creating a transaction in the Safe UI leaves a trace via the Safe REST API, and thus defeats the purpose of zkSafe.

Each of the signing owners will produce a signature for the desired transaction, and send over the txn hash and the signature to the prover.  The prover could be one of the owners, or a completely separate person/entity. Prover just needs to produce a SNARK certifying that it has seen at least a threshold of valid signatures of the owners of the Safe.

Here's how one can sign a transaction with zkSafe hardhat tasks using the `sign` hardhat task:

```
npx hardhat --network <mainnet|sepolia|gnosis|etc> sign --safe <safe address> --to <to-address> --value <to-value-in-wei> --data <calldata>
```

It will check the chain ID, current Safe transaction nonce, etc, and generate the transaction hash and signature just as Safe would via the UI.
The command will output the transaction hash, and the signature. These values need to be send to the prover.

### Proving the transaction

Having collected all the signatures, we need to generate a proof. This is done with the `prove` hardhat task.

```
npx hardhat --network <mainnet|sepolia|gnosis|etc>  prove --safe <safe address>  --signatures <signature1>,<signature2>,<sinagure3> --txhash <txhash>
```

Proving might take a couple of minutes, and would return a large hex string starting with 0x.  This is the prove that needs to be sent to zkSafe along with the transaction.

WARNING: Only up to 10 owners/signatures is supported at the moment. This limit will be increased (or completely removed) soon.


### Sending a proven transaction

Once we have the proof, we may send it. Proving and sending the transaction are separate steps, because they can be done by different entities. For instance, one can send the transaction from a relay.
Here is how one can use the hardhat task `zksend`.

```
npx hardhat --network  <mainnet|sepolia|gnosis|etc> zksend --safe <safe address>  --to <to-address> --value <to-value-in-wei> --data <calldata> --proof <proof hex string>
```

If the prove is correct, the transaction will call DELEGATECALL on the Safe to bump the transaction nonce, and then execute the required transction from the module.
