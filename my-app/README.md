# Getting Started

Follow these steps to create and sign a transaction. Please ensure you complete each step thoroughly before proceeding to the next one.

1. **Check out the main README**: Begin by reviewing the main README document for an overview and setup instructions.

2. **Create and Sign a Transaction**: Use the following command to create and sign a transaction. Replace `<mainnet|sepolia|gnosis|etc>` with your network of choice, `<safe address>` with your safe address, `<to-address>` with the recipient's address, `<to-value-in-wei>` with the value of the transaction in wei, and `<calldata>` with the calldata of the transaction.

    ```shell
    npx hardhat --network <mainnet|sepolia|gnosis|etc> sign --safe <safe address> --to <to-address> --value <to-value-in-wei> --data <calldata>
    ```

3. **Input Transaction Details**: After creating and signing the transaction, copy the safe address, transaction hash (txHash), and signatures (comma-separated) into the corresponding input fields in the web interface.

4. **Prove the Transaction**: Click the "Prove Transaction" button. Please wait a few minutes for the process to complete. If no proof appears on the webpage, try pressing the button again and wait a few more minutes. Keep an eye on the browser's console logs for updates; the proof should eventually be displayed on the webpage.
