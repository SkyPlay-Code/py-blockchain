# Pure Python Blockchain

A fully functional, decentralized P2P blockchain implementation written entirely in pure Python. This project demonstrates the core concepts of a blockchain, including cryptographic hashing, digital signatures, proof-of-work mining, and peer-to-peer networking, without using any external libraries for the core logic.

## Features

- **Pure Python SHA-256**: A from-scratch implementation of the SHA-256 hashing algorithm.
- **RSA Cryptography & Wallets**: Custom implementation of RSA for generating public/private key pairs and signing transactions.
- **Proof-of-Work (PoW)**: A mining mechanism with adjustable difficulty to secure the network.
- **P2P Networking**: A socket-based peer-to-peer system for syncing the blockchain and broadcasting transactions.
- **Transaction Validation**: Digital signatures ensure that only the owner of a wallet can authorize transactions.
- **Reward System**: Miners are rewarded with coins for every block they successfully mine.

## Core Components

### 1. Cryptography (`sha256`, `Wallet`, `RSA`)
- **SHA-256**: Implemented using the official FIPS 180-4 specification. It handles message padding, chunk processing, and the 64-round compression loop.
- **Wallet**: Generates a 384-bit RSA key pair. The public key acts as the wallet address.
- **Digital Signatures**: Transactions are signed using the private key and verified using the public key, ensuring authenticity and integrity.

### 2. Blockchain Logic (`Transaction`, `Block`, `Blockchain`)
- **Transaction**: Represents a transfer of coins between two addresses.
- **Block**: Contains a list of transactions, a timestamp, a reference to the previous block's hash, and a nonce for mining.
- **Blockchain**: Manages the chain of blocks, handles the transaction pool, and maintains the ledger's consistency.

### 3. Networking (`Node`)
- **P2P Syncing**: New nodes can connect to existing ones to download and sync the entire blockchain.
- **Transaction Broadcasting**: Transactions sent to one node are broadcast and processed by the network.

## Getting Started

### Prerequisites
- Python 3.x

### How to Run the P2P Network

To see the decentralized network in action, you should run the script in two separate terminal windows.

#### Step 1: Start Node A (The Miner)
1. Open a terminal window.
2. Run the script:
   ```bash
   python blockchain.py
   ```
3. Select `1` to start as **Node A**.
4. Node A will initialize, pre-mine some coins, and start listening on port 5000.

#### Step 2: Start Node B (The Peer)
1. Open a second terminal window.
2. Run the script:
   ```bash
   python blockchain.py
   ```
3. Select `2` to start as **Node B**.
4. Node B will connect to Node A, sync the blockchain, and then attempt to send 15 coins to Node A.
5. You will see Node A receive the transaction, mine a new block, and Node B eventually sync the updated state.

## Implementation Details

### SHA-256 Constants and Functions
The implementation includes the standard SHA-256 constants ($K$) and initial hash values ($H\_INIT$). It uses bitwise operations (`_rotr`, `_shr`, `_ch`, `_maj`) and the sigma functions ($\Sigma_0, \Sigma_1, \sigma_0, \sigma_1$) as defined in the SHA-256 specification.

### RSA and Primality Testing
The RSA implementation uses the **Miller-Rabin Primality Test** for generating large primes and the **Extended Euclidean Algorithm** for calculating the modular inverse to find the private exponent $d$.

### Mining (Proof-of-Work)
The `mine_block` method in the `Block` class implements a simple PoW algorithm. It increments a `nonce` until the hash of the block starts with a specific number of zeros (defined by the `difficulty` level).

## Disclaimer
This project is for educational purposes only. It is not intended for use as a secure cryptocurrency or in a production environment. The RSA implementation uses relatively small keys (384-bit) for performance reasons during testing, and the P2P networking lacks robust error handling and security features.
