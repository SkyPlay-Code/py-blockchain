# Pure Python P2P Blockchain

A comprehensive, pedagogical implementation of a decentralized blockchain and peer-to-peer (P2P) network, written from the ground up in **Pure Python**.

This project provides a transparent, "no-magic" look at how modern cryptocurrencies operate by implementing every layer of the stack—from cryptographic primitives to network protocols—without relying on any external libraries.

---

## 🌟 Key Features

*   **Zero Dependencies**: Uses only Python's standard library (mostly `socket` for networking).
*   **From-Scratch SHA-256**: A full implementation of the FIPS 180-4 hashing standard.
*   **Custom RSA Implementation**: Includes the Miller-Rabin primality test and Extended Euclidean Algorithm for secure key generation.
*   **Asymmetric Cryptography**: Wallets use public/private key pairs for secure identity and transaction signing.
*   **Proof-of-Work (PoW) Mining**: A classic CPU-based mining mechanism with an adjustable difficulty target.
*   **Dynamic P2P Networking**: A multi-node system that supports chain synchronization and transaction broadcasting.
*   **Stateful Ledger**: Maintains a consistent balance for all addresses across the network.

---

## 🛠 Core Components

### 1. Cryptography Engine
The foundation of the blockchain is built on two custom-built cryptographic systems:
*   **`sha256(message)`**: Implements the SHA-256 compression algorithm, including message padding, constants generation, and the 64-round transformation loop.
*   **`SHA256_PRNG`**: A Pseudo-Random Number Generator that leverages SHA-256 to generate high-entropy bits for RSA key generation.
*   **RSA Wallets**: Generates **384-bit RSA keys**. We specifically use 384 bits to ensure the modulus $n$ is numerically larger than any 256-bit SHA-256 hash, preventing data loss during signing.

### 2. Transaction Lifecycle
1.  **Creation**: A sender specifies a recipient and an amount.
2.  **Signing**: The sender hashes the transaction data and signs it using their RSA private key.
3.  **Validation**: Other nodes verify the signature using the sender's public key before adding it to the pool.
4.  **Inclusion**: Valid transactions are pooled as "pending" until a miner includes them in a new block.

### 3. Block & Chain Structure
*   **`Block`**: Each block contains an index, timestamp, list of transactions, and the hash of the *previous* block.
*   **The Chain**: A linked list of blocks starting from the **Genesis Block** (index 0). Any change to a block's data invalidates its hash and all subsequent blocks.
*   **Mining**: The `mine_block` method performs PoW by iterating a `nonce` until the block hash satisfies the difficulty target (e.g., starts with `000`).

### 4. P2P Network Protocol
The `Node` class implements a custom string-based protocol over TCP sockets:
*   **`GET_CHAIN`**: Requests the full blockchain from a peer to sync local state.
*   **`NEW_TX`**: Broadcasts a new transaction to the network for validation and mining.
*   **Chain Replacement**: If a node receives a valid chain longer than its own, it adopts the longer chain (following the "Longest Chain Rule").

---

## 🚀 Getting Started

### Prerequisites
*   Python 3.6+
*   A terminal (or two!)

### Running the Demo
To witness the decentralized nature of the project, follow these steps to simulate two nodes interacting:

#### Window 1: Node A (The Miner)
1.  Run `python blockchain.py`.
2.  Enter `1` to start as **Node A**.
3.  Node A will pre-mine some coins and wait for incoming connections on port `5000`.

#### Window 2: Node B (The Peer)
1.  Run `python blockchain.py`.
2.  Enter `2` to start as **Node B**.
3.  Node B will:
    *   Connect to Node A on port `5000`.
    *   Sync its blockchain.
    *   Generate its own RSA wallet.
    *   Create and broadcast a transaction of 15 coins to Node A.
    *   Wait for Node A to mine the transaction and then re-sync.

---

## 📝 Implementation Notes & Safety

*   **Pedagogical Design**: The code is optimized for readability and learning. For example, it uses a `time_simulator` instead of system time to ensure consistency during tests.
*   **Security Disclaimer**: This implementation is for **educational purposes only**.
    *   It uses `eval()` for simple deserialization, which is unsafe for untrusted input.
    *   The 384-bit RSA keys are significantly smaller than modern production standards (2048+ bits).
    *   The networking layer does not include encryption (TLS/SSL).
*   **Performance**: Mining is performed in a single thread. Higher difficulty settings will significantly slow down the demo.

---

## 📚 What This Teaches
By exploring this codebase, you can learn:
1.  How **hashing** creates immutable links between blocks.
2.  How **digital signatures** prove ownership without revealing private keys.
3.  How **Proof-of-Work** prevents spam and double-spending.
4.  How **distributed systems** reach consensus over a network.
