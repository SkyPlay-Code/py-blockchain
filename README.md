# Pure Python Blockchain

A comprehensive, decentralized Peer-to-Peer (P2P) blockchain implementation written entirely in pure Python. This project serves as an educational resource to demonstrate the internal mechanics of a blockchain—from low-level cryptographic hashing to network-wide consensus—without relying on any external libraries.

## 🌟 Key Features

*   **Custom Cryptography**:
    *   **SHA-256**: A from-scratch implementation of the Secure Hash Algorithm 2.
    *   **RSA**: Manual implementation of RSA key generation, signing, and verification.
    *   **Miller-Rabin**: Probabilistic primality testing for generating large primes.
*   **Proof-of-Work (PoW)**: A mining mechanism with adjustable difficulty.
*   **P2P Networking**: A socket-based communication layer for chain synchronization and transaction broadcasting.
*   **Persistence**: Automatic state saving to local `.dat` files.
*   **Wallet System**: Deterministic key generation based on seed phrases.

---

## 🏗 Architecture

The system is divided into four distinct layers:

### 1. Cryptographic Layer
*   **SHA-256**: Follows the FIPS 180-4 specification. It processes messages in 512-bit chunks, applying 64 rounds of compression using constants derived from the cube roots of the first 64 prime numbers.
*   **RSA (384-bit)**:
    *   Uses the **Extended Euclidean Algorithm** to find the modular multiplicative inverse for the private exponent ($d$).
    *   Implements **Miller-Rabin** to ensure $p$ and $q$ are prime.
    *   *Note: 384-bit keys are used for speed in this educational context.*

### 2. Data Layer (`Transaction`, `Block`)
*   **Transactions**: Contain sender/recipient public keys, amount, and a digital signature.
*   **Blocks**: Bundle transactions with a timestamp, index, previous hash, and a nonce.
*   **Hashing**: Blocks are hashed using SHA-256, creating an immutable cryptographic link to the previous block.

### 3. Consensus Layer (`Blockchain`)
*   **Mining**: To add a block, a node must find a hash that starts with a specific number of leading zeros (the `difficulty`).
*   **Validation**: Every transaction is verified against the sender's public key before being added to the pending pool.
*   **Chain Replacement**: Nodes always adopt the longest valid chain received from peers (Longest Chain Rule).

### 4. Networking Layer (`Node`)
*   **Protocol**: Simple pipe-delimited string protocol over TCP sockets.
*   **Commands**:
    *   `GET_CHAIN`: Requests the full blockchain from a peer.
    *   `NEW_TX`: Broadcasts a new transaction to be mined by the network.

---

## 🚀 Getting Started

### Prerequisites
*   Python 3.x (No `pip install` required!)

### Running the Network

To experience the decentralized nature of the project, run it in two separate terminal windows.

#### Step 1: Initialize Node A (The Miner)
1.  Open Terminal 1.
2.  Run the script: `python blockchain.py`
3.  Select option `1`.
4.  Node A will generate Alice's wallet, pre-mine some initial coins, and listen on **Port 5000**.

#### Step 2: Initialize Node B (The Peer)
1.  Open Terminal 2.
2.  Run the script: `python blockchain.py`
3.  Select option `2`.
4.  Node B will:
    *   Generate Bob's wallet.
    *   Connect to Node A and download the current chain.
    *   Send 15 coins to Node A.
5.  **Observe**: Node A will receive the transaction, mine it into a new block, and Node B will then re-sync to see its updated balance.

---

## 🛠 Implementation Details

### SHA-256 Internal Functions
The implementation uses standard bitwise operations:
*   `_rotr(x, n)`: Rotate Right
*   `_shr(x, n)`: Logical Shift Right
*   `_ch(x, y, z)`: Choose
*   `_maj(x, y, z)`: Majority

### Data Persistence
The blockchain is saved as a Python dictionary string in `chain_A.dat` and `chain_B.dat`. This allows you to stop the script and resume the network later without losing the ledger.

---

## ⚠️ Limitations & Disclaimer

This project is for **educational purposes only**.
*   **Security**: The RSA implementation uses 384-bit keys, which are insecure for modern production use.
*   **Serialization**: Uses `eval()` for parsing data from disk/network, which is unsafe for untrusted inputs.
*   **Networking**: Lacks robust error handling, peer discovery, and protection against common attacks (like Sybil or DDoS).

Do not use this code to secure any real-world value.
