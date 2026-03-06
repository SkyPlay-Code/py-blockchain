# ==========================================
# PURE PYTHON SHA-256 IMPLEMENTATION
# ==========================================

import socket

# SHA-256 Constants (First 32 bits of the fractional parts of the cube roots of the first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial Hash Values (First 32 bits of the fractional parts of the square roots of the first 8 primes)
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def _shr(x, n):
    return (x >> n) & 0xFFFFFFFF

def _ch(x, y, z):
    # Using x ^ 0xFFFFFFFF instead of ~x to avoid Python negative integer issues
    return (x & y) ^ ((x ^ 0xFFFFFFFF) & z)

def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def _SIGMA0(x): return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)
def _SIGMA1(x): return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)
def _sigma0(x): return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)
def _sigma1(x): return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)

def sha256(message_string):
    """Computes the SHA-256 hash of a string entirely from scratch."""
    b = bytearray(message_string.encode('utf-8'))
    orig_len_bits = len(b) * 8

    # Append the '1' bit
    b.append(0x80)

    # Pad with zeros until length is 56 (mod 64) bytes
    while len(b) % 64 != 56:
        b.append(0x00)

    # Append original length as a 64-bit big-endian integer
    b += orig_len_bits.to_bytes(8, 'big')

    # Initialize working variables
    h = list(H_INIT)

    # Process message in 64-byte chunks
    for chunk_start in range(0, len(b), 64):
        chunk = b[chunk_start:chunk_start+64]
        
        # Prepare the message schedule (64 32-bit words)
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:i*4+4], 'big')
        for i in range(16, 64):
            w[i] = (_sigma1(w[i-2]) + w[i-7] + _sigma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF

        a, b_reg, c, d, e, f, g, h_reg = h

        # Compression loop
        for i in range(64):
            t1 = (h_reg + _SIGMA1(e) + _ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
            t2 = (_SIGMA0(a) + _maj(a, b_reg, c)) & 0xFFFFFFFF
            h_reg = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b_reg
            b_reg = a
            a = (t1 + t2) & 0xFFFFFFFF

        # Add the compressed chunk to the current hash value
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b_reg) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF
        h[5] = (h[5] + f) & 0xFFFFFFFF
        h[6] = (h[6] + g) & 0xFFFFFFFF
        h[7] = (h[7] + h_reg) & 0xFFFFFFFF

    # Produce the final hex string
    return ''.join('{:08x}'.format(value) for value in h)

# ==========================================
# PURE PYTHON RSA & WALLETS
# ==========================================

class SHA256_PRNG:
    """A Pseudo-Random Number Generator powered by our SHA-256."""
    def __init__(self, seed_text):
        self.state = sha256(seed_text)
        
    def get_rand_bits(self, bits):
        res = ""
        while len(res) * 4 < bits:
            self.state = sha256(self.state)
            res += self.state
        # Convert hex to int and truncate to exact bit length
        return int(res, 16) >> ((len(res) * 4) - bits)

def _ext_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0: return b, 0, 1
    gcd, x1, y1 = _ext_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def _mod_inverse(e, phi):
    gcd, x, y = _ext_gcd(e, phi)
    if gcd != 1: raise Exception("Modular inverse does not exist")
    return x % phi

def _is_prime(n, prng, k=5):
    """Miller-Rabin Primality Test."""
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = 2 + (prng.get_rand_bits(128) % (n - 3))
        x = pow(a, s, n) # Python's built-in pow() handles modular exponentiation efficiently
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def _get_prime(bits, prng):
    """Generates a random prime number of specific bit length."""
    while True:
        p = prng.get_rand_bits(bits)
        p |= (1 << (bits - 1)) | 1  # Ensure it has the correct bit length and is odd
        if _is_prime(p, prng):
            return p

class Wallet:
    def __init__(self, seed_phrase):
        # We use a 192-bit prime so 'n' is 384 bits. 
        # This ensures 'n' is always strictly larger than our 256-bit SHA-256 hashes.
        prng = SHA256_PRNG(seed_phrase)
        p = _get_prime(192, prng)
        q = _get_prime(192, prng)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = _mod_inverse(e, phi)
        
        self.public_key = (e, n)  # This is the wallet address
        self.private_key = (d, n) # Keep this secret!

# ==========================================
# TRANSACTIONS (UPDATED FOR SERIALIZATION)
# ==========================================

class Transaction:
    def __init__(self, sender_pub_key, recipient_pub_key, amount):
        self.sender = sender_pub_key
        self.recipient = recipient_pub_key
        self.amount = amount
        self.signature = None

    def calculate_hash(self):
        data = str(self.sender) + str(self.recipient) + str(self.amount)
        return sha256(data)

    def sign_transaction(self, private_key):
        if self.sender == "System": return
        tx_hash_int = int(self.calculate_hash(), 16)
        d, n = private_key
        self.signature = pow(tx_hash_int, d, n)

    def is_valid(self):
        if self.sender == "System": return True
        if self.signature is None: return False
        tx_hash_int = int(self.calculate_hash(), 16)
        e, n = self.sender
        verified_hash_int = pow(self.signature, e, n)
        return tx_hash_int == verified_hash_int

    def to_dict(self):
        """Converts transaction to a dictionary for network transmission."""
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, d):
        """Rebuilds a transaction object from a dictionary."""
        tx = cls(d["sender"], d["recipient"], d["amount"])
        tx.signature = d["signature"]
        return tx

# ==========================================
# BLOCK & BLOCKCHAIN CLASSES (UPDATED)
# ==========================================

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        tx_string = "".join(tx.calculate_hash() for tx in self.transactions)
        block_data = str(self.index) + str(self.timestamp) + tx_string + str(self.previous_hash) + str(self.nonce)
        return sha256(block_data)

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }

    @classmethod
    def from_dict(cls, d):
        b = cls(d["index"], d["timestamp"], [Transaction.from_dict(tx) for tx in d["transactions"]], d["previous_hash"], d["nonce"])
        b.hash = d["hash"]
        return b

# ==========================================
# BLOCKCHAIN CLASS (UPDATED FOR STORAGE)
# ==========================================

class Blockchain:
    def __init__(self, storage_file="blockchain.dat"):
        self.storage_file = storage_file
        self.difficulty = 3
        self.time_simulator = 1000 
        self.pending_transactions = []
        self.mining_reward = 100

        # Attempt to load from disk, otherwise start fresh
        if not self.load_from_disk():
            self.chain = [self.create_genesis_block()]
            self.save_to_disk()

    def create_genesis_block(self):
        return Block(0, 0, [], "0" * 64)

    def get_latest_block(self):
        return self.chain[-1]

    def get_balance_of_address(self, address):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address: balance -= tx.amount
                if tx.recipient == address: balance += tx.amount
        for tx in self.pending_transactions:
            if tx.sender == address: balance -= tx.amount
        return balance

    def add_transaction(self, transaction):
        if not transaction.is_valid(): return False
        if transaction.sender != "System":
            if self.get_balance_of_address(transaction.sender) < transaction.amount:
                return False
        self.pending_transactions.append(transaction)
        return True

    def mine_pending_transactions(self, mining_reward_address):
        reward_tx = Transaction("System", mining_reward_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)

        self.time_simulator += 10
        new_block = Block(self.get_latest_block().index + 1, self.time_simulator, self.pending_transactions, self.get_latest_block().hash)
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        self.pending_transactions = []
        self.save_to_disk() # <--- SAVE TO DISK AFTER MINING

    def to_dict(self):
        return {
            "chain": [b.to_dict() for b in self.chain],
            "difficulty": self.difficulty,
            "time_simulator": self.time_simulator
        }

    def replace_chain(self, chain_data):
        new_chain = [Block.from_dict(b) for b in chain_data["chain"]]
        if len(new_chain) > len(self.chain):
            self.chain = new_chain
            self.difficulty = chain_data["difficulty"]
            self.time_simulator = chain_data["time_simulator"]
            self.save_to_disk() # <--- SAVE TO DISK AFTER SYNCING
            return True
        return False

    def save_to_disk(self):
        """Saves the blockchain state to a local text file."""
        try:
            with open(self.storage_file, "w") as f:
                f.write(str(self.to_dict()))
        except Exception as e:
            print(f"❌ Failed to save chain to disk: {e}")

    def load_from_disk(self):
        """Loads the blockchain state from a local text file if it exists."""
        try:
            with open(self.storage_file, "r") as f:
                data_str = f.read()
                if not data_str: return False
                chain_data = eval(data_str)
                
                self.chain = [Block.from_dict(b) for b in chain_data["chain"]]
                self.difficulty = chain_data["difficulty"]
                self.time_simulator = chain_data["time_simulator"]
                print(f"📦 Loaded existing blockchain from {self.storage_file} (Length: {len(self.chain)} blocks)")
                return True
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"❌ Failed to load chain from disk: {e}")
            return False


# ==========================================
# VERIFICATION / P2P MULTI-TERMINAL TEST
# ==========================================

if __name__ == "__main__":
    print("=========================================")
    print("       PERSISTENT P2P NETWORK            ")
    print("=========================================")
    print(" 1. Run Node A. It will mine initial coins and save to disk.")
    print(" 2. Stop Node A (Ctrl+C).")
    print(" 3. Run Node A again! It will load from disk and remember the balances!")
    print("=========================================\n")
    
    choice = input("Start as Node (1 for Node A, 2 for Node B): ")
    
    print("Generating deterministic cryptography keys...")
    alice = Wallet("Alice")
    bob = Wallet("Bob")
    
    if choice == "1":
        print("\n--- STARTING NODE A (MINER ON PORT 5000) ---")
        my_coin = Blockchain("chain_A.dat") # Specific file for Node A
        
        # Only pre-mine if this is a brand new chain
        if len(my_coin.chain) == 1:
            print("New chain detected. Pre-mining blocks to generate coins...")
            my_coin.mine_pending_transactions(alice.public_key)
            
            tx = Transaction(alice.public_key, bob.public_key, 50)
            tx.sign_transaction(alice.private_key)
            my_coin.add_transaction(tx)
            my_coin.mine_pending_transactions(alice.public_key)
        else:
            print("Resuming network from saved state...")
            
        print(f"Initialization complete.")
        print(f"Node A (Alice) Balance: {my_coin.get_balance_of_address(alice.public_key)}")
        print(f"Node B (Bob) Balance: {my_coin.get_balance_of_address(bob.public_key)}\n")
        
        node = Node('127.0.0.1', 5000, my_coin, alice)
        node.start_listening()
        
    elif choice == "2":
        print("\n--- STARTING NODE B (PEER ON PORT 5001) ---")
        my_coin = Blockchain("chain_B.dat") # Specific file for Node B
        node = Node('127.0.0.1', 5001, my_coin, bob)
        
        print("Connecting to Node A (Port 5000) to sync blockchain...")
        reply = node.send_message(5000, "GET_CHAIN|")
        
        if reply and reply.startswith("CHAIN_REPLY|"):
            chain_dict = eval(reply.split("|", 1)[1])
            my_coin.replace_chain(chain_dict)
            print("Chain downloaded, synced, and saved to disk successfully!")
        else:
            print("❌ Failed to sync chain. Make sure Node A is running first!")
            exit()
            
        balance = my_coin.get_balance_of_address(bob.public_key)
        print(f"\nNode B Initial Balance: {balance} coins")
        
        print("\nCreating P2P Transaction: Sending 15 coins to Node A...")
        tx = Transaction(bob.public_key, alice.public_key, 15)
        tx.sign_transaction(bob.private_key)
        
        print("Broadcasting transaction to network...")
        node.send_message(5000, "NEW_TX|" + str(tx.to_dict()))
        
        print("Waiting 3 seconds for Node A to mine our transaction...")
        for _ in range(15000000): pass 
        
        print("Syncing updated chain from Node A...")
        reply = node.send_message(5000, "GET_CHAIN|")
        if reply and reply.startswith("CHAIN_REPLY|"):
            chain_dict = eval(reply.split("|", 1)[1])
            my_coin.replace_chain(chain_dict)
            
        new_balance = my_coin.get_balance_of_address(bob.public_key)
        print(f"\nNode B Final Balance: {new_balance} coins")
    else:
        print("Invalid choice.")