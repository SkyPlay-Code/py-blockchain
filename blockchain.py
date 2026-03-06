# ==========================================
# PURE PYTHON SHA-256 IMPLEMENTATION
# ==========================================

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
# TRANSACTIONS
# ==========================================

class Transaction:
    def __init__(self, sender_pub_key, recipient_pub_key, amount):
        self.sender = sender_pub_key
        self.recipient = recipient_pub_key
        self.amount = amount
        self.signature = None

    def calculate_hash(self):
        """Hashes the transaction details."""
        data = str(self.sender) + str(self.recipient) + str(self.amount)
        return sha256(data)

    def sign_transaction(self, private_key):
        """Signs the transaction hash with the sender's private key."""
        if self.sender == "System": return # Mining rewards don't need signatures
        
        tx_hash = self.calculate_hash()
        tx_hash_int = int(tx_hash, 16)
        
        d, n = private_key
        # RSA Signature: S = (hash^d) mod n
        self.signature = pow(tx_hash_int, d, n)

    def is_valid(self):
        """Verifies the signature using the sender's public key."""
        if self.sender == "System": return True # Mining rewards are valid
        if self.signature is None: return False
        
        tx_hash = self.calculate_hash()
        tx_hash_int = int(tx_hash, 16)
        
        e, n = self.sender
        # RSA Verification: hash = (S^e) mod n
        verified_hash_int = pow(self.signature, e, n)
        
        return tx_hash_int == verified_hash_int

    def __str__(self):
        return f"{self.sender[:10]}... pays {self.recipient[:10]}... {self.amount} Coins" if self.sender != "System" else f"System pays {self.recipient[:10]}... {self.amount} Coins"

# ==========================================
# UPDATED BLOCK & BLOCKCHAIN CLASSES
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
        # We now use the calculate_hash() of each transaction object to build the block string
        tx_string = "".join(tx.calculate_hash() for tx in self.transactions)
        block_data = str(self.index) + str(self.timestamp) + tx_string + str(self.previous_hash) + str(self.nonce)
        return sha256(block_data)

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"   => Block {self.index} mined! Hash: {self.hash}")

# ==========================================
# THE BLOCKCHAIN CLASS (UPDATED FOR BALANCES)
# ==========================================

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.time_simulator = 1000 
        self.difficulty = 3
        self.pending_transactions = []
        self.mining_reward = 100

    def create_genesis_block(self):
        return Block(0, 0, [], "0" * 64)

    def get_latest_block(self):
        return self.chain[-1]

    def get_balance_of_address(self, address):
        """Calculates balance by iterating through the entire blockchain history."""
        balance = 0

        # 1. Sum up all confirmed transactions in the blockchain
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address:
                    balance -= tx.amount
                if tx.recipient == address:
                    balance += tx.amount

        # 2. Subtract unconfirmed transactions in the mempool to prevent double-spending
        for tx in self.pending_transactions:
            if tx.sender == address:
                balance -= tx.amount

        return balance

    def add_transaction(self, transaction):
        """Validates signature and balance, then adds to mempool."""
        if not transaction.is_valid():
            print("❌ ERROR: Cannot add invalid transaction (Bad Signature).")
            return False
        
        # Check balance (System/Mining rewards don't need balance checks)
        if transaction.sender != "System":
            sender_balance = self.get_balance_of_address(transaction.sender)
            if sender_balance < transaction.amount:
                print(f"❌ ERROR: Insufficient funds! Address has {sender_balance} coins, tried to send {transaction.amount}.")
                return False
                
        self.pending_transactions.append(transaction)
        return True

    def mine_pending_transactions(self, mining_reward_address):
        """Creates a block out of pending transactions and rewards the miner."""
        reward_tx = Transaction("System", mining_reward_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)

        self.time_simulator += 10
        new_block = Block(
            index=self.get_latest_block().index + 1,
            timestamp=self.time_simulator,
            transactions=self.pending_transactions,
            previous_hash=self.get_latest_block().hash
        )

        print(f"Mining block {new_block.index} containing {len(self.pending_transactions)} transactions...")
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        self.pending_transactions = []

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
            if current.hash[:self.difficulty] != "0" * self.difficulty:
                return False
            for tx in current.transactions:
                if not tx.is_valid():
                    return False
        return True

# ==========================================
# VERIFICATION / TEST RUN
# ==========================================

if __name__ == "__main__":
    print("Generating Wallets...")
    alice = Wallet("Alice")
    bob = Wallet("Bob")
    miner = Wallet("Miner")
    
    my_coin = Blockchain()

    print("\n--- PHASE 1: INITIAL DISTRIBUTION ---")
    print("Miner mines an empty block to earn the 100 coin block reward...")
    my_coin.mine_pending_transactions(miner.public_key)
    print(f"Miner Balance: {my_coin.get_balance_of_address(miner.public_key)}")
    print(f"Alice Balance: {my_coin.get_balance_of_address(alice.public_key)}")

    print("\n--- PHASE 2: MINER FUNDS ALICE ---")
    print("Miner sends 50 coins to Alice...")
    tx_fund_alice = Transaction(miner.public_key, alice.public_key, 50)
    tx_fund_alice.sign_transaction(miner.private_key)
    my_coin.add_transaction(tx_fund_alice)

    print("Miner mines the block to confirm the transaction...")
    my_coin.mine_pending_transactions(miner.public_key)
    
    # Miner spent 50, but earned 100 for mining this block! (100 - 50 + 100 = 150)
    print(f"Miner Balance: {my_coin.get_balance_of_address(miner.public_key)}")
    print(f"Alice Balance: {my_coin.get_balance_of_address(alice.public_key)}")

    print("\n--- PHASE 3: ALICE TRIES TO OVERSPEND ---")
    print("Alice tries to send 500 coins to Bob (she only has 50)...")
    tx_overspend = Transaction(alice.public_key, bob.public_key, 500)
    tx_overspend.sign_transaction(alice.private_key)
    success = my_coin.add_transaction(tx_overspend)
    if not success:
        print("Transaction successfully rejected by the network.")

    print("\n--- PHASE 4: ALICE SENDS VALID TRANSACTION ---")
    print("Alice sends 15 coins to Bob...")
    tx_valid = Transaction(alice.public_key, bob.public_key, 15)
    tx_valid.sign_transaction(alice.private_key)
    my_coin.add_transaction(tx_valid)
    
    print("Miner mines the block...")
    my_coin.mine_pending_transactions(miner.public_key)

    print("\n--- FINAL BALANCES ---")
    print(f"Alice Balance: {my_coin.get_balance_of_address(alice.public_key)}")
    print(f"Bob Balance:   {my_coin.get_balance_of_address(bob.public_key)}")
    print(f"Miner Balance: {my_coin.get_balance_of_address(miner.public_key)}")