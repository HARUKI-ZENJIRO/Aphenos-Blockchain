# APHENOS TESTNET v0.1  
**Proof of Useful Work + ZeroKnowledge Blockchain**

APHENOS is an experimental blockchain designed from the ground up to explore a new consensus paradigm:  
**Proof of Useful Work (PoUW)** combined with **ZeroKnowledge Proofs (ZKP)**.  
This first version implements a complete and functional flow that includes:

- Key generation  
- Transaction signing  
- Cryptographic validation  
- Mining with PoUW mock  
- ZKP mock verification  
- Bitcoin-style dynamic difficulty  
- Persistent account state  
- Chained blocks with Merkle Root  

---

# 🌌 Why APHENOS?

The name comes from **Aphelion**, the farthest point in a planet’s orbit from the Sun. It represents expansion, resilience, and the ability to reach where others cannot.

### 1. Scientific Root  
**Aphelion** comes from the Greek *apo* (away) and *helios* (sun).  
To create **Aphenos**, the following creative liberties were taken:

- **“Aph”** preserves the root of Aphelion.  
- **“-enos”** adds identity, substance, and a technical sound (similar to *ethos*, *genos*).  

### 2. The Concept  
The Aphelion symbolizes:

- **Reach:** going farther than other projects.  
- **Resilience:** remaining stable even at the coldest and most distant point.  
- **Exclusivity:** a unique place in the technological cosmos.  

---

# 🔐 Consensus Protocol: PoW + ZKP

APHENOS introduces a consensus model inspired by Proof of Work, but extended with **zero-knowledge proofs** to enable demonstrable, verifiable, and potentially useful computation.

Instead of merely solving an arbitrary puzzle, the miner generates a **cryptographic proof** showing that:

- They executed the mining algorithm correctly.  
- They used the correct data (header, transactions, previous state).  
- They reached the target difficulty.  
- They did not skip steps or apply shortcuts.  

All of this is done **without revealing internal computation details**.

This design prepares APHENOS to evolve into a real PoUW system, where miners’ work can align with useful real-world tasks.

---

# ⚙️ How It Works

### 1. Computational Work  
The miner performs a computation defined by the protocol (currently classical PoW, but structured to evolve into real PoUW).

### 2. ZKP Generation  
The miner produces a proof demonstrating that they followed the exact procedure and reached the required difficulty.

### 3. Block Construction  
Each block includes:

- Valid hash  
- Mock ZKP proof  
- Transactions  
- Coinbase  
- Merkle Root  
- Block metadata  

### 4. Network Verification  
Nodes:

- Verify the ZKP proof (fast and deterministic).  
- Validate difficulty, structure, and signatures.  
- Accept the block if everything is correct.  

---

# 🚀 Why This Approach Is Innovative

### ✔️ Separation between “doing the work” and “verifying the work”  
Miners perform heavy computation, but nodes verify only a lightweight proof.

### ✔️ Solid foundation for real PoUW  
The protocol is designed so the puzzle can be replaced with useful tasks:

- Halo2/Plonk circuits  
- Proof verification  
- Simulations  
- Scientific computation  

### ✔️ Conceptual compatibility with traditional PoW  
It maintains the familiar structure:

- Blocks  
- Difficulty  
- Coinbase  
- Linear chain  

---

# 🔐 Why It Is More Secure

### 🔸 Proofs against cheating  
The ZKP ensures the miner cannot falsify the process.

### 🔸 Uniform verification  
All nodes verify the same proof with the same verifier.

### 🔸 Built‑in privacy  
It allows proving work over sensitive data without revealing it.

### 🔸 More expressive consensus rules  
The protocol can enforce richer rules and require proofs of compliance.

---

# 🚀 Main Features (v0.1)

- **PoUW Mock (CPU-based):** Real nonce search according to difficulty.  
- **ZKP Mock:** Each block includes a deterministic proof simulating a real circuit.  
- **Bitcoin-style dynamic difficulty:** Automatic retarget every 2016 blocks.  
- **Ed25519 signatures:** Incremental nonces, replay prevention, full signature verification.  
- **Real mining:** CPU consumption, nonce search, block application, and rewards.  
- **Fast testnet:** Blocks in seconds, ideal for learning and experimentation.  

---

# 🛠️ System Requirements

- Windows, Linux, or MacOS  
- Modern CPU (Intel/AMD)  
- 4 GB RAM  
- **Rust** (only if compiling from source)  

---

# 📦 Installation

### Option A — Download Binaries (Recommended)
Download from the **Releases** section of the HARUKI-ZENJIRO profile.

### Option B — Compile from Source
```bash
git clone https://github.com/HARUKI-ZENJIRO/aphenos.git
cd aphenos
cargo build --release

## The binaries will be located in: target/release/aphenos-cli and target/release/aphenos-node.

### 🕹️ Usage Guide
## 🔑 1. Generate Keys

# Miner:
aphenos-cli keygen --out-dir .
mv secret.key miner_secret.key
mv public.key miner_public.key


**Alice:**
bash
aphenos-cli keygen --out-dir alice


### 🌱 2. Create Genesis Block (Only once)
bash
aphenos-node

Expected output: Node starting, initial credit for Alice, and chain saved.

### 💸 3. Send a Transaction
Example: Alice sends 100 APS to the miner:
bash
aphenos-cli send --from-sk-path alice/secret.key --to-pk-path miner_public.key --amount 100


### ⛏️ 4. Auto-mine Blocks
bash
aphenos-cli auto-mine --interval-secs 5

Typical output shows block applied and rewards credited.

### 💰 5. Check Balances]
bash
# Miner
aphenos-cli balance --pk-path miner_public.key
# Alice
aphenos-cli balance --pk-path alice/public.key


### 📊 6. Chain Information
bash
aphenos-cli info
```
---

## 📊 Testnet Status
* Stable height and functional mining.
* Validated PoUW and ZKP mock.
* Error-free complete flow.
* Ideal for community testing.

---

## 🗺️ ROADMAP
*(Flexible dates depending on technical challenges)*

**v0.2 — Real PoUW:** Integration of Halo2/Plonk circuits and real ZK proofs.

**v0.3 — Block Explorer:** RPC API, Web Dashboard, and transaction history.

**v0.4 — Graphical Wallet:** Send/Receive APS, Key management and local node integration.

**v1.0 — Mainnet:** Real PoUW/ZKP, Low initial mining difficulty, economic incentives.

---

## Contributing
Pull requests, ideas, and discussions are welcome. This project is in its early stages with a clear vision: turning useful work into blockchain security.
