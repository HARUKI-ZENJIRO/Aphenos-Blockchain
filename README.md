# APHENOS TESTNET v0.1

**APHENOS — Proof of Useful Work + ZeroKnowledge Blockchain**

**Public Testnet v0.1** 

APHENOS is an experimental blockchain designed to explore a new consensus paradigm: **Proof of Useful Work (PoUW)** combined with **ZeroKnowledge Proofs (ZKP)**. The network executes a complete flow of:

*Key generation.
*Transaction signing.
*Cryptographic validation.
*Mining with PoUW mock.
*ZKP mock verification.
*Bitcoin-style dynamic difficulty.
*Persistent account state.
*Chained blocks with Merkle Root.

---

## Why APHENOS?

Inspired by the **Aphelion**, which is the point in the orbit of a planet furthest from the Sun, it evokes the idea of reaching the farthest frontiers.

### 1. The Scientific Root
The term **Aphelion** comes from the Greek *apo* (away from) and *helios* (sun). It is the exact point where a planet is at its maximum distance from the sun in its orbit. To create **Aphenos**, the following creative liberties were taken:
**The "Aph" base:** Maintains the root of "Aphelion".
**The "-enos" suffix:** Added to give an ending that sounds like substance, entity, or value (similar to Greek terms like *ethos* or *genos*).

### 2. The Concept
In space, the Aphelion represents the point of **greatest expansion** of an orbit. For an innovative network like APHENOS, this translates to:
**Reach:** Reaching where others do not reach.
**Resilience:** The ability to maintain orbit even at the coldest and farthest point.
**Exclusivity:** A unique place in the financial cosmos.

---

## Version
This version corresponds to **TESTNET v0.1**, focused on testing, demonstrations, and community experimentation.

## 🚀 Main Features

**PoUW Mock (CPU-based):** The miner performs real work on the CPU to find a valid nonce according to the difficulty.
**ZKP Mock:** Each block includes a deterministic ZK proof that simulates the structure of a real circuit.
**Bitcoin-style dynamic difficulty:** Low initial difficulty (testnet) with automatic adjustment via `[next_bits()]` and retarget every 2016 blocks.
**Transactions signed with Ed25519:** Includes incremental nonces, replay prevention, and full signature verification.
**Real Mining:** CPU consumption, nonce search, mock ZKP testing, block application, and miner rewards.
**Fast Testnet:** Blocks in seconds, ideal for testing and learning.

---

## 🛠️ System Requirements
* Windows, Linux, or MacOS.
* Modern CPU (Intel/AMD).
* 4 GB RAM.
**Rust** (only if compiling from source).

---

## 📦 Installation

### Option A — Download Binaries (Recommended) 
Download the corresponding version from the releases section in the **HARUKI-ZENJIRO** profile.

### Option B — Compile from Source 
bash
git clone [https://github.com/HARUKI-ZENJIRO/aphenos.git](https://github.com/HARUKI-ZENJIRO/aphenos.git)
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
