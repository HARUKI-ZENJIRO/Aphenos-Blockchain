pub mod config;

use serde::{Deserialize, Serialize};
use blake3;
use thiserror::Error;
use ed25519_dalek::{Signature, PublicKey, Verifier};
use std::collections::HashMap;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid block")]
    InvalidBlock,
    #[error("invalid transaction")]
    InvalidTransaction,
    #[error("signature verification failed")]
    BadSignature,
    #[error("invalid work proof")]
    InvalidWorkProof,
    #[error("insufficient funds")]
    InsufficientFunds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPayload {
    pub from_pubkey: [u8; 32],
    pub to_pubkey: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
}

impl TxPayload {
    pub fn hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).expect("serialize payload");
        blake3::hash(&bytes).as_bytes().clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSigned {
    pub payload: TxPayload,
    pub signature: Vec<u8>,
}

impl TransactionSigned {
    pub fn hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).expect("serialize tx");
        blake3::hash(&bytes).as_bytes().clone()
    }

    pub fn verify(&self) -> Result<(), CoreError> {
        let vk = PublicKey::from_bytes(&self.payload.from_pubkey)
            .map_err(|_| CoreError::InvalidTransaction)?;

        let sig_bytes: [u8; 64] = self.signature
            .clone()
            .try_into()
            .map_err(|_| CoreError::InvalidTransaction)?;

        let sig = Signature::from_bytes(&sig_bytes)
            .map_err(|_| CoreError::InvalidTransaction)?;

        let msg = self.payload.hash();

        vk.verify(&msg[..], &sig).map_err(|_| CoreError::BadSignature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoUWModule {
    CpuLogic,
    GpuVision,
    DataCompression,
    RLFeedback,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkProof {
    pub module: PoUWModule,
    pub task_id: [u8; 32],
    pub proof: Vec<u8>,
    pub score: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkProofZkp {
    pub circuit_id: [u8; 32],     // Identificador del circuito
    pub params_hash: [u8; 32],    // Hash de los parámetros del circuito
    pub witness_commit: [u8; 32], // Compromiso del witness
    pub proof_bytes: Vec<u8>,     // Prueba ZK generada por el minero
    pub nonce: u64,               // Sal para evitar precomputación
}

impl WorkProof {
    pub fn verify(&self, _parent_hash: [u8; 32], _merkle_root: [u8; 32]) -> Result<(), CoreError> {
        if self.proof.is_empty() || self.score == 0 {
            return Err(CoreError::InvalidWorkProof);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub height: u64,

    // Dificultad estilo Bitcoin (compact target)
    pub bits: u32,

    // Prueba de trabajo útil basada en ZKP
    pub work_proof: WorkProofZkp,

    pub miner_pubkey: [u8; 32],
    pub block_reward: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<TransactionSigned>,
}

/// Helpers de clave para serialización JSON
fn key_hex(addr: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in addr {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountsState {
    pub balances: HashMap<String, u128>,
    pub nonces: HashMap<String, u64>,
}

impl AccountsState {
    pub fn get_balance(&self, addr: &[u8; 32]) -> u128 {
        *self.balances.get(&key_hex(addr)).unwrap_or(&0u128)
    }
    pub fn credit(&mut self, addr: [u8; 32], amount: u64) {
        let k = key_hex(&addr);
        let entry = self.balances.entry(k).or_insert(0u128);
        *entry = entry.saturating_add(amount as u128);
    }
    pub fn debit(&mut self, addr: [u8; 32], amount: u64) -> Result<(), CoreError> {
        let k = key_hex(&addr);
        let entry = self.balances.entry(k).or_insert(0u128);
        let amt = amount as u128;
        if *entry < amt {
            return Err(CoreError::InsufficientFunds);
        }
        *entry -= amt;
        Ok(())
    }
    pub fn next_nonce_ok(&mut self, addr: [u8; 32], nonce: u64) -> bool {
        let k = key_hex(&addr);
        let expected = self.nonces.get(&k).copied().unwrap_or(0u64) + 1;
        if nonce == expected {
            self.nonces.insert(k, nonce);
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub blocks: Vec<Block>,
    pub tip: [u8; 32],
    pub accounts: AccountsState,
}

impl Chain {
    pub fn new_genesis(miner_pubkey: [u8; 32], block_reward: u64) -> Self {
        let genesis_txs = vec![];
        let merkle = merkle_root(&genesis_txs);

        // Prueba ZKP ficticia para génesis (no afecta nada)
        let wp = WorkProofZkp {
            circuit_id: blake3::hash(b"genesis-circuit").as_bytes().clone(),
            params_hash: blake3::hash(b"genesis-params").as_bytes().clone(),
            witness_commit: blake3::hash(b"genesis-witness").as_bytes().clone(),
            proof_bytes: b"genesis-proof".to_vec(),
            nonce: 0,
        };

        let header = BlockHeader {
            parent_hash: [0u8; 32],
            merkle_root: merkle,
            timestamp: now(),
            height: 0,

            // dificultad inicial estilo Bitcoin
            bits: if crate::config::IS_TESTNET {
                crate::config::TESTNET_BITS
            } else {
                crate::config::MAINNET_BITS
            },

            work_proof: wp,
            miner_pubkey,
            block_reward,
        };

        let genesis = Block { header, txs: genesis_txs };
        let tip = block_hash(&genesis);

        let mut accounts = AccountsState::default();
        accounts.credit(miner_pubkey, block_reward);

        Self { blocks: vec![genesis], tip, accounts }
    }
}

impl Chain {
    pub fn add_block(&mut self, block: Block) -> Result<(), CoreError> {
        let parent_ok = block.header.parent_hash == self.tip;
        let merkle_ok = block.header.merkle_root == merkle_root(&block.txs);
        if !parent_ok || !merkle_ok {
            return Err(CoreError::InvalidBlock);
        }

        // Verificar PoUW mock (nonce válido según dificultad)
        if !verify_pouw(&block.header) {
            return Err(CoreError::InvalidWorkProof);
        }

        let params = pouw_circuit_params(block.header.bits, block.header.miner_pubkey);
        if !pouw_verify(&params, &block.header.work_proof.proof_bytes, block.header.work_proof.nonce) {
            return Err(CoreError::InvalidWorkProof);
        }

        // 1️⃣ Acreditar recompensa al minero ANTES de validar transacciones
        if block.header.height > 1 {
            self.accounts.credit(block.header.miner_pubkey, block.header.block_reward);
            println!("💰 Recompensa de {} APS acreditada al minero {:?}.",
                     block.header.block_reward, block.header.miner_pubkey);
        }

        // 2️⃣ Validar y aplicar transacciones
        for tx in &block.txs {
            tx.verify()?;
            if !self.accounts.next_nonce_ok(tx.payload.from_pubkey, tx.payload.nonce) {
                return Err(CoreError::InvalidTransaction);
            }

            // 🔎 Depuración: imprimir claves de la transacción
            println!("➡️ TX aplicada: from={:?} → to={:?}, monto={}",
                     tx.payload.from_pubkey, tx.payload.to_pubkey, tx.payload.amount);

            self.accounts.debit(tx.payload.from_pubkey, tx.payload.amount)?;
            self.accounts.credit(tx.payload.to_pubkey, tx.payload.amount);
        }

        // 3️⃣ Actualizar tip y añadir bloque
        self.tip = block_hash(&block);
        self.blocks.push(block);
        Ok(())
    }
}

// ===============================
//  Dificultad estilo Bitcoin
// ===============================

const BLOCKS_PER_RETARGET: u64 = 2016;
const TARGET_BLOCK_TIME_SECS: u64 = 600; // 10 minutos
const RETARGET_WINDOW_SECS: u64 = BLOCKS_PER_RETARGET * TARGET_BLOCK_TIME_SECS;

fn clamp_timespan(timespan: u64) -> u64 {
    let min = RETARGET_WINDOW_SECS / 4;
    let max = RETARGET_WINDOW_SECS * 4;
    timespan.clamp(min, max)
}

pub fn next_bits(chain: &Chain) -> u32 {
    // Si no hay bloques, usar dificultad inicial según config
    if chain.blocks.is_empty() {
        return if crate::config::IS_TESTNET {
            crate::config::TESTNET_BITS
        } else {
            crate::config::MAINNET_BITS
        };
    }

    let last_height = chain.blocks.last().unwrap().header.height;

    if last_height % BLOCKS_PER_RETARGET != 0 {
        return chain.blocks.last().unwrap().header.bits;
    }

    if last_height < BLOCKS_PER_RETARGET {
        return chain.blocks.last().unwrap().header.bits;
    }

    let start_index = (last_height - BLOCKS_PER_RETARGET) as usize;
    let end_index = (last_height - 1) as usize;

    let start_block = &chain.blocks[start_index];
    let end_block = &chain.blocks[end_index];

    let actual_timespan = end_block.header.timestamp.saturating_sub(start_block.header.timestamp);
    let adjusted_timespan = clamp_timespan(actual_timespan);

    let prev_bits = end_block.header.bits as u64;

    let new_bits_f = (prev_bits as f64)
        * (RETARGET_WINDOW_SECS as f64)
        / (adjusted_timespan as f64);

    let new_bits = new_bits_f.round() as u64;

    let new_bits = new_bits.max(1).min(u32::MAX as u64);

    new_bits as u32
}

pub fn verify_pouw(header: &BlockHeader) -> bool {
    let mut data = Vec::new();
    data.extend_from_slice(&header.miner_pubkey);
    data.extend_from_slice(&header.work_proof.nonce.to_le_bytes());

    let h = blake3::hash(&data).as_bytes().clone();

    // Dificultad mock: bits controla cuántos ceros iniciales se requieren
    let required_zeros = (header.bits / 1_000_000).max(1);

    let mut count = 0;
    for byte in h {
        if byte == 0 {
            count += 1;
        } else {
            break;
        }
    }

    count >= required_zeros
}

// ===============================
//  Interfaz para PoUW-ZKP real
// ===============================

pub struct ZkpCircuitParams {
    pub complexity: u64,     // Complejidad del circuito según bits
    pub public_inputs: Vec<u8>,
}

pub fn pouw_circuit_params(bits: u32, miner_pubkey: [u8; 32]) -> ZkpCircuitParams {
    // Mapeo simple: más bits => circuito más complejo
    let complexity = (bits as u64).max(1);

    ZkpCircuitParams {
        complexity,
        public_inputs: miner_pubkey.to_vec(),
    }
}

// Generar prueba ZKP real (placeholder)
pub fn pouw_prove(params: &ZkpCircuitParams, nonce: u64) -> Vec<u8> {
    // Aquí irá Halo2/Plonk/Groth16 más adelante
    // Por ahora devolvemos un hash determinista
    let mut data = Vec::new();
    data.extend_from_slice(&params.public_inputs);
    data.extend_from_slice(&nonce.to_le_bytes());
    blake3::hash(&data).as_bytes().to_vec()
}

// Verificar prueba ZKP real (placeholder)
pub fn pouw_verify(params: &ZkpCircuitParams, proof: &[u8], nonce: u64) -> bool {
    let expected = pouw_prove(params, nonce);
    expected == proof
}

pub fn block_hash(block: &Block) -> [u8; 32] {
    let bytes = serde_json::to_vec(block).expect("serialize block");
    blake3::hash(&bytes).as_bytes().clone()
}

pub fn merkle_root(txs: &Vec<TransactionSigned>) -> [u8; 32] {
    if txs.is_empty() {
        return blake3::hash(b"empty").as_bytes().clone();
    }
    let mut hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.hash()).collect();
    while hashes.len() > 1 {
        let mut next = Vec::new();
        for i in (0..hashes.len()).step_by(2) {
            let left = hashes[i];
            let right = if i + 1 < hashes.len() { hashes[i + 1] } else { left };
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(&left);
            bytes.extend_from_slice(&right);
            next.push(blake3::hash(&bytes).as_bytes().clone());
        }
        hashes = next;
    }
    hashes[0]
}

fn now() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()) as u64
}
