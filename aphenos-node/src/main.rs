use std::fs;
use std::path::PathBuf;

use aphenos_core::{
    Chain,
    Block,
    BlockHeader,
    TransactionSigned,
    WorkProofZkp,
    merkle_root,
};
use serde_json;

fn main() {
    println!("⛏️ Iniciando nodo aphenos...");

    // Configuración del minero
    let miner_pk_path = PathBuf::from("miner_public.key");
    let block_reward: u64 = 50;

    // Cargar clave pública del minero (o crear archivo con 32 bytes cero)
    let miner_pubkey: [u8; 32] = if miner_pk_path.exists() {
        let bytes = fs::read(&miner_pk_path).expect("no se pudo leer miner_public.key");
        bytes.try_into().expect("miner_public.key inválido")
    } else {
        let zeros = [0u8; 32];
        fs::write(&miner_pk_path, &zeros).expect("no se pudo escribir miner_public.key");
        zeros
    };

    // Cargar o crear cadena
    let chain_path = PathBuf::from("chain.json");
    let mut chain: Chain = if chain_path.exists() {
        let data = fs::read_to_string(&chain_path).expect("no se pudo leer chain.json");
        serde_json::from_str(&data).expect("chain.json inválido")
    } else {
        Chain::new_genesis(miner_pubkey, block_reward)
    };

    // Crédito inicial para Alice (si existe su public.key)
    if let Ok(alice_pk_bytes) = fs::read("alice/public.key") {
        if alice_pk_bytes.len() == 32 {
            let alice_pk: [u8; 32] = alice_pk_bytes.try_into().expect("alice public.key inválido");
            if chain.accounts.get_balance(&alice_pk) == 0 {
                chain.accounts.credit(alice_pk, 1000);
                println!("💰 Crédito inicial: Alice = +1000 APS");
            }
        }
    }

    // Leer transacciones del inbox
    let inbox_dir = PathBuf::from("inbox");
    fs::create_dir_all(&inbox_dir).expect("no se pudo crear inbox");

    let mut txs: Vec<TransactionSigned> = Vec::new();
    for entry in fs::read_dir(&inbox_dir).expect("no se pudo leer inbox") {
        let path = entry.expect("entry").path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            let content = fs::read_to_string(&path).expect("no se pudo leer tx json");
            match serde_json::from_str::<TransactionSigned>(&content) {
                Ok(tx) => txs.push(tx),
                Err(_) => println!("⚠️ Archivo inválido en inbox: {:?}", path),
            }
        }
    }

    if txs.is_empty() {
        println!("📭 No hay transacciones en inbox. Nada que minar.");
        let json = serde_json::to_string_pretty(&chain).expect("serialize chain");
        fs::write(&chain_path, json).expect("write chain.json");
        return;
    }

    // Construir header del bloque
    let header = BlockHeader {
        parent_hash: chain.tip,
        merkle_root: merkle_root(&txs),
        timestamp: now(),
        height: chain.blocks.last().map(|b| b.header.height + 1).unwrap_or(1),
        bits: if aphenos_core::config::IS_TESTNET {
            aphenos_core::config::TESTNET_BITS
        } else {
            aphenos_core::config::MAINNET_BITS
        }, // dificultad estilo Bitcoin

        work_proof: WorkProofZkp {
            circuit_id: [0u8; 32],
            params_hash: [0u8; 32],
            witness_commit: [0u8; 32],
            proof_bytes: b"pouw-proof".to_vec(),
            nonce: 0,
        },

        miner_pubkey,
        block_reward,
    };

    let block = Block { header, txs };

    // Intentar aplicar bloque
    match chain.add_block(block) {
        Ok(()) => {
            println!("✅ Bloque aplicado correctamente.");
            println!("⛏️ Bloque minado. Altura: {}", chain.blocks.last().unwrap().header.height);
            let json = serde_json::to_string_pretty(&chain).expect("serialize chain");
            fs::write(&chain_path, json).expect("write chain.json");

            // Limpiar inbox
            for entry in fs::read_dir(&inbox_dir).expect("read inbox") {
                let path = entry.expect("entry").path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    let _ = fs::remove_file(&path);
                }
            }

            println!("📦 Cadena guardada en chain.json");
        }
        Err(e) => {
            println!("❌ Error al aplicar bloque: {}", e);
            let json = serde_json::to_string_pretty(&chain).expect("serialize chain");
            fs::write(&chain_path, json).expect("write chain.json");
            println!("📦 Cadena guardada en chain.json");
        }
    }
}

fn now() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()) as u64
}