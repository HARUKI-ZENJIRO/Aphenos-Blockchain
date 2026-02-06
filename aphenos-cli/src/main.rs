use std::fs;
use std::path::PathBuf;
use hex;

use clap::{Parser, Subcommand};
use ed25519_dalek::{Keypair, Signer, SecretKey, PublicKey, Signature};
use rand::rngs::OsRng;
use serde_json;

use aphenos_core::{
    TxPayload,
    TransactionSigned,
    Chain,
    Block,
    BlockHeader,
    WorkProofZkp,
    merkle_root,
};

#[derive(Parser)]
#[command(name = "aphenos-cli")]
#[command(about = "CLI para generar claves, firmar transacciones, enviar, consultar y minar en aphenos")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generar un par de claves (privada y pública)
    Keygen { #[arg(long)] out_dir: PathBuf },

    /// Firmar una transacción (genera archivo JSON)
    TxSign {
        #[arg(long)] from_sk_path: PathBuf,
        #[arg(long)] to_pk_path: PathBuf,
        #[arg(long)] amount: u64,
        #[arg(long)] nonce: u64,
        #[arg(long)] out: PathBuf,
    },

    /// Enviar una transacción directamente al inbox (nonce automático)
    Send {
        #[arg(long)] from_sk_path: PathBuf,
        #[arg(long)] to_pk_path: PathBuf,
        #[arg(long)] amount: u64,
    },

    /// Consultar saldo de una dirección
    Balance { #[arg(long)] pk_path: PathBuf },

    /// Consultar historial de transacciones de una dirección
    History { #[arg(long)] pk_path: PathBuf },

    /// Consultar altura actual de la cadena
    Height,

    /// Consultar el hash del último bloque (tip)
    Tip,

    /// Mostrar resumen completo de la cadena
    Info,

    /// Minar un bloque con las transacciones del inbox
    Mine,

    /// Minar automáticamente bloques cada cierto intervalo (como Bitcoin)
    AutoMine {
        #[arg(long)]
        interval_secs: u64,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out_dir } => {
            fs::create_dir_all(&out_dir).expect("no se pudo crear directorio");
            let kp = Keypair::generate(&mut OsRng);
            fs::write(out_dir.join("secret.key"), kp.secret.to_bytes()).expect("no se pudo escribir secret.key");
            fs::write(out_dir.join("public.key"), kp.public.to_bytes()).expect("no se pudo escribir public.key");
            println!("Claves generadas en {:?}", out_dir);
        }

        Commands::TxSign { from_sk_path, to_pk_path, amount, nonce, out } => {
            let sk_bytes = fs::read(&from_sk_path).expect("no se pudo leer secret.key");
            let pk_bytes = fs::read(&to_pk_path).expect("no se pudo leer public.key");
            let sk_array: [u8; 32] = sk_bytes.try_into().expect("secret.key inválido");
            let to_pk_array: [u8; 32] = pk_bytes.try_into().expect("public.key inválido");

            let secret = SecretKey::from_bytes(&sk_array).expect("clave secreta inválida");
            let derived_public = PublicKey::from(&secret);
            let kp = Keypair { secret, public: derived_public };

            let payload = TxPayload { from_pubkey: kp.public.to_bytes(), to_pubkey: to_pk_array, amount, nonce };
            let msg = payload.hash();
            let sig = kp.sign(&msg[..]).to_bytes().to_vec();

            let tx = TransactionSigned { payload, signature: sig };
            let json = serde_json::to_string_pretty(&tx).expect("no se pudo serializar transacción");
            fs::write(&out, json).expect("no se pudo escribir archivo de salida");
            println!("Transacción firmada guardada en {:?}", out);
        }

        Commands::Send { from_sk_path, to_pk_path, amount } => {
            let sk_bytes = fs::read(&from_sk_path).expect("no se pudo leer secret.key");
            let pk_bytes = fs::read(&to_pk_path).expect("no se pudo leer public.key");
            let sk_array: [u8; 32] = sk_bytes.try_into().expect("secret.key inválido");
            let to_pk_array: [u8; 32] = pk_bytes.try_into().expect("public.key inválido");

            let secret = SecretKey::from_bytes(&sk_array).expect("clave secreta inválida");
            let derived_public = PublicKey::from(&secret);
            let kp = Keypair { secret, public: derived_public };

            let chain_data = fs::read_to_string("chain.json").expect("no se pudo leer chain.json");
            let chain: Chain = serde_json::from_str(&chain_data).expect("chain.json inválido");

            let from_pk = kp.public.to_bytes();
            let from_key_hex = key_hex(&from_pk);
            let current_nonce = chain.accounts.nonces.get(&from_key_hex).copied().unwrap_or(0);
            let nonce = current_nonce + 1;

            let payload = TxPayload { from_pubkey: from_pk, to_pubkey: to_pk_array, amount, nonce };
            let msg = payload.hash();
            let sig = kp.sign(&msg[..]).to_bytes().to_vec();
            let tx = TransactionSigned { payload, signature: sig };

            let inbox_dir = PathBuf::from("inbox");
            fs::create_dir_all(&inbox_dir).expect("no se pudo crear inbox");
            let filename = format!("tx_{}_{}.json", now(), nonce);
            let out_path = inbox_dir.join(filename);

            let json = serde_json::to_string_pretty(&tx).expect("no se pudo serializar transacción");
            fs::write(&out_path, json).expect("no se pudo escribir archivo en inbox");

            println!("📨 Transacción enviada al inbox: {:?}", out_path);
            println!("➡️  from nonce = {}, amount = {}", nonce, amount);
        }

        Commands::Balance { pk_path } => {
            let pk_bytes = fs::read(&pk_path).expect("no se pudo leer public.key");
            let pk_array: [u8; 32] = pk_bytes.try_into().expect("public.key inválido");
            let chain_data = fs::read_to_string("chain.json").expect("no se pudo leer chain.json");
            let chain: Chain = serde_json::from_str(&chain_data).expect("chain.json inválido");
            let balance = chain.accounts.get_balance(&pk_array);
            println!("Saldo de {:?}: {} APS", pk_array, balance);
        }

        Commands::History { pk_path } => {
            // Leer clave pública desde archivo
            let pk_bytes = fs::read(&pk_path).expect("no se pudo leer public.key");
            let pk_array: [u8; 32] = pk_bytes.try_into().expect("public.key inválido");

            // Leer cadena
            let chain_data = fs::read_to_string("chain.json").expect("no se pudo leer chain.json");
            let chain: Chain = serde_json::from_str(&chain_data).expect("chain.json inválido");

            println!("📜 Historial de transacciones para la dirección {}:", hex::encode(pk_array));

            let mut found = false;
            for block in &chain.blocks {
                for tx in &block.txs {
                    if tx.payload.from_pubkey == pk_array {
                        println!(
                            "⬅️ Bloque {} | Nonce {} | Enviados {} APS a {}",
                            block.header.height,
                            tx.payload.nonce,
                            tx.payload.amount,
                            hex::encode(tx.payload.to_pubkey)
                        );
                        found = true;
                    } else if tx.payload.to_pubkey == pk_array {
                        println!(
                            "➡️ Bloque {} | Recibidos {} APS desde {}",
                            block.header.height,
                            tx.payload.amount,
                            hex::encode(tx.payload.from_pubkey)
                        );
                        found = true;
                    }
                }
            }

            if !found {
                println!("⚠️ No se encontraron transacciones para esta dirección.");
            }
        },

        Commands::Height => {
            let chain_data = fs::read_to_string("chain.json").expect("no se pudo leer chain.json");
            let chain: Chain = serde_json::from_str(&chain_data).expect("chain.json inválido");
            let height = chain.blocks.last().map(|b| b.header.height).unwrap_or(0);
            println!("Altura actual de la cadena: {}", height);
        }

        Commands::Tip => {
            let chain_data = fs::read_to_string("chain.json").expect("no se pudo leer chain.json");
            let chain: Chain = serde_json::from_str(&chain_data).expect("chain.json inválido");
            println!("Hash del último bloque (tip): {:?}", chain.tip);
        }

        Commands::Info => {
            let chain_data = fs::read_to_string("chain.json").expect("no se pudo leer chain.json");
            let chain: Chain = serde_json::from_str(&chain_data).expect("chain.json inválido");
            let height = chain.blocks.last().map(|b| b.header.height).unwrap_or(0);
            println!("📊 Resumen de la cadena aphenos:");
            println!("- Altura actual: {}", height);
            println!("- Hash tip: {:?}", chain.tip);
            println!("- Número de bloques: {}", chain.blocks.len());
            println!("- Balances:");
            for (addr, bal) in &chain.accounts.balances {
                println!("  • {} => {} APS", addr, bal);
            }
        }

        Commands::Mine => {
            let miner_pk_bytes = fs::read("miner_public.key").expect("no se pudo leer miner_public.key");
            let miner_pubkey: [u8; 32] = miner_pk_bytes.try_into().expect("miner_public.key inválido");
            let block_reward: u64 = 50;

            let chain_data = fs::read_to_string("chain.json").unwrap_or_else(|_| {
                // Si no existe chain.json, inicializamos con un bloque génesis
                serde_json::to_string(&Chain::new_genesis(miner_pubkey, block_reward))
                    .expect("no se pudo crear chain.json inicial")
            });
            let mut chain: Chain = serde_json::from_str(&chain_data).expect("chain.json inválido");

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
                println!("📭 No hay transacciones en inbox. Minando bloque vacío...");
            }

            let height = chain.blocks.last().map(|b| b.header.height + 1).unwrap_or(1);

            let header = BlockHeader {
                parent_hash: chain.tip,
                merkle_root: merkle_root(&txs),
                timestamp: now(),
                height,
                bits: if aphenos_core::config::IS_TESTNET {
                    aphenos_core::config::TESTNET_BITS
                } else {
                    aphenos_core::config::MAINNET_BITS
                },
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

            match chain.add_block(block) {
                Ok(()) => {
                    println!("✅ Bloque aplicado correctamente.");
                    println!("⛏️ Bloque minado. Altura: {}", height);

                    if height == 1 {
                        println!("⚠️ Recompensa del génesis (50 APS) bloqueada para siempre.");
                    } else {
                        println!(
                            "💰 Recompensa de {} APS acreditada al minero.",
                            chain.blocks.last().unwrap().header.block_reward
                        );
                    }

                    let json = serde_json::to_string_pretty(&chain).expect("serialize chain");
                    fs::write("chain.json", json).expect("write chain.json");

                    // Limpiar inbox
                    for entry in fs::read_dir(&inbox_dir).expect("read inbox") {
                        let path = entry.expect("entry").path();
                        if path.extension().map(|e| e == "json").unwrap_or(false) {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Error al aplicar bloque: {}", e);
                }
            }
        }

        Commands::AutoMine { interval_secs } => {
            println!("🚀 Iniciando auto-minado cada {} segundos...", interval_secs);

            loop {
                let miner_pk_bytes = fs::read("miner_public.key").expect("no se pudo leer miner_public.key");
                let miner_pubkey: [u8; 32] = miner_pk_bytes.try_into().expect("miner_public.key inválido");
                let block_reward: u64 = 50;

                let chain_data = fs::read_to_string("chain.json").unwrap_or_else(|_| {
                    serde_json::to_string(&Chain::new_genesis(miner_pubkey, block_reward))
                        .expect("no se pudo crear chain.json inicial")
                });
                let mut chain: Chain = serde_json::from_str(&chain_data).expect("chain.json inválido");

                let inbox_dir = PathBuf::from("inbox");
                fs::create_dir_all(&inbox_dir).expect("no se pudo crear inbox");

                let mut txs: Vec<TransactionSigned> = Vec::new();
                for entry in fs::read_dir(&inbox_dir).expect("no se pudo leer inbox") {
                    let path = entry.expect("entry").path();
                    if path.extension().map(|e| e == "json").unwrap_or(false) {
                        let content = fs::read_to_string(&path).expect("no se pudo leer tx json");
                        if let Ok(tx) = serde_json::from_str::<TransactionSigned>(&content) {
                            txs.push(tx);
                        }
                    }
                }

                let height = chain.blocks.last().map(|b| b.header.height + 1).unwrap_or(1);
                
                let bits = aphenos_core::next_bits(&chain);
                
                // === PoUW MOCK: buscar nonce válido según dificultad ===
                let mut nonce = 0u64;

                loop {
                let mut data = Vec::new();
                    data.extend_from_slice(&miner_pubkey);
                    data.extend_from_slice(&nonce.to_le_bytes());

                    let h = blake3::hash(&data).as_bytes().clone();

                    // Dificultad mock: bits controla cuántos ceros iniciales se requieren
                    let required_zeros = (bits / 1_000_000).max(1);

                    let mut count = 0;
                    for byte in h {
                        if byte == 0 {
                            count += 1;
                        } else {
                            break;
                        }
                    }

                    if count >= required_zeros {
                        break;
                    }

                    nonce = nonce.wrapping_add(1);
                }

                // Obtener parámetros del circuito según la dificultad
                let params = aphenos_core::pouw_circuit_params(bits, miner_pubkey);

                // Generar prueba ZKP real (placeholder)
                let proof_bytes = aphenos_core::pouw_prove(&params, nonce);

                // Construir el WorkProofZkp válido
                let work_proof = aphenos_core::WorkProofZkp {
                    circuit_id: params.public_inputs[..32].try_into().unwrap_or([0u8; 32]),
                    params_hash: blake3::hash(&params.complexity.to_le_bytes()).as_bytes().clone(),
                    witness_commit: blake3::hash(&miner_pubkey).as_bytes().clone(),
                    proof_bytes,
                    nonce,
                };

                let header = BlockHeader {
                    parent_hash: chain.tip,
                    merkle_root: merkle_root(&txs),
                    timestamp: now(),
                    height,
                    bits,

                    // PoUW ZKP temporal (mock) hasta que activemos el real
                    work_proof,

                    miner_pubkey,
                    block_reward,
                };


                let block = Block { header, txs };

                match chain.add_block(block) {
                    Ok(()) => {
                        println!("✅ Bloque aplicado. Altura: {}", height);
                        if height == 1 {
                            println!("⚠️ Recompensa del génesis (50 APS) bloqueada para siempre.");
                        } else {
                            println!("💰 Recompensa de {} APS acreditada al minero.", block_reward);
                        }

                        let json = serde_json::to_string_pretty(&chain).expect("serialize chain");
                        fs::write("chain.json", json).expect("write chain.json");

                        // Limpiar inbox SOLO si el bloque se aplicó bien
                        for entry in fs::read_dir(&inbox_dir).expect("read inbox") {
                            let path = entry.expect("entry").path();
                            if path.extension().map(|e| e == "json").unwrap_or(false) {
                                let _ = fs::remove_file(&path);
                            }
                        }
                    }
                    Err(e) => {
                        println!("❌ Error al aplicar bloque: {}", e);
                        // No borramos el inbox, para que las transacciones se reintenten en el próximo ciclo
                    }
                }

                std::thread::sleep(std::time::Duration::from_secs(interval_secs));
            }
        }
    }
}

// Función auxiliar para obtener timestamp actual en segundos
fn now() -> u64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()) as u64
}

// Helper para convertir [u8;32] a hex (coincide con aphenos-core)
fn key_hex(addr: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in addr {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
