use serde::{Serialize, Deserialize};
use blake3;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PoUWError {
    #[error("invalid work proof")]
    InvalidWorkProof,
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

impl WorkProof {
    /// Verifica que la prueba sea válida
    pub fn verify(&self, parent_hash: [u8; 32], merkle_root: [u8; 32]) -> Result<(), PoUWError> {
        // Reglas simples de validación
        if self.proof.is_empty() || self.score == 0 {
            return Err(PoUWError::InvalidWorkProof);
        }

        // Validación básica: task_id debe depender de parent_hash y merkle_root
        let mut buf = Vec::new();
        buf.extend_from_slice(&parent_hash);
        buf.extend_from_slice(&merkle_root);

        let expected = blake3::hash(&buf).as_bytes().clone();
        if self.task_id != expected {
            return Err(PoUWError::InvalidWorkProof);
        }

        Ok(())
    }

    /// Construye una prueba dummy para pruebas
    pub fn dummy(module: PoUWModule, parent_hash: [u8; 32], merkle_root: [u8; 32]) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(&parent_hash);
        buf.extend_from_slice(&merkle_root);

        let task_id = blake3::hash(&buf).as_bytes().clone();

        WorkProof {
            module,
            task_id,
            proof: b"dummy-proof".to_vec(),
            score: 42,
        }
    }
}
