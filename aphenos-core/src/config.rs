// aphenos-core/src/config.rs

pub const IS_TESTNET: bool = true; // Cambia a false para mainnet

// Dificultad inicial estilo Bitcoin (pero ajustada)
pub const MAINNET_BITS: u32 = 0x1d00ffff / 500;   // dificultad baja pero realista
pub const TESTNET_BITS: u32 = 0x0000ffff;         // dificultad ultra baja