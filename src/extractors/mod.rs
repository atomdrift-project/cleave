//! Extractors for encoded payloads (base64, zlib, AES, etc.)
//!
//! This module extracts encoded payloads from files, decodes them,
//! and writes them to temp files for separate analysis.

pub(crate) mod aes_payload;
pub(crate) mod batch_self_hex;
pub mod encoded_payload;
pub(crate) mod fragment_gcm_pe;
pub(crate) mod hex_rc4_nextbyte;
pub(crate) mod macho_chacha;
pub(crate) mod macho_integer_tables;
pub(crate) mod metamorphic_graft;
pub(crate) mod mpress;
pub(crate) mod node_sea;
pub(crate) mod nrv32;
pub(crate) mod powershell_literals;
pub(crate) mod powershell_payloads;
pub(crate) mod ps_to_exe;
pub(crate) mod pyarmor;
pub(crate) mod rc4_pe_table;
pub(crate) mod skc3_pe;

pub(crate) use aes_payload::extract_aes_payloads;
pub(crate) use encoded_payload::extract_encoded_payloads;
