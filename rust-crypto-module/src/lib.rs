mod encryption;
mod checksum;
mod ffi;

pub use encryption::{encrypt_data, decrypt_data, generate_key};
pub use checksum::{generate_checksum, verify_checksum};

// Publicly re-export error types
pub use encryption::EncryptionError;
pub use checksum::ChecksumError;