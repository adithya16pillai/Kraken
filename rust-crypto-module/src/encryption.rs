use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

const NONCE_SIZE: usize = 12; // 96 bits for AES-GCM

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Failed to encrypt data: {0}")]
    EncryptionFailed(String),
    
    #[error("Failed to decrypt data: {0}")]
    DecryptionFailed(String),
    
    #[error("Invalid key length")]
    InvalidKeyLength,
    
    #[error("Invalid data format")]
    InvalidDataFormat,
}

/// Generate a secure random key for AES-256-GCM
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt data using AES-256-GCM
///
/// Returns a vector where the first 12 bytes are the nonce and the rest is the encrypted data
pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| EncryptionError::InvalidKeyLength)?;
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt data
    let encrypted = cipher.encrypt(nonce, data)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
    
    // Combine nonce and encrypted data
    let mut result = Vec::with_capacity(NONCE_SIZE + encrypted.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&encrypted);
    
    Ok(result)
}

/// Decrypt data using AES-256-GCM
///
/// Expects input where the first 12 bytes are the nonce and the rest is the encrypted data
pub fn decrypt_data(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, EncryptionError> {
    // Ensure data is long enough to contain nonce + ciphertext
    if encrypted_data.len() <= NONCE_SIZE {
        return Err(EncryptionError::InvalidDataFormat);
    }
    
    // Split data into nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;
    
    // Decrypt data
    let decrypted = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;
    
    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption_decryption_roundtrip() {
        let data = b"This is a test message for encryption!";
        let key = generate_key();
        
        let encrypted = encrypt_data(data, &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }
    
    #[test]
    fn test_invalid_key_fails() {
        let data = b"This is a test message for encryption!";
        let key = generate_key();
        let wrong_key = generate_key();
        
        let encrypted = encrypt_data(data, &key).unwrap();
        let result = decrypt_data(&encrypted, &wrong_key);
        
        assert!(result.is_err());
    }
}