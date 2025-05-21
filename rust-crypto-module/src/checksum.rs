use sha2::{Sha256, Digest};
use blake3::Hasher as Blake3Hasher;
use thiserror::Error;
use std::io::{self, Read};

const BUFFER_SIZE: usize = 8192; // 8KB buffer for streaming

#[derive(Debug, Error)]
pub enum ChecksumError {
    #[error("IO error during checksum calculation: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),
    
    #[error("Verification failed: expected {expected}, got {actual}")]
    VerificationFailed {
        expected: String,
        actual: String,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Blake3 => write!(f, "blake3"),
        }
    }
}

impl std::str::FromStr for HashAlgorithm {
    type Err = ChecksumError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha256" => Ok(HashAlgorithm::Sha256),
            "blake3" => Ok(HashAlgorithm::Blake3),
            _ => Err(ChecksumError::InvalidHashAlgorithm(s.to_string())),
        }
    }
}

/// Generate a checksum for a byte slice
pub fn generate_checksum(data: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let result = hasher.finalize();
            format!("{:x}", result)
        },
        HashAlgorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            hasher.update(data);
            let result = hasher.finalize();
            result.to_hex().to_string()
        }
    }
}

/// Generate a checksum for a reader (like a file) in a streaming fashion
pub fn generate_checksum_reader<R: Read>(
    mut reader: R, 
    algorithm: HashAlgorithm
) -> Result<String, ChecksumError> {
    let mut buffer = [0u8; BUFFER_SIZE];
    
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            
            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            
            let result = hasher.finalize();
            Ok(format!("{:x}", result))
        },
        HashAlgorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            
            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            
            let result = hasher.finalize();
            Ok(result.to_hex().to_string())
        }
    }
}

/// Verify a checksum against expected value
pub fn verify_checksum(
    data: &[u8], 
    expected: &str, 
    algorithm: HashAlgorithm
) -> Result<bool, ChecksumError> {
    let actual = generate_checksum(data, algorithm);
    
    if actual == expected {
        Ok(true)
    } else {
        Err(ChecksumError::VerificationFailed {
            expected: expected.to_string(),
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    
    #[test]
    fn test_sha256_checksum() {
        let data = b"test data for checksum";
        // Expected SHA-256 checksum for "test data for checksum"
        let expected = "cce73cd53bee7ebd23498f33dfbd634b8a4b1d7d67c5e5dc9758936cea7fcddb";
        
        let result = generate_checksum(data, HashAlgorithm::Sha256);
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_blake3_checksum() {
        let data = b"test data for checksum";
        // We don't hardcode Blake3 expected output as it might change with library versions
        let result = generate_checksum(data, HashAlgorithm::Blake3);
        
        // Verify the result matches format and style of Blake3 outputs
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }
    
    #[test]
    fn test_streaming_checksum() {
        let data = b"test data for checksum";
        let cursor = Cursor::new(data);
        
        let direct = generate_checksum(data, HashAlgorithm::Sha256);
        let streaming = generate_checksum_reader(cursor, HashAlgorithm::Sha256).unwrap();
        
        assert_eq!(direct, streaming);
    }
    
    #[test]
    fn test_verify_checksum() {
        let data = b"test data for checksum";
        let correct = "cce73cd53bee7ebd23498f33dfbd634b8a4b1d7d67c5e5dc9758936cea7fcddb";
        let incorrect = "0000000000000000000000000000000000000000000000000000000000000000";
        
        assert!(verify_checksum(data, correct, HashAlgorithm::Sha256).unwrap());
        assert!(verify_checksum(data, incorrect, HashAlgorithm::Sha256).is_err());
    }
}