use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_uint};
use std::slice;
use std::ptr;

use crate::encryption::{encrypt_data, decrypt_data, generate_key};
use crate::checksum::{generate_checksum, HashAlgorithm};

// Error codes for FFI
const SUCCESS: c_int = 0;
const ERR_ENCRYPTION: c_int = -1;
const ERR_DECRYPTION: c_int = -2;
const ERR_INVALID_KEY: c_int = -3;
const ERR_INVALID_DATA: c_int = -4;
const ERR_INVALID_ALGORITHM: c_int = -5;
const ERR_NULL_POINTER: c_int = -6;
const ERR_STRING_CONVERSION: c_int = -7;

/// Generate a new encryption key
///
/// # Safety
///
/// The caller must ensure that the output buffer is at least 32 bytes long.
#[no_mangle]
pub unsafe extern "C" fn generate_encryption_key(out_key: *mut c_uchar) -> c_int {
    if out_key.is_null() {
        return ERR_NULL_POINTER;
    }
    
    let key = generate_key();
    let out_key_slice = slice::from_raw_parts_mut(out_key, 32);
    out_key_slice.copy_from_slice(&key);
    
    SUCCESS
}

/// Encrypt data with AES-256-GCM
///
/// # Safety
///
/// The caller must ensure that:
/// - `data` points to a valid buffer of length `data_len`
/// - `key` points to a valid buffer of length 32 bytes (AES-256 key)
/// - `out_data` is either null (for output size request) or points to a buffer of at least 
///   `*out_len` bytes
/// - `out_len` is not null and points to a valid c_uint
///
/// # Return value
///
/// - On success, returns SUCCESS (0)
/// - On error, returns a negative error code
///
/// When `out_data` is null, this function sets `*out_len` to the required output buffer size
/// and returns SUCCESS without writing any data.
#[no_mangle]
pub unsafe extern "C" fn encrypt_buffer(
    data: *const c_uchar,
    data_len: c_uint,
    key: *const c_uchar,
    out_data: *mut c_uchar,
    out_len: *mut c_uint,
) -> c_int {
    // Validate inputs
    if data.is_null() || key.is_null() || out_len.is_null() {
        return ERR_NULL_POINTER;
    }
    
    let data_slice = slice::from_raw_parts(data, data_len as usize);
    let key_slice = slice::from_raw_parts(key, 32);
    
    // Convert key from slice to fixed-size array
    let mut key_array = [0u8; 32];
    if key_slice.len() != key_array.len() {
        return ERR_INVALID_KEY;
    }
    key_array.copy_from_slice(key_slice);
    
    // Encrypt the data
    let encrypted = match encrypt_data(data_slice, &key_array) {
        Ok(enc) => enc,
        Err(_) => return ERR_ENCRYPTION,
    };
    
    // Check if we're just requesting the output size
    let required_len = encrypted.len() as c_uint;
    if out_data.is_null() {
        *out_len = required_len;
        return SUCCESS;
    }
    
    // Check if the output buffer is large enough
    if *out_len < required_len {
        *out_len = required_len;
        return ERR_INVALID_DATA;
    }
    
    // Copy the encrypted data to the output buffer
    let out_slice = slice::from_raw_parts_mut(out_data, required_len as usize);
    out_slice.copy_from_slice(&encrypted);
    *out_len = required_len;
    
    SUCCESS
}

/// Decrypt data with AES-256-GCM
///
/// # Safety
///
/// The caller must ensure that:
/// - `encrypted_data` points to a valid buffer of length `encrypted_len`
/// - `key` points to a valid buffer of length 32 bytes (AES-256 key)
/// - `out_data` is either null (for output size request) or points to a buffer of at least 
///   `*out_len` bytes
/// - `out_len` is not null and points to a valid c_uint
///
/// # Return value
///
/// - On success, returns SUCCESS (0)
/// - On error, returns a negative error code
///
/// When `out_data` is null, this function sets `*out_len` to the required output buffer size
/// and returns SUCCESS without writing any data.
#[no_mangle]
pub unsafe extern "C" fn decrypt_buffer(
    encrypted_data: *const c_uchar,
    encrypted_len: c_uint,
    key: *const c_uchar,
    out_data: *mut c_uchar,
    out_len: *mut c_uint,
) -> c_int {
    // Validate inputs
    if encrypted_data.is_null() || key.is_null() || out_len.is_null() {
        return ERR_NULL_POINTER;
    }
    
    let encrypted_slice = slice::from_raw_parts(encrypted_data, encrypted_len as usize);
    let key_slice = slice::from_raw_parts(key, 32);
    
    // Convert key from slice to fixed-size array
    let mut key_array = [0u8; 32];
    if key_slice.len() != key_array.len() {
        return ERR_INVALID_KEY;
    }
    key_array.copy_from_slice(key_slice);
    
    // Decrypt the data
    let decrypted = match decrypt_data(encrypted_slice, &key_array) {
        Ok(dec) => dec,
        Err(_) => return ERR_DECRYPTION,
    };
    
    // Check if we're just requesting the output size
    let required_len = decrypted.len() as c_uint;
    if out_data.is_null() {
        *out_len = required_len;
        return SUCCESS;
    }
    
    // Check if the output buffer is large enough
    if *out_len < required_len {
        *out_len = required_len;
        return ERR_INVALID_DATA;
    }
    
    // Copy the decrypted data to the output buffer
    let out_slice = slice::from_raw_parts_mut(out_data, required_len as usize);
    out_slice.copy_from_slice(&decrypted);
    *out_len = required_len;
    
    SUCCESS
}

/// Generate a checksum for a data buffer
///
/// # Safety
///
/// The caller must ensure that:
/// - `data` points to a valid buffer of length `data_len`
/// - `algorithm` is a null-terminated C string representing a valid hash algorithm
/// - `out_checksum` is a buffer of at least 65 bytes (64 hex chars + null terminator)
///
/// # Return value
///
/// - On success, returns SUCCESS (0)
/// - On error, returns a negative error code
#[no_mangle]
pub unsafe extern "C" fn generate_buffer_checksum(
    data: *const c_uchar,
    data_len: c_uint,
    algorithm: *const c_char,
    out_checksum: *mut c_char,
) -> c_int {
    // Validate inputs
    if data.is_null() || algorithm.is_null() || out_checksum.is_null() {
        return ERR_NULL_POINTER;
    }
    
    // Convert C string to Rust string
    let algorithm_cstr = match CStr::from_ptr(algorithm).to_str() {
        Ok(s) => s,
        Err(_) => return ERR_STRING_CONVERSION,
    };
    
    // Parse hash algorithm
    let hash_algorithm = match algorithm_cstr {
        "sha256" => HashAlgorithm::Sha256,
        "blake3" => HashAlgorithm::Blake3,
        _ => return ERR_INVALID_ALGORITHM,
    };
    
    // Get data slice and generate checksum
    let data_slice = slice::from_raw_parts(data, data_len as usize);
    let checksum = generate_checksum(data_slice, hash_algorithm);
    
    // Convert to C string and copy to output
    let c_checksum = match CString::new(checksum) {
        Ok(s) => s,
        Err(_) => return ERR_STRING_CONVERSION,
    };
    
    // Copy to output buffer including null terminator
    let c_bytes = c_checksum.as_bytes_with_nul();
    let out_slice = slice::from_raw_parts_mut(out_checksum as *mut u8, c_bytes.len());
    out_slice.copy_from_slice(c_bytes);
    
    SUCCESS
}

// Additional utility to get version info
#[no_mangle]
pub extern "C" fn get_crypto_module_version() -> *const c_char {
    static VERSION: &[u8] = b"secure_transfer_crypto v0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

// FFI helper functions for debugging
#[no_mangle]
pub extern "C" fn get_last_error_message() -> *const c_char {
    // In a real implementation, this would return the last error message
    static MSG: &[u8] = b"No error message available\0";
    MSG.as_ptr() as *const c_char
}