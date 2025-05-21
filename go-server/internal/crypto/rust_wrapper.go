package crypto

// #cgo LDFLAGS: -L${SRCDIR}/../../../rust-crypto-module/target/release -lsecure_transfer_crypto
// #include <stdlib.h>
// #include <stdint.h>
//
// // Function declarations matching the Rust FFI interface
// extern int generate_encryption_key(unsigned char* out_key);
// extern int encrypt_buffer(const unsigned char* data, unsigned int data_len,
//                          const unsigned char* key, unsigned char* out_data,
//                          unsigned int* out_len);
// extern int decrypt_buffer(const unsigned char* encrypted_data, unsigned int encrypted_len,
//                          const unsigned char* key, unsigned char* out_data,
//                          unsigned int* out_len);
// extern int generate_buffer_checksum(const unsigned char* data, unsigned int data_len,
//                                   const char* algorithm, char* out_checksum);
// extern const char* get_crypto_module_version();
// extern const char* get_last_error_message();
import "C"
import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"unsafe"
)

// Error codes from Rust
const (
	SUCCESS          = 0
	ERR_ENCRYPTION   = -1
	ERR_DECRYPTION   = -2
	ERR_INVALID_KEY  = -3
	ERR_INVALID_DATA = -4
	ERR_INVALID_ALG  = -5
	ERR_NULL_POINTER = -6
	ERR_STRING_CONV  = -7
)

// SupportedHashAlgorithms lists available hash algorithms
var SupportedHashAlgorithms = []string{"sha256", "blake3"}

// GenerateKey generates a new random encryption key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	result := C.generate_encryption_key((*C.uchar)(unsafe.Pointer(&key[0])))

	if result != SUCCESS {
		return nil, mapErrorCode(result)
	}

	return key, nil
}

// Encrypt encrypts data using the provided key
func Encrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length: must be 32 bytes")
	}

	// First call to get required buffer size
	dataLen := C.uint(len(data))
	var outLen C.uint

	result := C.encrypt_buffer(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		dataLen,
		(*C.uchar)(unsafe.Pointer(&key[0])),
		nil,
		&outLen,
	)

	if result != SUCCESS {
		return nil, mapErrorCode(result)
	}

	// Allocate output buffer
	encrypted := make([]byte, outLen)

	// Second call to actually encrypt data
	result = C.encrypt_buffer(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		dataLen,
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&encrypted[0])),
		&outLen,
	)

	if result != SUCCESS {
		return nil, mapErrorCode(result)
	}

	return encrypted[:outLen], nil
}

// Decrypt decrypts data using the provided key
func Decrypt(encryptedData []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length: must be 32 bytes")
	}

	// First call to get required buffer size
	encryptedLen := C.uint(len(encryptedData))
	var outLen C.uint

	result := C.decrypt_buffer(
		(*C.uchar)(unsafe.Pointer(&encryptedData[0])),
		encryptedLen,
		(*C.uchar)(unsafe.Pointer(&key[0])),
		nil,
		&outLen,
	)

	if result != SUCCESS {
		return nil, mapErrorCode(result)
	}

	// Allocate output buffer
	decrypted := make([]byte, outLen)

	// Second call to actually decrypt data
	result = C.decrypt_buffer(
		(*C.uchar)(unsafe.Pointer(&encryptedData[0])),
		encryptedLen,
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&decrypted[0])),
		&outLen,
	)

	if result != SUCCESS {
		return nil, mapErrorCode(result)
	}

	return decrypted[:outLen], nil
}

// GenerateChecksum generates a checksum for the provided data
func GenerateChecksum(data []byte, algorithm string) (string, error) {
	// Validate algorithm
	valid := false
	for _, alg := range SupportedHashAlgorithms {
		if algorithm == alg {
			valid = true
			break
		}
	}

	if !valid {
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	// Allocate checksum buffer (64 hex chars + null terminator)
	checksumBuf := make([]byte, 65)

	// Convert algorithm to C string
	cAlgorithm := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlgorithm))

	result := C.generate_buffer_checksum(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		cAlgorithm,
		(*C.char)(unsafe.Pointer(&checksumBuf[0])),
	)

	if result != SUCCESS {
		return "", mapErrorCode(result)
	}

	// Convert C string to Go string
	checksum := C.GoString((*C.char)(unsafe.Pointer(&checksumBuf[0])))
	return checksum, nil
}

// EncryptReader encrypts data from a reader and writes to a writer
func EncryptReader(reader io.Reader, writer io.Writer, key []byte) error {
	if len(key) != 32 {
		return errors.New("invalid key length: must be 32 bytes")
	}

	// For simplicity, we'll read the entire file into memory
	// In a production system, you'd want to stream this
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	encrypted, err := Encrypt(data, key)
	if err != nil {
		return err
	}

	_, err = writer.Write(encrypted)
	if err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	return nil
}

// DecryptReader decrypts data from a reader and writes to a writer
func DecryptReader(reader io.Reader, writer io.Writer, key []byte) error {
	if len(key) != 32 {
		return errors.New("invalid key length: must be 32 bytes")
	}

	// For simplicity, we'll read the entire file into memory
	// In a production system, you'd want to stream this
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	decrypted, err := Decrypt(data, key)
	if err != nil {
		return err
	}

	_, err = writer.Write(decrypted)
	if err != nil {
		return fmt.Errorf("failed to write decrypted data: %w", err)
	}

	return nil
}

// GetVersion returns the version of the crypto module
func GetVersion() string {
	return C.GoString(C.get_crypto_module_version())
}

// mapErrorCode converts error codes from Rust to Go errors
func mapErrorCode(code C.int) error {
	switch code {
	case SUCCESS:
		return nil
	case ERR_ENCRYPTION:
		return errors.New("encryption failed")
	case ERR_DECRYPTION:
		return errors.New("decryption failed")
	case ERR_INVALID_KEY:
		return errors.New("invalid encryption key")
	case ERR_INVALID_DATA:
		return errors.New("invalid data format")
	case ERR_INVALID_ALG:
		return errors.New("invalid hash algorithm")
	case ERR_NULL_POINTER:
		return errors.New("null pointer error")
	case ERR_STRING_CONV:
		return errors.New("string conversion error")
	default:
		return fmt.Errorf("unknown error: %d", code)
	}
}
