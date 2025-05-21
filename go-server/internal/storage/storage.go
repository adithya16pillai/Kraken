package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FileMetadata represents information about a stored file
type FileMetadata struct {
	ID               string    `json:"id"`
	OriginalFilename string    `json:"original_filename"`
	Size             int64     `json:"size"`
	Checksum         string    `json:"checksum"`
	Algorithm        string    `json:"algorithm"`
	UploadedAt       time.Time `json:"uploaded_at"`
	Encrypted        bool      `json:"encrypted"`
	ContentType      string    `json:"content_type,omitempty"`
}

// Storage defines the interface for file storage operations
type Storage interface {
	// Save stores a file and returns its generated ID and metadata
	Save(reader io.Reader, filename string, metadata FileMetadata) (string, error)

	// Get retrieves a file by its ID
	Get(id string) (io.ReadCloser, FileMetadata, error)

	// Delete removes a file by its ID
	Delete(id string) error

	// GetMetadata retrieves just the metadata for a file
	GetMetadata(id string) (FileMetadata, error)

	// UpdateMetadata updates the metadata for a file
	UpdateMetadata(id string, metadata FileMetadata) error
}

// FileSystemStorage implements Storage using the local filesystem
type FileSystemStorage struct {
	basePath string
}

// NewStorage creates a new storage instance based on configuration
func NewStorage(config struct {
	Type string `mapstructure:"type"`
	Path string `mapstructure:"path"`
}) (Storage, error) {
	switch config.Type {
	case "filesystem":
		return NewFileSystemStorage(config.Path)
	// Add cases for other storage types like S3 in the future
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.Type)
	}
}

// NewFileSystemStorage creates a new instance of FileSystemStorage
func NewFileSystemStorage(basePath string) (*FileSystemStorage, error) {
	// Create base storage directories
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Create subdirectories for files and metadata
	filesDir := filepath.Join(basePath, "files")
	metadataDir := filepath.Join(basePath, "metadata")

	if err := os.MkdirAll(filesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create files directory: %w", err)
	}

	if err := os.MkdirAll(metadataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create metadata directory: %w", err)
	}

	return &FileSystemStorage{basePath: basePath}, nil
}

// Save implements Storage.Save for FileSystemStorage
func (fs *FileSystemStorage) Save(reader io.Reader, filename string, metadata FileMetadata) (string, error) {
	// Generate UUID if not provided
	if metadata.ID == "" {
		metadata.ID = uuid.New().String()
	}

	// Compute file paths
	filePath := filepath.Join(fs.basePath, "files", metadata.ID)
	metadataPath := filepath.Join(fs.basePath, "metadata", metadata.ID+".json")

	// Create the file
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy data to file
	size, err := io.Copy(file, reader)
	if err != nil {
		// Clean up on error
		os.Remove(filePath)
		return "", fmt.Errorf("failed to write file data: %w", err)
	}

	// Update metadata
	metadata.Size = size
	metadata.UploadedAt = time.Now()
	metadata.OriginalFilename = filename

	// Save metadata
	if err := writeJSONFile(metadataPath, metadata); err != nil {
		// Clean up on error
		os.Remove(filePath)
		return "", fmt.Errorf("failed to write metadata: %w", err)
	}

	return metadata.ID, nil
}

// Get implements Storage.Get for FileSystemStorage
func (fs *FileSystemStorage) Get(id string) (io.ReadCloser, FileMetadata, error) {
	// Sanitize input to prevent path traversal
	if !isValidID(id) {
		return nil, FileMetadata{}, errors.New("invalid file ID")
	}

	// Compute file paths
	filePath := filepath.Join(fs.basePath, "files", id)
	metadataPath := filepath.Join(fs.basePath, "metadata", id+".json")

	// Read metadata
	var metadata FileMetadata
	if err := readJSONFile(metadataPath, &metadata); err != nil {
		return nil, FileMetadata{}, fmt.Errorf("failed to read metadata: %w", err)
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, FileMetadata{}, errors.New("file not found")
		}
		return nil, FileMetadata{}, fmt.Errorf("failed to open file: %w", err)
	}

	return file, metadata, nil
}

// Delete implements Storage.Delete for FileSystemStorage
func (fs *FileSystemStorage) Delete(id string) error {
	// Sanitize input to prevent path traversal
	if !isValidID(id) {
		return errors.New("invalid file ID")
	}

	// Compute file paths
	filePath := filepath.Join(fs.basePath, "files", id)
	metadataPath := filepath.Join(fs.basePath, "metadata", id+".json")

	// Delete file
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	// Delete metadata
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete metadata: %w", err)
	}

	return nil
}

// GetMetadata implements Storage.GetMetadata for FileSystemStorage
func (fs *FileSystemStorage) GetMetadata(id string) (FileMetadata, error) {
	// Sanitize input to prevent path traversal
	if !isValidID(id) {
		return FileMetadata{}, errors.New("invalid file ID")
	}

	// Read metadata
	metadataPath := filepath.Join(fs.basePath, "metadata", id+".json")
	var metadata FileMetadata
	if err := readJSONFile(metadataPath, &metadata); err != nil {
		return FileMetadata{}, fmt.Errorf("failed to read metadata: %w", err)
	}

	return metadata, nil
}

// UpdateMetadata implements Storage.UpdateMetadata for FileSystemStorage
func (fs *FileSystemStorage) UpdateMetadata(id string, metadata FileMetadata) error {
	// Sanitize input to prevent path traversal
	if !isValidID(id) {
		return errors.New("invalid file ID")
	}

	// Ensure ID is not changed
	metadata.ID = id

	// Write metadata
	metadataPath := filepath.Join(fs.basePath, "metadata", id+".json")
	return writeJSONFile(metadataPath, metadata)
}

// Helper functions
func isValidID(id string) bool {
	// Basic validation - UUIDs should not contain path characters
	return id != "" &&
		!filepath.IsAbs(id) &&
		!strings.Contains(id, "/") &&
		!strings.Contains(id, "\\") &&
		!strings.Contains(id, "..")
}

func writeJSONFile(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := ioutil.WriteFile(path, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func readJSONFile(path string, data interface{}) error {
	jsonData, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("metadata not found")
		}
		return fmt.Errorf("failed to read file: %w", err)
	}

	if err := json.Unmarshal(jsonData, data); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}
