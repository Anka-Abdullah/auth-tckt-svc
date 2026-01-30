package utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
)

// GetFileExtension gets file extension
func GetFileExtension(filename string) string {
	return strings.ToLower(filepath.Ext(filename))
}

// GetMimeType gets mime type from extension
func GetMimeType(extension string) string {
	mimeTypes := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".pdf":  "application/pdf",
		".doc":  "application/msword",
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xls":  "application/vnd.ms-excel",
		".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".txt":  "text/plain",
		".csv":  "text/csv",
		".json": "application/json",
		".zip":  "application/zip",
	}

	if mime, ok := mimeTypes[strings.ToLower(extension)]; ok {
		return mime
	}

	return "application/octet-stream"
}

// IsImageFile checks if file is an image
func IsImageFile(filename string) bool {
	extension := GetFileExtension(filename)
	imageExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}

	for _, ext := range imageExtensions {
		if extension == ext {
			return true
		}
	}

	return false
}

// CalculateFileHash calculates MD5 hash of file
func CalculateFileHash(file *multipart.FileHeader) (string, error) {
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, src); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// SaveUploadedFile saves uploaded file
func SaveUploadedFile(file *multipart.FileHeader, destination string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	// Create destination directory if not exists
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	dst, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err = io.Copy(dst, src); err != nil {
		return err
	}

	return nil
}

// GetFileSize returns file size in human readable format
func GetFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// SafeFileName creates a safe filename
func SafeFileName(filename string) string {
	// Remove directory path
	filename = filepath.Base(filename)

	// Replace unsafe characters
	unsafeChars := []string{" ", "\"", "'", "&", "/", "\\", "?", "#", "%"}
	for _, char := range unsafeChars {
		filename = strings.ReplaceAll(filename, char, "_")
	}

	// Limit length
	if len(filename) > 255 {
		ext := filepath.Ext(filename)
		name := filename[:255-len(ext)]
		filename = name + ext
	}

	return filename
}

// FileExists checks if file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// CreateDirectory creates directory recursively
func CreateDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// DeleteFile deletes a file
func DeleteFile(path string) error {
	return os.Remove(path)
}

// GetWorkingDirectory gets current working directory
func GetWorkingDirectory() string {
	dir, _ := os.Getwd()
	return dir
}
