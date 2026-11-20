package router

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Envelope is the encrypted object format used by the Zyxel web API.
type Envelope struct {
	Content string `json:"content"`
	Key     string `json:"key"`
	IV      string `json:"iv"`
}

func EncryptEnvelope(plaintext, publicKeyPEM []byte) (Envelope, []byte, error) {
	publicKey, err := parseRSAPublicKey(publicKeyPEM)
	if err != nil {
		return Envelope{}, nil, err
	}
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return Envelope{}, nil, fmt.Errorf("generate encryption key: %w", err)
	}
	envelope, err := EncryptWithKey(plaintext, aesKey)
	if err != nil {
		return Envelope{}, nil, err
	}
	transportedKey := []byte(base64.StdEncoding.EncodeToString(aesKey))
	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, transportedKey)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("encrypt session key: %w", err)
	}
	envelope.Key = base64.StdEncoding.EncodeToString(encryptedKey)
	return envelope, aesKey, nil
}

func EncryptWithKey(plaintext, key []byte) (Envelope, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return Envelope{}, errors.New("invalid AES key")
	}
	iv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return Envelope{}, fmt.Errorf("generate initialization vector: %w", err)
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv[:block.BlockSize()]).CryptBlocks(ciphertext, padded)
	return Envelope{
		Content: base64.StdEncoding.EncodeToString(ciphertext),
		IV:      base64.StdEncoding.EncodeToString(iv),
	}, nil
}

func DecryptEnvelope(envelope Envelope, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("invalid AES key")
	}
	iv, err := base64.StdEncoding.DecodeString(envelope.IV)
	if err != nil || len(iv) < block.BlockSize() {
		return nil, errors.New("invalid encrypted response IV")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Content)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("invalid encrypted response content")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv[:block.BlockSize()]).CryptBlocks(plaintext, ciphertext)
	plaintext, err = pkcs7Unpad(plaintext, block.BlockSize())
	if err != nil {
		return nil, errors.New("invalid encrypted response padding")
	}
	return plaintext, nil
}

func ParseOptionalJSON(data []byte, status int) (any, error) {
	if len(data) == 0 {
		if status >= http.StatusOK && status < http.StatusMultipleChoices {
			return nil, nil
		}
		return nil, fmt.Errorf("empty response with HTTP %d", status)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("invalid JSON response with HTTP %d", status)
	}
	return value, nil
}

func parseRSAPublicKey(value []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, errors.New("router public key is not PEM")
	}
	if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("router public key is not RSA")
		}
		return publicKey, nil
	}
	if publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return publicKey, nil
	}
	return nil, errors.New("router public key could not be parsed")
}

func pkcs7Pad(value []byte, blockSize int) []byte {
	padding := blockSize - len(value)%blockSize
	return append(append([]byte(nil), value...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func pkcs7Unpad(value []byte, blockSize int) ([]byte, error) {
	if len(value) == 0 || len(value)%blockSize != 0 {
		return nil, errors.New("invalid PKCS#7 length")
	}
	padding := int(value[len(value)-1])
	if padding == 0 || padding > blockSize || padding > len(value) {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	for _, b := range value[len(value)-padding:] {
		if int(b) != padding {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}
	return value[:len(value)-padding], nil
}
