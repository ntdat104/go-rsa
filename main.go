package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
)

// KeyPair represents an RSA public and private key pair in PEM format.
type KeyPair struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

// KeyBuffer manages the pre-generated RSA key pairs.
type KeyBuffer struct {
	mu            sync.Mutex // Mutex for protecting fillBuffer calls
	keys512       chan KeyPair
	keys1024      chan KeyPair
	keys2048      chan KeyPair
	keys4096      chan KeyPair
	minBufferSize int // Minimum number of keys to maintain in the buffer
	maxBufferSize int // Maximum number of keys to allow in the buffer
}

// NewKeyBuffer initializes and returns a new KeyBuffer.
func NewKeyBuffer(min, max int) *KeyBuffer {
	kb := &KeyBuffer{
		keys512:       make(chan KeyPair, max),
		keys1024:      make(chan KeyPair, max),
		keys2048:      make(chan KeyPair, max),
		keys4096:      make(chan KeyPair, max),
		minBufferSize: min,
		maxBufferSize: max,
	}
	// Start initial key generation for all supported key sizes in the background
	go kb.fillBuffer(512)
	go kb.fillBuffer(1024)
	go kb.fillBuffer(2048)
	go kb.fillBuffer(4096)
	return kb
}

// generateSingleKeyPair generates a single RSA key pair synchronously.
func generateSingleKeyPair(keySize int) (KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return KeyPair{}, fmt.Errorf("error generating %d-bit RSA private key: %v", keySize, err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("error marshalling PKCS8 private key (%d-bit): %v", keySize, err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("error marshalling PKIX public key (%d-bit): %v", keySize, err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return KeyPair{PublicKey: string(publicPEM), PrivateKey: string(privatePEM)}, nil
}

// GetKeyPair retrieves a key pair from the buffer for a given key size.
// If the buffer is empty, it will synchronously generate a new key pair.
func (kb *KeyBuffer) GetKeyPair(keySize int) (KeyPair, error) {
	var kp KeyPair
	var targetChannel chan KeyPair

	switch keySize {
	case 512:
		targetChannel = kb.keys512
	case 1024:
		targetChannel = kb.keys1024
	case 2048:
		targetChannel = kb.keys2048
	case 4096:
		targetChannel = kb.keys4096
	default:
		return KeyPair{}, fmt.Errorf("unsupported key size: %d", keySize)
	}

	select {
	case kp = <-targetChannel:
		// Key successfully retrieved from buffer
		log.Printf("Retrieved %d-bit key from buffer. Current buffer size: %d/%d", keySize, len(targetChannel), cap(targetChannel))
		// Check if buffer needs refilling after extraction
		if len(targetChannel) < kb.minBufferSize {
			go kb.fillBuffer(keySize) // Trigger background fill
		}
		return kp, nil
	default:
		// Buffer is empty, synchronously generate a new key
		log.Printf("Buffer for %d-bit keys is empty. Synchronously generating one key...", keySize)
		generatedKey, err := generateSingleKeyPair(keySize)
		if err != nil {
			log.Printf("Error during synchronous key generation for %d-bit: %v", keySize, err)
			return KeyPair{}, fmt.Errorf("failed to synchronously generate key pair: %v", err)
		}
		log.Printf("Synchronously generated %d-bit key.", keySize)
		// Also trigger background fill to replenish the buffer for future requests
		go kb.fillBuffer(keySize)
		return generatedKey, nil
	}
}

// fillBuffer generates RSA keys and adds them to the respective buffer channel.
func (kb *KeyBuffer) fillBuffer(keySize int) {
	// Use a mutex to prevent multiple concurrent fillBuffer goroutines for the same keySize
	// from generating too many keys if multiple requests hit the low buffer at once.
	// This mutex is internal to fillBuffer and separate from the map access mutex.
	var targetChannel chan KeyPair

	switch keySize {
	case 512:
		targetChannel = kb.keys512
	case 1024:
		targetChannel = kb.keys1024
	case 2048:
		targetChannel = kb.keys2048
	case 4096:
		targetChannel = kb.keys4096
	default:
		log.Printf("Attempted to fill buffer for unsupported key size: %d", keySize)
		return
	}

	kb.mu.Lock() // Use the KeyBuffer's main mutex to prevent concurrent fills for the same key size
	defer kb.mu.Unlock()

	currentSize := len(targetChannel)
	if currentSize >= kb.maxBufferSize {
		log.Printf("Buffer for %d-bit keys is already full (%d/%d). No background generation needed.", keySize, currentSize, kb.maxBufferSize)
		return
	}

	keysToGenerate := kb.maxBufferSize - currentSize
	log.Printf("Background: Generating %d new %d-bit RSA key pairs to replenish buffer (current: %d, min: %d, max: %d)...",
		keysToGenerate, keySize, currentSize, kb.minBufferSize, kb.maxBufferSize)

	for i := 0; i < keysToGenerate; i++ {
		kp, err := generateSingleKeyPair(keySize) // Use the new helper function
		if err != nil {
			log.Printf("Background: Error generating %d-bit RSA private key: %v", keySize, err)
			continue // Try next iteration
		}

		select {
		case targetChannel <- kp:
			// Key added successfully
		default:
			// This case means the channel is unexpectedly full, possibly due to a race
			// condition or misconfiguration of buffer sizes. Log and break.
			log.Printf("Background: Buffer for %d-bit keys is unexpectedly full while generating. Stopping generation.", keySize)
			return
		}
	}
	log.Printf("Background: Finished generating %d-bit RSA key pairs. Buffer size: %d/%d", keySize, len(targetChannel), cap(targetChannel))
}

var keyBuffer *KeyBuffer

func main() {
	// Initialize the key buffer with desired min and max sizes
	// minKeys = 15: Trigger background generation if buffer drops below 15 keys
	// maxKeys = 30: Maintain up to 30 keys in the buffer
	const (
		minKeys = 15
		maxKeys = 30
	)
	keyBuffer = NewKeyBuffer(minKeys, maxKeys)

	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*") // IMPORTANT: Restrict this to your frontend's origin in production
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	router.GET("/generate-rsa-keys", getBufferedRSAKeysHandler)

	log.Println("Go-Gin RSA Key Generation API (Buffered/On-Demand) running on :8080")
	router.Run(":8080")
}

// getBufferedRSAKeysHandler retrieves a key pair from the buffer.
func getBufferedRSAKeysHandler(c *gin.Context) {
	keySizeStr := c.DefaultQuery("keySize", "2048")
	keySize, err := strconv.Atoi(keySizeStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid keySize parameter. Must be an integer (e.g., 512, 1024, 2048, 4096)."})
		return
	}

	// Updated to include 512 and 1024
	if keySize != 512 && keySize != 1024 && keySize != 2048 && keySize != 4096 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported keySize. Choose from 512, 1024, 2048 or 4096."})
		return
	}

	kp, err := keyBuffer.GetKeyPair(keySize)
	if err != nil {
		// This error will now only occur if synchronous generation fails
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "message": "Failed to generate key pair."})
		return
	}

	c.JSON(http.StatusOK, kp)
}
