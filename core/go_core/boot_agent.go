package bootagent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Vault is the decrypted payload from Python CoreSpawner
type Vault struct {
	UniversalID string                 `json:"universal_id"`
	Name        string                 `json:"name"`
	Role        []string               `json:"role"`
	CommPath    string                 `json:"comm_path"`
	PodPath     string                 `json:"pod_path"`
	Config      map[string]interface{} `json:"config"`
	SecureKeys  map[string]string      `json:"secure_keys"`
	SwarmKey    string                 `json:"swarm_key"`
	MatrixPub   string                 `json:"matrix_pub"`
	MatrixPriv  string                 `json:"matrix_priv"`
}

// envelope mirrors ghost_vault.py structure
type envelope struct {
	Sha256  string `json:"sha256"`
	Payload Vault  `json:"payload"`
}

// LoadVault decrypts the vault file using SYMKEY + AES-GCM
func LoadVault() (*Vault, error) {
	vaultFile := os.Getenv("VAULTFILE")
	symkeyB64 := os.Getenv("SYMKEY")
	if vaultFile == "" || symkeyB64 == "" {
		return nil, fmt.Errorf("[GO-BOOT_AGENT] Missing VAULTFILE or SYMKEY in env")
	}

	symkey, err := base64.StdEncoding.DecodeString(symkeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode symkey: %v", err)
	}

	raw, err := ioutil.ReadFile(vaultFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault file: %v", err)
	}

	var vault map[string]string
	if err := json.Unmarshal(raw, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse vault json: %v", err)
	}

	nonce, _ := base64.StdEncoding.DecodeString(vault["nonce"])
	tag, _ := base64.StdEncoding.DecodeString(vault["tag"])
	ciphertext, _ := base64.StdEncoding.DecodeString(vault["ciphertext"])

	// Python ghost_vault stores ciphertext and tag separately
	// Go AES-GCM expects ciphertext||tag
	combined := append(ciphertext, tag...)

	block, err := aes.NewCipher(symkey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher error: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm error: %v", err)
	}

	plaintext, err := gcm.Open(nil, nonce, combined, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt error: %v", err)
	}

	var env envelope
	if err := json.Unmarshal(plaintext, &env); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted payload: %v", err)
	}

	// verify sha256
	h := sha256.Sum256(plaintext)
	if !hexEqualPrefix(hex.EncodeToString(h[:]), env.Sha256) {
		return nil, fmt.Errorf("sha mismatch: expected %s got %s", env.Sha256, hex.EncodeToString(h[:]))
	}

	return &env.Payload, nil
}

// hexEqualPrefix compares hashes allowing env.Sha256 to be truncated
func hexEqualPrefix(calc, given string) bool {
	if len(given) > len(calc) {
		return false
	}
	return calc[:len(given)] == given
}

// InitPaths ensures comm/pod dirs exist
func InitPaths(v *Vault) error {
	paths := []string{
		filepath.Join(v.CommPath, v.UniversalID, "incoming"),
		filepath.Join(v.CommPath, v.UniversalID, "replies"),
		filepath.Join(v.CommPath, v.UniversalID, "hello.moto"),
		filepath.Join(v.PodPath, "logs"),
	}
	for _, p := range paths {
		if err := os.MkdirAll(p, 0755); err != nil {
			return err
		}
	}
	return nil
}

// DebugPrint shows identity info
func DebugPrint(v *Vault) {
	fmt.Printf("[VAULT] id=%s comm=%s roles=%v\n",
		v.UniversalID, v.CommPath, v.Role)
}
