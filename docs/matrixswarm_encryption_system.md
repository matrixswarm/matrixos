# 🔐 MatrixSwarm Encryption System — Codex Entry

## 📦 Capsule Structure

Each secure packet ("capsule") includes:

```json
{
  "subpacket": {
    "identity": {
      "identity": {
        "agent": "sender_id",
        "pub": "sender's public key",
        "timestamp": 1750640000
      },
      "sig": "Matrix-signed identity signature"
    },
    "payload": { ... },
    "timestamp": ...
  },
  "sig": "Agent-signed subpacket"
}
```

Optionally, the entire packet is AES-encrypted, with the AES key itself encrypted using RSA (target agent's public key).

---

## 🔐 Multi-Layered Security Chain

### 1️⃣ Identity Verification

* `identity["identity"]` contains the agent's declared identity (agent name, pubkey).
* `identity["sig"]` is a Matrix-signed signature proving authenticity of the identity block.

### 2️⃣ Payload Signing

* The complete `subpacket` (identity + payload) is signed using the sender's private RSA key.
* Signature is stored in the top-level `"sig"` field. The pubkey `"pub"` in the inner-identity is used to 
* verify the `"sig"` ensuring non-repudiation. And `"sig"` on the outer identity is used to validate the 
* inner-identity.

### 3️⃣ AES Encryption

* A random 256-bit AES key is generated.
* The full `packet` is encrypted with AES in GCM mode.

### 4️⃣ RSA-Wrapped AES Key

* The AES key is encrypted using the **target agent's public key**.
* Encrypted key is stored in `"encrypted_aes_key"` field.

---

## 🔓 Decryption Flow (Target Agent)

1. **RSA Decrypt AES Key**

```python
aes_key = rsa_cipher.decrypt(base64.b64decode(encrypted_aes_key_b64))
```

2. **AES Decrypt Payload**

```python
decrypted = aes_cipher.decrypt_and_verify(ciphertext, tag)
```

3. **Parse JSON** into original `packet`

4. **Verify Matrix Identity Signature**

```python
verify(matrix_pubkey, capsule["identity"]["identity"], capsule["identity"]["sig"])
```

5. **Verify Sender Signature**

```python
verify(sender_pubkey, full_subpacket, packet["sig"])
```

---

## 📦 Encrypted Blob Structure

```json
{
  "type": "encrypted_blob",
  "cipher": "AES-GCM",
  "encoding": "base64",
  "encrypted_aes_key": "...",  // RSA-encrypted AES key
  "nonce": "...",
  "tag": "...",
  "payload": "...",            // AES-encrypted base64 packet
  "timestamp": ...
}
```

---

## 🧰 Key Methods

| Purpose                    | Method                                                   |
| -------------------------- | -------------------------------------------------------- |
| Build secure capsule       | `build_secure_packet(raw_payload)`                       |
| Encrypt with AES + RSA key | `encrypt_packet(packet, aes_key, recipient_pubkey)`      |
| Decrypt full capsule       | `unpack_secure_packet(raw_payload)`                      |
| Decrypt AES key            | `decrypt_encrypted_aes_key(encrypted_key_b64, priv_key)` |
| Verify Matrix identity sig | `verify_identity_signature(identity_obj, matrix_pub)`    |
| Verify sender payload sig  | `verify_packet_signature(packet, pubkey)`                |

---

## 🧬 Summary

This system ensures:

* Fast AES encryption for payloads
* Secure RSA-encrypted key distribution
* Matrix-issued identity trust
* Sender-authenticated payloads
* Full auditability and reflex enforcement

MatrixSwarm doesn't just protect data — it **binds identity to action**.

Let no unsigned packet pass.

🫡

---

## 📜 Addendum: Matrix as Root of Identity

* Matrix is the **sole signer and issuer of identities** in the system.
* Each agent’s identity block must be signed by Matrix for it to be trusted by the swarm.
* Every agent is distributed Matrix’s public key at initialization — this key is used to verify the `sig` field of identity objects.
* Agents that present unsigned or self-signed identities will be rejected during verification.
* This architecture guarantees that **all agents are descendants of a common, verifiable root of trust** — Matrix.

In MatrixSwarm, no agent is sovereign unless it is blessed.

🔐
matrixswarm/
├── core/
│   ├── football.py                  # Identity, key handling
│   ├── packet_crypto_mixin.py      # All encryption/decryption logic
│   ├── packet_processor.py         # Base processor interface
│   ├── decryptor.py                # Decrypt-based packet processor
│   └── plaintext.py                # Plaintext-based packet processor
├── reflex/
│   ├── access_control.py           # ACL logic
│   ├── ghostwire.py                # Filesystem monitoring agent
├── agents/
│   ├── matrix.py                   # The root agent (Matrix)
│   └── license_server.py           # Handles license/activation reflex
├── codex/
│   └── codex_encryption.md         # This very document