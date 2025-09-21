import time
import json
import base64
from core.python_core.mixin.log_method import LogMixin

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from core.python_core.utils.debug.config import DebugConfig
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.sig_payload_json import SigPayloadJson
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.interfaces.sig_payload import SigPayload

class PacketCryptoMixin(LogMixin):

    def __init__(self):
        self.football = None  # Command & Crypto strategy
        self._decrypted_packet = None
        self.allowed_sender_ids = set()
        self.debug = DebugConfig()

    def set_football(self, football_obj):
        self.football = football_obj
        self.allowed_sender_ids = self.football.get_allowed_sender_ids()
        return self

    def force_jsonify(obj):
        """
        Ensures the object is converted to a valid JSON string.
        - If it's already a dict, attempts to serialize it.
        - If it fails, attempts to clean or fallback.
        """
        try:
            return json.dumps(obj, sort_keys=True)
        except (TypeError, OverflowError) as e:
            raise RuntimeError(f"Object could not be JSON-encoded: {e}")

    def build_secure_packet(self, raw_payload: dict):

        try:
            """
            Builds a secure packet using Football as the strategy controller.
            Follows the exact path of: identity -> verify -> encrypt -> sign -> AES encrypt
            """
            if not self.football:
                raise RuntimeError("Football not injected. Cannot proceed.")

            if not isinstance(raw_payload, dict):
                raise RuntimeError("Payload is not a dictionary.")

            # Step 1: Load identity into packet (optional)
            subpacket = {"payload": raw_payload, "timestamp": int(time.time())}

            #this will include identity(universal_id, pubkey, timestamp) + sig(Matrix signature of the identity)
            if self.football.use_payload_identity_file():
                subpacket["identity"] = self.football.get_payload_identity()

            if self.football.use_asymmetric_encryption():

                pubkey_pem = self.football.get_pubkey_for_encryption()
                pubkey = RSA.import_key(pubkey_pem.encode())
                cipher = PKCS1_OAEP.new(pubkey)
                encrypted = cipher.encrypt(json.dumps(subpacket["payload"]).encode())
                subpacket["payload"] = base64.b64encode(encrypted).decode()

            packet = {"subpacket": subpacket}

            # Step 3: Sign the packet with your private key
            if self.football.sign_payload():
                sp = SigPayloadJson()
                sp.set_payload(subpacket)

                signer_key = RSA.import_key(self.football.get_payload_signing_key())
                packet["sig"] = self.sign_payload(sp, signer_key)

            # Step 4: Encrypt final packet with AES key
            # You could make this even more secure, by passing a random aes private key
            # encrypting it with the targets pubkey, and then using it to encrypt the packet
            if self.football.use_symmetric_encryption(): #this will either be the swarm-key or the target agent's id

                aes_key_b64 = self.football.get_aes_key()

                packet = self.encrypt_packet(packet,
                                             aes_key_b64,                                          #personal aes key
                                             self.football.encrypt_aes_key_using_target_pubkey(),  #are we using a key
                                             self.football.get_aes_encryption_pubkey()    #key belongs to the target
                                             )

            # exit(json.dumps(packet, indent=2, sort_keys=True))

            return packet

        except Exception as e:
            self.log(error=e, block="main_try")

    def unpack_secure_packet(self, raw_payload: dict):
        """
        Fully reverses the packet built by build_secure_packet().
        - Decrypts AES outer wrapper
        - Verifies signature (if expected)
        - Optionally decrypts RSA payload
        - Extracts subpacket
        - Returns original payload
        """
        self._decrypted_packet = None
        if not self.football:
            raise RuntimeError("Football not injected.")

        try:
            packet=raw_payload
            if self.football.use_symmetric_encryption():
                # Step 1: Decrypt AES outer layer
                step="1"
                if raw_payload.get("type") != "encrypted_blob":
                    step="1.1"
                    raise ValueError("Unsupported or unrecognized packet format.")

                if self.football.decrypt_aes_key_using_privkey():
                    aes_key_b64 = self.decrypt_private_key(raw_payload["encrypted_aes_key"], self.football.get_aes_encryption_privkey()) # must be private
                else:
                    aes_key_b64 = self.football.get_aes_key()

                raw_payload = self.decrypt_packet(raw_payload, aes_key_b64)

                packet = raw_payload.get("subpacket")

            # Step 2: Verify signature if expected
            subpacket = packet.get("subpacket", {})
            if self.football.verify_signed_payload():
                step = "2"
                r'''
                this tests if the sig matches the whole packet ({identity} + payload + timestamp)
                Example:
                #sender signature of subpacket - the pubkey to verify the signature is contained in subpacket\identity\identity\pub
                "sig": "CjtI5QZjSuR6siKxblJvFqpvv41wAnmlLUEHrf0QEgEusq9+Ea4JqII2s4Ai2HNbWweiZtx4qwF2qQIJW+hrF4/n5nJ4yYpiaMxSBVZM6oKleYxzhgVru44/EzKwN3CFgX5kq15B1TlgN6eww8LXER1z13vIHzbx7zBIX9VQKNnN1pE1d04THmsAQAcHJrs+q5ONy0F9igZVmXbEdWGyhctKIoBZ8ticE8VwRvHQwAdFwKRWxub57KysWhok3yZdd0numCiOw4ERhkYVeHJoJhYhCjvm9GrLit79Djdn0pgdq7FDGDjYjXq3Bjs0/JP+WH7fpWsEYMfVce7wb6QiVQ==",
                "subpacket": {
                ----"identity": {
                --------"identity": {
                ------------"universal_id": "bigboytoy_1",
                ------------"pub": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAioYDKbnAoYJsQme6aJvw\nDIBlEYEDqTjuZIffDHJYtaK0SsflJijmuUKXI/fA8RH93MipWDe6uvHoz9ewTk67\nWymN6YYsiRXjKPcPnimFcjw051kBJZ7GyMJRAOrZCqgAgjZO5TKV5naS5+9OzInq\nEDiL9uNmKJy1yHG6DMinvVL4jD0m0E4gsKhbDh9I3VEYNKPDqiWdwDiEntVdvc5v\njU69zzlZ+WGNDhVpwVvWo8i5K3yb95XY+m15U/o+zdGfO9XWiicudk8WiwGg6b3K\nPgEYaFM6F5KuqAYkVBaY5LX04lI6oGsp8NIFZYtpLUdgOU7FpdVzfqpxPU0Jq6ls\nXwIDAQAB\n-----END PUBLIC KEY-----\n",
                ------------"timestamp": 441763200
                --------},
                --------Matrix signature of the inner identity
                --------"sig": "hvdwEmDpJrW0IZg95XaNU9fVbtrft2x4fGO+7XadfKKwY7Izdyu0TG0GiJrJvpp+gCXLI51A6P5nQ/oxAjG0gCCBE8Hw4DdeRfjUx6n7jd7HK3XyPA6MiZ21YMvMtqIy/hlKJIST0lEgbx71jrolRaYwP/8i9aEP1In3ZIRTDWP6q8REw4EoJOQPwFLO7NRBYB8vngoypOgALA3Akqc5ItQaVEEvKQv+LMyggAEJyUCh9/mDt2wus8SotP7tFg1si9sDipKAoFUIh+wIORxURBlnTMGsND7QTOQjsZ5Q+R2d0PZDA3Qzu5ZP0Mk3Zw1pMlU30W+dEyVp8zHsWNHBgA=="
                ----},
                ----"payload": {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5},
                ----"timestamp": 922838400
                }
                '''

                #exit(json.dumps(packet, indent=2, sort_keys=True))

                # inner-identity packet
                identity = subpacket.get("identity").get("identity")

                #Matrix Signature
                sig = subpacket.get("identity").get("sig")
                pubkey = self.football.get_pubkey_verifier() #Matrix's pubkey
                if not sig or not pubkey:
                    step = "2.1"
                    raise RuntimeError("Packet signature exists but no subpacket found.")

                #verify Matrix signed the identity
                sp = SigPayloadJson()
                sp.set_payload(identity)
                if not self.verify_payload(sp, pubkey, sig):
                    step = "2.2"
                    raise RuntimeError("Packet signature did not pass.")

                #outter packet - sender's signature, using the sender's private key on the outer packet(subpacket)
                #since the inner-identity pubkey has been signed by Matrix and since the inner-identity pubkey is used to
                # verify the outer packet. hence, the owner of the identity sent the message
                sig = packet.get('sig')
                pubkey = subpacket.get("identity").get("identity").get("pub")
                if not sig or not pubkey:
                    step = "2.3"
                    raise RuntimeError("Packet signature exists but no subpacket found.")

                sp = SigPayloadJson()
                sp.set_payload(subpacket)
                #use the pubkey contained in the identity, since the packet has been signed by the paired privkey
                if not self.verify_payload(sp, pubkey, sig):
                    step = "2.4"
                    raise RuntimeError("Packet signature did not pass.")

                self._decrypted_packet = subpacket

                if not self.is_sender_allowed():
                    step = "2.5"
                    raise RuntimeError(f"Packet dropped: sender \"{self.get_sender_uid()}\" not in allowlist.")

            #exit(json.dumps(packet, indent=2, sort_keys=True))

            # Step 3: Decrypt RSA-wrapped payload if present
            if self.football.use_asymmetric_encryption() :
                encrypted_payload_b64 = subpacket.get("payload")
                step = "3"
                if encrypted_payload_b64:
                    encrypted_bytes = base64.b64decode(encrypted_payload_b64)

                    priv_obj = RSA.import_key(self.football.get_payload_signing_key())

                    cipher_rsa = PKCS1_OAEP.new(priv_obj)

                    decrypted_payload_json = cipher_rsa.decrypt(encrypted_bytes)

                    subpacket["payload"] = json.loads(decrypted_payload_json.decode())

            step = "4"
            # Step 4: Extract creamy center and validate timestamp
            subpacket_ts = subpacket.get("timestamp")
            now = int(time.time())
            ttl_limit = 90  # seconds

            if subpacket_ts and (now - subpacket_ts) > ttl_limit:
                step = "4.1"
                #raise RuntimeError(f"Packet too old. Age: {now - subpacket_ts}s > TTL {ttl_limit}s")

            #return unencrypted
            return subpacket["payload"]

        except Exception as e:

            self.log(f"Failed to unpack secure packet step({step})", error=e, block="UNPACK", level="ERROR")


    def has_verified_identity(self) -> bool:
        """Returns True if the packet has a Matrix-verified identity."""
        r = False
        try:
            uuid = self._decrypted_packet.get("identity").get("identity").get("universal_id").strip()
            if uuid:
                r = True
        except Exception as e:

            self.log(f"{self._decrypted_packet}", error=e, block="UNPACK", level="ERROR")
            pass

        return r

    def get_sender_uid(self) -> str:
        """Returns the universal_id (agent ID) of the sender if verified, else raises or returns None."""
        r = None
        try:

            r = self._decrypted_packet.get("identity").get("identity").get("universal_id").strip()

        except Exception as e:
            pass

        return r

    def is_sender_allowed(self) -> bool:
        """
        Checks if the sender's universal_id is in the allowlist.
        If the allowlist is empty, allow all verified senders.
        """
        if not self.has_verified_identity():
            return False

        sender_id = self.get_sender_uid()

        if not sender_id:
            return False

        # Skip enforcement if allowlist is empty
        if not self.allowed_sender_ids:
            return True

        if sender_id not in self.allowed_sender_ids:
            return False

        return True

    def is_authorized_for(self, action: str) -> bool:
        """
        Checks if the decrypted sender has permission to execute a given action.
        """
        if not self.has_verified_identity():
            return False

        sender_id = self.get_sender_uid()
        if not sender_id:
            return False

        #return "ALL" in allowed_actions or action in allowed_actions

    def decrypt_private_key(self, encrypted_b64: str, privkey_pem: str) -> str:

        rsa_key = RSA.import_key(privkey_pem.encode())

        cipher_rsa = PKCS1_OAEP.new(rsa_key)

        decrypted_bytes = cipher_rsa.decrypt(base64.b64decode(encrypted_b64))

        # Re-encode to base64 string so it's compatible with rest of the pipeline
        return base64.b64encode(decrypted_bytes).decode()

    def encrypt_packet(
            self,
            raw_payload: dict,
            aes_key_b64: str,
            encrypt_aes_key_using_target_pubkey: bool = False,
            aes_encryption_pubkey: str = ""
    ) -> dict:
        """
        Encrypts a raw packet using AES-GCM. Optionally wraps AES key using target's RSA public key.

        Returns a JSON-safe encrypted_blob structure with optional encrypted_aes_key field.
        """

        try:
            # Validate payload structure
            if not isinstance(raw_payload, dict):
                raise ValueError("Payload must be a dictionary.")

            # Decode AES key
            aes_key = base64.b64decode(aes_key_b64)
            if len(aes_key) not in (16, 24, 32):
                raise ValueError("Invalid AES key length. Must be 16, 24, or 32 bytes.")

            # Prepare payload wrapper
            wrapper = {
                "timestamp": int(time.time()),
                "subpacket": raw_payload
            }

            # Encrypt the wrapper using AES-GCM
            nonce = get_random_bytes(12)
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(json.dumps(wrapper, sort_keys=True).encode())

            # Build encrypted_blob structure
            encrypted_blob = {
                "type": "encrypted_blob",
                "cipher": "AES-GCM",
                "encoding": "base64",
                "timestamp": int(time.time()),
                "nonce": base64.b64encode(nonce).decode(),
                "tag": base64.b64encode(tag).decode(),
                "payload": base64.b64encode(ciphertext).decode()
            }

            # Optionally encrypt the AES key with recipient's RSA pubkey
            if encrypt_aes_key_using_target_pubkey:
                if not aes_encryption_pubkey:
                    raise ValueError("Public key required for AES key encryption.")
                if isinstance(aes_key, str):
                    aes_key = base64.b64decode(aes_key)
                rsa_cipher = PKCS1_OAEP.new(RSA.import_key(aes_encryption_pubkey))
                encrypted_key = rsa_cipher.encrypt(aes_key)
                encrypted_blob["encrypted_aes_key"] = base64.b64encode(encrypted_key).decode()

            return encrypted_blob

        except Exception as e:
            self.log(error=e, block="ENCRYPT_PACKET", level="ERROR")
            raise


    def decrypt_packet(self,
                       blob: dict,
                       aes_key_b64: str,
                       ) -> dict:

        if blob.get("type") != "encrypted_blob":
            raise ValueError("Unsupported or unrecognized packet type.")

        aes_key = base64.b64decode(aes_key_b64)
        nonce = base64.b64decode(blob["nonce"])
        tag = base64.b64decode(blob["tag"])
        ciphertext = base64.b64decode(blob["payload"])

        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        payload = json.loads(decrypted.decode())

        # Return only the original subpacket by default, or return the whole payload if preferred
        return payload

    def sign_payload(self, payload: SigPayload, private_key) -> str:
        """
        Sign a JSON payload with a private key using PKCS1 v1.5 and SHA256.
        Returns a base64-encoded signature.
        """
        payload_bytes = payload.get_payload()
        digest = SHA256.new(payload_bytes)
        signature = pkcs1_15.new(private_key).sign(digest)
        return base64.b64encode(signature).decode()

    def verify_payload(self, payload: SigPayload, public_key, signature_b64: str) -> bool:
        """
        Verify a signed JSON payload with a public key.
        Returns True if valid, raises exception on failure.
        """
        try:

            rsa_key = RSA.import_key(public_key.encode())

            if not rsa_key:
                raise ValueError("Verifier key not set")

            signature = base64.b64decode(signature_b64)
            payload_bytes = payload.get_payload()
            digest = SHA256.new(payload_bytes)
            pkcs1_15.new(rsa_key).verify(digest, signature)
            if self.debug.is_enabled():
                self.log("Signature verified successfully", block="BL_VERIFY", level="INFO")

            return True

        except Exception as e:
            self.log("Signature verification failed", error=e, block="BL_VERIFY", level="ERROR")
            return False

    def canonical_json(obj):
        """
        Canonical JSON serializer: compact, ordered, no random whitespace or key ordering differences.
        """
        return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)