from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import base64
import time

class SignatureService:
    def __init__(self):
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        self.ed_private_key = ed25519.Ed25519PrivateKey.generate()
        self.ed_public_key = self.ed_private_key.public_key()

    def _get_hash(self, hash_name: str):
        name = (hash_name or "sha256").lower()
        if name == "sha256":
            return hashes.SHA256()
        if name == "sha512":
            return hashes.SHA512()
        raise ValueError("Unsupported hash algorithm")

    def _get_sig_algo(self, sig_algo: str) -> str:
        name = (sig_algo or "rsa-pss").lower()
        if name in ("rsa-pss", "rsa_pss", "rsa"):
            return "rsa-pss"
        if name in ("ed25519", "ed"):
            return "ed25519"
        raise ValueError("Unsupported signature algorithm")

    def sign(self, data: bytes, *, sig_algo: str = "rsa-pss", hash_name: str = "sha256") -> str:
        algo = self._get_sig_algo(sig_algo)
        if algo == "ed25519":
            return self.ed_private_key.sign(data).hex()

        h = self._get_hash(hash_name)
        signature = self.rsa_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(h),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            h
        )
        return signature.hex()

    def verify(self, data: bytes, signature_hex: str, public_key_pem: str, *, sig_algo: str = "rsa-pss", hash_name: str = "sha256") -> bool:
        algo = self._get_sig_algo(sig_algo)
        pub = load_pem_public_key(public_key_pem.encode())
        try:
            if algo == "ed25519":
                pub.verify(bytes.fromhex(signature_hex), data)
            else:
                h = self._get_hash(hash_name)
                pub.verify(
                    bytes.fromhex(signature_hex),
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(h),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    h
                )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def get_public_key(self, *, sig_algo: str = "rsa-pss") -> str:
        algo = self._get_sig_algo(sig_algo)
        pub = self.ed_public_key if algo == "ed25519" else self.rsa_public_key
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def build_metadata(self, *, filename: str, data: bytes, sig_algo: str = "rsa-pss", hash_name: str = "sha256") -> dict:
        algo = self._get_sig_algo(sig_algo)
        signature_hex = self.sign(data, sig_algo=algo, hash_name=hash_name)
        file_b64 = base64.b64encode(filename.encode("utf-8")).decode()
        meta_algo = {"signature": algo.upper()}
        if algo == "rsa-pss":
            meta_algo["hash"] = (hash_name or "sha256").lower()
        return {
            "meta_version": 1,
            "type": "signature-metadata",
            "filename_b64": file_b64,
            "timestamp": int(time.time()),
            "algo": meta_algo,
            "public_key_pem": self.get_public_key(sig_algo=algo),
            "signature_hex": signature_hex
        }

    # ---- Weak hash demo (bonus) ----
    def weak_hash_sum256(self, data: bytes) -> int:
        return sum(data) % 256

    def forge_same_weak_hash(self, original: bytes) -> bytes:
        """
        Creates a different byte string with the same weak hash.
        Since weak_hash = sum(bytes) mod 256, appending bytes with sum 0 mod 256 keeps the hash.
        """
        forged = original + bytes([1, 255])  # +256 => +0 mod 256
        if forged == original:
            # practically impossible, but keep it safe
            forged = original + bytes([0])
        return forged