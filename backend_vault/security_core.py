import os
import base64

class MasterKeyManager:
    def generate_master_key_material(self) -> bytes:
        # 32 bytes -> Fernet key via urlsafe_b64encode (44 bytes)
        return os.urandom(32)

    def to_fernet_key(self, master_key_material: bytes) -> bytes:
        return base64.urlsafe_b64encode(master_key_material)

    def split_master_key(self, master_key_material: bytes):
        part1 = os.urandom(len(master_key_material))
        part2 = bytes(a ^ b for a, b in zip(master_key_material, part1))
        return base64.b64encode(part1).decode(), base64.b64encode(part2).decode()

    def recover_master_key_material(self, p1_str, p2_str) -> bytes:
        # tolerate whitespace/newlines from copy-paste
        p1_clean = (p1_str or "").strip().replace("\n", "").replace("\r", "").replace(" ", "")
        p2_clean = (p2_str or "").strip().replace("\n", "").replace("\r", "").replace(" ", "")
        p1 = base64.b64decode(p1_clean)
        p2 = base64.b64decode(p2_clean)
        if len(p1) != len(p2) or len(p1) != 32:
            raise ValueError("Invalid key parts length")
        return bytes(a ^ b for a, b in zip(p1, p2))