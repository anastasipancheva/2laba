import os
import base64
from cryptography.fernet import Fernet

class MasterKeyManager:
    def split_master_key(self):
        master_key = Fernet.generate_key()
        part1 = os.urandom(len(master_key))
        part2 = bytes(a ^ b for a, b in zip(master_key, part1))
        return base64.b64encode(part1).decode(), base64.b64encode(part2).decode()

    def recover_master_key(self, p1_str, p2_str):
        p1 = base64.b64decode(p1_str)
        p2 = base64.b64decode(p2_str)
        master_key = bytes(a ^ b for a, b in zip(p1, p2))
        return master_key