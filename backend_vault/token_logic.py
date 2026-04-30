import time
import uuid

class TokenManager:
    def __init__(self):
        self.tokens = {}

    def create_wrapped_token(self, secret_data, ttl_seconds=60):
        token = str(uuid.uuid4())
        expire_at = time.time() + ttl_seconds
        self.tokens[token] = {"data": secret_data, "expires": expire_at}
        return token

    def unwrap_token(self, token):
        if token not in self.tokens:
            return None
        t_data = self.tokens.pop(token)
        if time.time() > t_data["expires"]:
            return "Expired"
        return t_data["data"]