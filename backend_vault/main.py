from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from security_core import MasterKeyManager
from token_logic import TokenManager
from cryptography.fernet import Fernet
import json
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

master_manager = MasterKeyManager()
token_manager = TokenManager()

vault_state = {
    "is_sealed": True,
    "master_key": None,
    "db_path": "vault_storage.json"
}

if not os.path.exists(vault_state["db_path"]):
    with open(vault_state["db_path"], "w") as f:
        json.dump({}, f)

@app.post("/unseal")
async def unseal(parts: dict):
    try:
        recovered_key = master_manager.recover_master_key(parts["part1"], parts["part2"])
        vault_state["master_key"] = recovered_key
        vault_state["is_sealed"] = False
        return {"status": "Vault unsealed"}
    except:
        raise HTTPException(status_code=400, detail="Invalid key parts")

@app.post("/secrets")
async def store_secret(payload: dict):
    if vault_state["is_sealed"]:
        raise HTTPException(status_code=401, detail="Vault is sealed")
    
    key = payload["key"]
    value = payload["value"]
    
    cipher = Fernet(vault_state["master_key"])
    encrypted_value = cipher.encrypt(value.encode()).decode()
    
    with open(vault_state["db_path"], "r+") as f:
        data = json.load(f)
        data[key] = encrypted_value
        f.seek(0)
        json.dump(data, f)
        f.truncate()
    
    return {"status": "Secret stored"}

@app.get("/secrets/{key}")
async def get_secret(key: str):
    if vault_state["is_sealed"]:
        raise HTTPException(status_code=401, detail="Vault is sealed")
    
    with open(vault_state["db_path"], "r") as f:
        data = json.load(f)
        if key not in data:
            raise HTTPException(status_code=404, detail="Not found")
        
        cipher = Fernet(vault_state["master_key"])
        decrypted_value = cipher.decrypt(data[key].encode()).decode()
        return {"key": key, "value": decrypted_value}

@app.post("/wrap/{key}")
async def wrap_secret(key: str):
    secret = await get_secret(key)
    token = token_manager.create_wrapped_token(secret["value"])
    return {"token": token, "ttl": "60s"}

@app.post("/unwrap")
async def unwrap_secret(payload: dict):
    result = token_manager.unwrap_token(payload["token"])
    if not result:
        raise HTTPException(status_code=404, detail="Token not found")
    if result == "Expired":
        raise HTTPException(status_code=410, detail="Token expired")
    return {"value": result}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)