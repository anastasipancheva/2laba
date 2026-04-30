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
    "db_path": "vault_storage.json",
    "key_parts": []
}

if not os.path.exists(vault_state["db_path"]):
    with open(vault_state["db_path"], "w") as f:
        json.dump({}, f)

@app.post("/unseal")
async def unseal(payload: dict):
    part = payload.get("key_part")
    if not part:
        raise HTTPException(status_code=400, detail="Missing key_part")
    
    if part not in vault_state["key_parts"]:
        vault_state["key_parts"].append(part)
    
    if len(vault_state["key_parts"]) >= 2:
        try:
            p1 = vault_state["key_parts"][0]
            p2 = vault_state["key_parts"][1]
            recovered_key = master_manager.recover_master_key(p1, p2)
            
            vault_state["master_key"] = recovered_key
            vault_state["is_sealed"] = False
            return {
                "status": "unsealed", 
                "keys_collected": len(vault_state["key_parts"])
            }
        except Exception:
            vault_state["key_parts"] = []
            raise HTTPException(status_code=400, detail="Invalid key parts combination")
    
    return {
        "status": "unsealing", 
        "keys_collected": len(vault_state["key_parts"])
    }

@app.post("/secrets/{key}")
async def store_secret(key: str, payload: dict):
    if vault_state["is_sealed"]:
        raise HTTPException(status_code=401, detail="Vault is sealed")
    
    value = payload.get("value")
    if not value:
        raise HTTPException(status_code=400, detail="Value is required")
    
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

@app.post("/wrap")
async def wrap_data(payload: dict):
    data_to_wrap = payload.get("data")
    if not data_to_wrap:
        raise HTTPException(status_code=400, detail="No data to wrap")
    
    token = token_manager.create_wrapped_token(json.dumps(data_to_wrap))
    return {"token": token, "ttl": "60s"}

@app.post("/unwrap")
async def unwrap_secret(payload: dict):
    token = payload.get("token")
    result = token_manager.unwrap_token(token)
    if not result:
        raise HTTPException(status_code=404, detail="Token not found")
    if result == "Expired":
        raise HTTPException(status_code=410, detail="Token expired")
    return {"value": json.loads(result)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)