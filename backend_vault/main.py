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
    "key_parts": [],
    "is_initialized": False
}

if not os.path.exists(vault_state["db_path"]):
    with open(vault_state["db_path"], "w") as f:
        json.dump({}, f)

@app.post("/init")
async def init_vault():
    """
    Generates a new master key and returns 2 key parts.
    The master key is NOT stored; it can only be reconstructed from both parts.
    """
    if vault_state["is_initialized"]:
        raise HTTPException(status_code=409, detail="Vault already initialized")
    if not vault_state["is_sealed"] or vault_state["master_key"] is not None:
        raise HTTPException(status_code=409, detail="Vault must be sealed before init")

    master_material = master_manager.generate_master_key_material()
    part1, part2 = master_manager.split_master_key(master_material)
    vault_state["key_parts"] = []
    vault_state["is_initialized"] = True

    return {
        "status": "initialized",
        "required_parts": 2,
        "part1": part1,
        "part2": part2
    }

@app.post("/seal")
async def seal_vault():
    vault_state["is_sealed"] = True
    vault_state["master_key"] = None
    vault_state["key_parts"] = []
    return {"status": "sealed"}

@app.post("/unseal")
async def unseal(payload: dict):
    if not vault_state["is_initialized"]:
        raise HTTPException(status_code=409, detail="Vault is not initialized. Call /init first.")

    part = payload.get("key_part")
    if not part:
        raise HTTPException(status_code=400, detail="Missing key_part")
    
    if part not in vault_state["key_parts"]:
        vault_state["key_parts"].append(part)
    
    if len(vault_state["key_parts"]) >= 2:
        try:
            p1 = vault_state["key_parts"][0]
            p2 = vault_state["key_parts"][1]
            recovered_material = master_manager.recover_master_key_material(p1, p2)
            recovered_fernet_key = master_manager.to_fernet_key(recovered_material)
            vault_state["master_key"] = recovered_fernet_key
            vault_state["is_sealed"] = False
            return {
                "status": "unsealed", 
                "keys_collected": len(vault_state["key_parts"])
            }
        except HTTPException:
            raise
        except Exception:
            vault_state["key_parts"] = []
            raise HTTPException(status_code=400, detail="Invalid key parts. Make sure you copied both parts exactly.")
    
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
    if vault_state["is_sealed"]:
        raise HTTPException(status_code=401, detail="Vault is sealed")

    secret = payload.get("secret")
    if secret is None:
        raise HTTPException(status_code=400, detail="Missing secret")

    cipher = Fernet(vault_state["master_key"])
    ciphertext = cipher.encrypt(str(secret).encode()).decode()
    token = token_manager.create_wrapped_token(ciphertext)
    return {"token": token, "ttl": "60s"}

@app.post("/unwrap")
async def unwrap_secret(payload: dict):
    if vault_state["is_sealed"]:
        raise HTTPException(status_code=401, detail="Vault is sealed")

    token = payload.get("token")
    result = token_manager.unwrap_token(token)
    if not result:
        raise HTTPException(status_code=404, detail="Token not found")
    if result == "Expired":
        raise HTTPException(status_code=410, detail="Token expired")
    cipher = Fernet(vault_state["master_key"])
    try:
        plaintext = cipher.decrypt(result.encode()).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token payload")
    return {"value": plaintext}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)