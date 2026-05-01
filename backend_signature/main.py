from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from signature_logic import SignatureService
import json
import base64

app = FastAPI()
service = SignatureService()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/sign")
async def sign_file(file: UploadFile = File(...), sig: str = "rsa-pss", hash: str = "sha256"):
    content = await file.read()
    try:
        meta = service.build_metadata(filename=file.filename or "file", data=content, sig_algo=sig, hash_name=hash)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return meta

@app.post("/verify")
async def verify_file(
    file: UploadFile = File(...),
    metadata: UploadFile = File(...)
):
    file_bytes = await file.read()
    meta_bytes = await metadata.read()
    try:
        meta = json.loads(meta_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid metadata JSON")

    required = ["public_key_pem", "signature_hex", "algo"]
    if not all(k in meta for k in required):
        raise HTTPException(status_code=400, detail="Metadata missing required fields")

    algo = meta.get("algo") or {}
    sig_algo = (algo.get("signature") or "RSA-PSS").lower()
    hash_name = algo.get("hash") or "sha256"
    ok = service.verify(
        file_bytes,
        signature_hex=meta["signature_hex"],
        public_key_pem=meta["public_key_pem"],
        sig_algo=sig_algo,
        hash_name=hash_name
    )
    return {"valid": ok}

@app.post("/demo/weak-hash")
async def demo_weak_hash(file: UploadFile = File(...)):
    data = await file.read()
    return {
        "filename": file.filename,
        "weak_hash_sum256": service.weak_hash_sum256(data),
        "bytes_len": len(data),
    }

@app.post("/demo/weak-hash/forge")
async def demo_weak_hash_forge(file: UploadFile = File(...)):
    original = await file.read()
    forged = service.forge_same_weak_hash(original)
    return {
        "filename": file.filename,
        "original": {
            "weak_hash_sum256": service.weak_hash_sum256(original),
            "bytes_len": len(original),
        },
        "forged": {
            "weak_hash_sum256": service.weak_hash_sum256(forged),
            "bytes_len": len(forged),
        },
        "forged_file_b64": base64.b64encode(forged).decode(),
        "explain": "Файл изменён (добавлены байты 01 FF), но weak_hash = sum(bytes) mod 256 не изменился. Это демонстрирует уязвимость слабого хеша."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)