from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from signature_logic import SignatureService

app = FastAPI()
service = SignatureService()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/sign")
async def sign_file(file: UploadFile = File(...), algorithm: str = "strong"):
    content = await file.read()
    
    if algorithm == "weak":
        signature = service.sign_weak(content)
    else:
        signature = service.sign_strong(content)
        
    return {
        "filename": file.filename,
        "algorithm": algorithm,
        "signature": signature,
        "public_key": service.get_public_key()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)