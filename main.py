from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from analyzer import analyze_trace
from pcap_parser import analyze_pcap  

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # o ["http://localhost:4200", "http://127.0.0.1:4200"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health():
    return {"status": "API running"}

@app.post("/analyze-trace")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()
    try:
        result = analyze_trace(content)  
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"XML parsing failed: {e}")

@app.post("/analyze-pcap")
async def analyze_pcap_file(file: UploadFile = File(...)):
    content = await file.read()
    try:
        result = analyze_pcap(content)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"PCAP parsing failed: {e}")

import os

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
