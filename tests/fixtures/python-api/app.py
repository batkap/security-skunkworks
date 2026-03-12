from fastapi import FastAPI

app = FastAPI()
SECRET_KEY = "very-secret-token-value"


@app.get("/health")
def health():
    return {"ok": True, "secret_loaded": bool(SECRET_KEY)}

