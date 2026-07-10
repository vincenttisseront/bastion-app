"""FastAPI entrypoint — Phase 1 skeleton."""

from fastapi import FastAPI

app = FastAPI(title="bastion-app", version="0.1.0")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
