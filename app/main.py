"""Web API for the review agent.

    uvicorn app.main:app --reload          # local dev
    docker build -t reviewagent . && docker run -p 7860:7860 reviewagent

Endpoints:
    GET  /            -> demo frontend
    POST /api/review  -> {"code": "...", "old_code": "..."} -> findings + trace
    GET  /health      -> liveness probe
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from reviewagent import review

MAX_CODE_BYTES = 100_000
RATE_LIMIT = 30          # requests
RATE_WINDOW = 60         # per seconds, per client
STATIC = Path(__file__).parent / "static"

app = FastAPI(title="Autonomous Code Review Agent", version="0.1.0")
_hits: dict[str, deque] = defaultdict(deque)


class ReviewRequest(BaseModel):
    code: str = Field(..., description="Python source to review")
    old_code: str | None = Field(None, description="Previous version (enables API-contract checks)")
    filename: str = Field("snippet.py", max_length=120)


def _rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(429, "Rate limit exceeded — try again in a minute.")
    q.append(now)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/review")
def api_review(req: ReviewRequest, request: Request):
    _rate_limit(request)
    if len(req.code.encode()) > MAX_CODE_BYTES:
        raise HTTPException(413, f"Code exceeds {MAX_CODE_BYTES // 1000}KB limit.")
    files = [{"path": req.filename, "source": req.code}]
    if req.old_code:
        if len(req.old_code.encode()) > MAX_CODE_BYTES:
            raise HTTPException(413, "Old version exceeds size limit.")
        files[0]["old_source"] = req.old_code
    try:
        result = review(files)
    except Exception:
        raise HTTPException(422, "Could not analyze this input — is it valid Python?")
    return JSONResponse(result)
