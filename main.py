"""
URL Security Scanner — FastAPI Application
SudoCorps | Digital Forensics & Automation

Routes:
  GET  /          → render the scanner UI
  POST /scan      → JSON API (accepts { "url": "..." })
  POST /scan/html → Jinja-rendered results (used by the UI form)
"""

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from scanner import full_scan, normalize_url

# ─── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("url_scanner")

# ─── App ──────────────────────────────────────────────────────────
app = FastAPI(
    title="URL Security Scanner",
    description="Lightweight cybersecurity URL analysis tool by SudoCorps.",
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


# ─── Request Model ────────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str


# ─── Routes ───────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the main scanner page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan")
async def scan_api(body: ScanRequest):
    """
    JSON API endpoint.
    Accepts: { "url": "https://example.com" }
    Returns: full scan report as JSON.
    """
    try:
        report = full_scan(body.url)
        return JSONResponse(content=report)
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": str(e)},
        )
    except Exception as e:
        logger.exception("Scan failed")
        return JSONResponse(
            status_code=500,
            content={"error": f"Internal scan error: {str(e)}"},
        )


# ─── Entrypoint ───────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
