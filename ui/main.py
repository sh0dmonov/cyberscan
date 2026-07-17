"""
FastAPI Web UI — Asosiy Ilova
================================
Starlette Jinja2Templates bypass qilingan — to'g'ridan-to'g'ri jinja2 ishlatiladi.
"""
import asyncio
import json
import logging
from pathlib import Path
from typing import AsyncGenerator

import jinja2
from markupsafe import Markup
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from agent.config import settings
from agent.models.database import init_db, get_db, AsyncSessionLocal
from agent.models.finding import ScanSession, Finding, ScanStatus, ScanDepth
from agent.orchestrator import Orchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent

# ── Jinja2 to'g'ridan-to'g'ri (Starlette bypass) ──────────────────────────
_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(BASE_DIR / "templates")),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
    auto_reload=True,
)
_env.filters["tojson"] = lambda v, **kw: Markup(
    json.dumps(v, ensure_ascii=False, default=str, **kw)
)


def render(template_name: str, **context) -> HTMLResponse:
    """Template'ni render qilib HTMLResponse qaytaradi."""
    tmpl = _env.get_template(template_name)
    return HTMLResponse(content=tmpl.render(**context))


# ── FastAPI ilovasi ────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    logger.info("WebAuditAgent ishga tushdi ✓")
    yield
    logger.info("WebAuditAgent to'xtatildi")


app = FastAPI(
    title="WebAuditAgent",
    description="Web Application Security Audit — Faqat ruxsat etilgan maqsadlar uchun",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Faol scan progresslari
_active_scans: dict = {}


# ──────────────────────────────────────────────────────────────────────────
# SAHIFALAR
# ──────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanSession).order_by(desc(ScanSession.created_at)).limit(10)
    )
    recent_sessions = result.scalars().all()
    return render("index.html",
        recent_sessions=recent_sessions,
        legal_notice=(
            "Ushbu vosita faqat sizga tegishli yoki yozma ruxsat olingan "
            "tizimlarni tekshirish uchun mo'ljallangan. "
            "Ruxsatsiz skanerlash qonun bilan taqiqlanadi."
        )
    )


@app.post("/scan/start")
async def start_scan(
    request: Request,
    target_url: str = Form(...),
    scan_depth: str = Form(default="standard"),
    user_consent: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
):
    if not user_consent:
        raise HTTPException(status_code=400, detail="Ruxsatnomani tasdiqlang.")

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Noto'g'ri URL format")

    if scan_depth not in ("quick", "standard", "deep"):
        scan_depth = "standard"

    session = ScanSession(
        target_url=target_url,
        target_domain=parsed.netloc,
        scan_depth=ScanDepth(scan_depth),
        user_consent=True,
        user_ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", ""),
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    asyncio.create_task(
        _run_scan_background(session.id, target_url, scan_depth)
    )
    return RedirectResponse(f"/scan/{session.id}", status_code=303)


@app.get("/scan/{session_id}", response_class=HTMLResponse)
async def scan_status(
    request: Request,
    session_id: int,
    db: AsyncSession = Depends(get_db),
):
    session = await db.get(ScanSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session topilmadi")

    result = await db.execute(
        select(Finding)
        .where(Finding.session_id == session_id)
        .where(Finding.false_positive == False)
        .order_by(Finding.cvss_score.desc())
    )
    findings = result.scalars().all()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return render("results.html",
        session=session,
        findings=findings,
        severity_counts=severity_counts,
        total_findings=len(findings),
    )


@app.get("/scan/{session_id}/progress")
async def scan_progress(session_id: int):
    async def event_gen() -> AsyncGenerator[str, None]:
        while True:
            data = _active_scans.get(session_id, {
                "message": "Kutilmoqda...", "percent": 0, "status": "running"
            })
            yield f"data: {json.dumps(data)}\n\n"
            if data.get("status") in ("completed", "failed"):
                break
            await asyncio.sleep(1)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@app.get("/sessions", response_class=HTMLResponse)
async def sessions_list(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanSession).order_by(desc(ScanSession.created_at)).limit(50)
    )
    sessions = result.scalars().all()
    return render("sessions.html", sessions=sessions)


@app.get("/api/session/{session_id}/findings")
async def api_findings(session_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.session_id == session_id)
    )
    return [f.to_dict() for f in result.scalars().all()]


# ──────────────────────────────────────────────────────────────────────────
# BACKGROUND SCAN
# ──────────────────────────────────────────────────────────────────────────

async def _run_scan_background(session_id: int, target_url: str, scan_depth: str):
    _active_scans[session_id] = {
        "message": "Boshlanyapti...", "percent": 0, "status": "running"
    }

    async def progress(msg: str, pct: int):
        _active_scans[session_id] = {
            "message": msg, "percent": pct, "status": "running"
        }

    try:
        async with AsyncSessionLocal() as db:
            orch = Orchestrator(db)
            await orch.run_scan(
                session_id=session_id,
                target_url=target_url,
                scan_depth=scan_depth,
                progress_callback=progress,
            )
        _active_scans[session_id] = {
            "message": "✅ Scan yakunlandi!", "percent": 100, "status": "completed"
        }
    except Exception as e:
        logger.error(f"Scan xato: {e}", exc_info=True)
        _active_scans[session_id] = {
            "message": f"❌ Xato: {str(e)[:100]}", "percent": 0, "status": "failed"
        }
