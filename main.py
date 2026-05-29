import asyncio
import json
import io
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner import MODULES

app = FastAPI(title="WRAITH — Hunt the Gaps")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_last_results: list[dict] = []
_scan_history: list[dict] = []          # lightweight summaries for sidebar

TEMPLATES_DIR = Path(__file__).parent / "templates"
ROOT_DIR = Path(__file__).parent

app.mount("/static", StaticFiles(directory=str(ROOT_DIR)), name="static")


class ScanRequest(BaseModel):
    url: str
    token: Optional[str] = ""
    checks: list[str] = list(MODULES.keys())


@app.get("/", response_class=HTMLResponse)
async def index():
    html = (TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html)


@app.post("/scan/stream")
async def scan_stream(req: ScanRequest):
    async def event_generator():
        global _last_results
        _last_results = []
        started_at = datetime.utcnow().isoformat()

        for check_name in req.checks:
            module_fn = MODULES.get(check_name)
            if not module_fn:
                continue

            yield f"data: {json.dumps({'type': 'progress', 'check': check_name, 'status': 'running'})}\n\n"

            findings = await asyncio.get_event_loop().run_in_executor(
                None, module_fn, req.url, req.token or ""
            )
            _last_results.extend(findings)

            for finding in findings:
                yield f"data: {json.dumps({'type': 'finding', 'check': check_name, 'finding': finding})}\n\n"

            yield f"data: {json.dumps({'type': 'progress', 'check': check_name, 'status': 'done'})}\n\n"

        # Store lightweight history entry
        _scan_history.append({
            "id": str(uuid.uuid4()),
            "url": req.url,
            "checks": req.checks,
            "timestamp": started_at,
            "total": len(_last_results),
            "critical": sum(1 for f in _last_results if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in _last_results if f.get("severity") == "HIGH"),
        })

        yield f"data: {json.dumps({'type': 'complete', 'total': len(_last_results)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


class ExportRequest(BaseModel):
    findings: list[dict] = []


@app.post("/export/json")
async def export_json(req: ExportRequest):
    findings = req.findings if req.findings else _last_results
    content = json.dumps({"findings": findings}, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=apisec_report.json"},
    )


@app.post("/export/pdf")
async def export_pdf(req: ExportRequest):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm

        findings = req.findings if req.findings else _last_results
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
        styles = getSampleStyleSheet()
        SEV_COLORS = {
            "CRITICAL": colors.HexColor("#dc2626"),
            "HIGH": colors.HexColor("#ea580c"),
            "MEDIUM": colors.HexColor("#d97706"),
            "LOW": colors.HexColor("#16a34a"),
            "INFO": colors.HexColor("#0891b2"),
        }
        story = []
        ts = ParagraphStyle("t", parent=styles["Title"], fontSize=20,
                            textColor=colors.HexColor("#06b6d4"))
        story.append(Paragraph("WRAITH — Security Hunt Report", ts))
        story.append(Spacer(1, 0.5 * cm))

        for f in findings:
            sev = f.get("severity", "INFO")
            sc = f.get("cvss_score", 0.0)
            ss = ParagraphStyle("s", parent=styles["Heading2"],
                                textColor=SEV_COLORS.get(sev, colors.grey), fontSize=11)
            story.append(Paragraph(
                f"[{sev}] {f['title']}  —  CVSS {sc}", ss
            ))
            story.append(Paragraph(f.get("description", ""), styles["Normal"]))
            if f.get("remediation"):
                rs = ParagraphStyle("r", parent=styles["Normal"],
                                    textColor=colors.HexColor("#6b7280"))
                story.append(Paragraph(f"Remediation: {f['remediation']}", rs))
            story.append(Spacer(1, 0.4 * cm))

        doc.build(story)
        buf.seek(0)
        return StreamingResponse(
            buf, media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=apisec_report.pdf"},
        )
    except ImportError:
        return JSONResponse(status_code=500,
                            content={"error": "reportlab not installed. Run: pip install reportlab"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
