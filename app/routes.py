"""Flask routes — operator console, streaming scan engine, report delivery."""

from __future__ import annotations

import os
import re
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Blueprint, jsonify, redirect,
    render_template, request, send_file, session, url_for,
)

from app.modules.dns_check import check_domain
from app.modules.report_builder import build_report
from app.modules.scanner import find_nmap, run_scan_streaming, validate_target

bp = Blueprint("main", __name__)

# Advanced console password. Works out-of-the-box with the default below; set
# the SOUN_ADVANCED_PASSWORD environment variable to override per-deployment.
# This gate only protects a local (127.0.0.1) console on the operator's own
# machine — it is a convenience lock, not a security boundary.
ADVANCED_PASSWORD = os.environ.get("SOUN_ADVANCED_PASSWORD", "Tmppassword")

_jobs: dict[str, dict] = {}

# Set once a self-wipe has started, so a double-click can't trigger a second
# export/delete or a second shutdown.
_wiping = False


def _advanced_unlocked() -> bool:
    return bool(session.get("advanced_ok"))

# Reports must live in a PERSISTENT location. In a frozen .exe, __file__ points
# inside PyInstaller's volatile _MEIPASS temp dir (auto-deleted on exit), so we
# anchor next to the executable instead. In source runs, use the project root.
if getattr(sys, "frozen", False):
    _BASE_DIR = Path(sys.executable).resolve().parent
else:
    _BASE_DIR = Path(__file__).resolve().parent.parent
_REPORTS_DIR = _BASE_DIR / "reports"
_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

if sys.platform == "darwin":
    _brew_lib = "/opt/homebrew/lib"
    existing = os.environ.get("DYLD_LIBRARY_PATH", "")
    if _brew_lib not in existing:
        os.environ["DYLD_LIBRARY_PATH"] = f"{_brew_lib}:{existing}" if existing else _brew_lib


def _safe_name(value: str) -> str:
    return re.sub(r"[^\w\s\-.]", "", value)[:80].strip()


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


# ── Landing gate ──────────────────────────────────────────────────────────────

@bp.get("/")
def landing():
    return render_template("landing.html", unlocked=_advanced_unlocked())


@bp.post("/unlock")
def unlock():
    pw = request.form.get("password", "")
    if pw == ADVANCED_PASSWORD:
        session["advanced_ok"] = True
        return redirect(url_for("main.advanced"))
    return render_template("landing.html", unlocked=False, error="Incorrect password.")


@bp.get("/lock")
def lock():
    session.pop("advanced_ok", None)
    return redirect(url_for("main.landing"))


# ── Advanced console (password-protected) ─────────────────────────────────────

@bp.get("/advanced")
def advanced():
    if not _advanced_unlocked():
        return redirect(url_for("main.landing"))
    nmap_found = bool(find_nmap())
    from app.modules.netinfo import detect
    try:
        net = detect()
    except Exception:
        net = None
    recent = [
        {"id": jid, "client_name": j["client_name"], "target": j["target"],
         "profile": j["profile"], "status": j["status"]}
        for jid, j in list(_jobs.items())[-6:]
        if j["status"] == "done" and j.get("mode") != "free"
    ][::-1]
    return render_template("index.html", nmap_found=nmap_found, net=net, recent=recent)


# ── Engineer workspace (Advanced only) ────────────────────────────────────────

@bp.get("/workspace/<job_id>")
def workspace(job_id: str):
    if not _advanced_unlocked():
        return redirect(url_for("main.landing"))
    job = _jobs.get(job_id)
    if not job or job.get("mode") == "free":
        return redirect(url_for("main.advanced"))
    rd = job.get("report_data")
    from app.modules.workspace import ACTIONS
    hosts = []
    if rd is not None:
        for h in getattr(rd, "host_rows", []):
            hosts.append({"ip": h.ip, "device": h.device_type, "risk": h.risk,
                          "ports": h.ports, "is_gateway": h.is_gateway})
    findings = []
    if rd is not None:
        triage = job.get("triage", {})
        overrides = job.get("severity_overrides", {})
        from app.modules.workspace import finding_key
        for f in rd.findings:
            k = finding_key(f.host, f.port, f.title)
            findings.append({"key": k, "title": f.title, "host": f.host, "port": f.port,
                             "risk": f.risk, "state": triage.get(k, ""),
                             "overridden": k in overrides,
                             "original_risk": getattr(f, "original_risk", "")})
    return render_template("workspace.html", job_id=job_id, job=job,
                           hosts=hosts, findings=findings, actions=ACTIONS,
                           manual=job.get("manual_findings", []))


@bp.post("/workspace/<job_id>/action")
def workspace_action(job_id: str):
    if not _advanced_unlocked():
        return jsonify({"error": "locked"}), 403
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "no job"}), 404
    ip = request.form.get("ip", "").strip()[:45]
    action = request.form.get("action", "").strip()[:20]
    from app.modules.workspace import host_in_scope, run_action
    if not host_in_scope(job, ip):
        return jsonify({"error": "Host not in scope for this assessment."}), 400
    return jsonify(run_action(ip, action))


@bp.post("/workspace/<job_id>/triage")
def workspace_triage(job_id: str):
    if not _advanced_unlocked():
        return jsonify({"error": "locked"}), 403
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "no job"}), 404
    from app.modules.workspace import set_triage
    key = request.form.get("key", "")
    state = request.form.get("state", "")
    ok = set_triage(job, key, state)
    return jsonify({"ok": ok, "key": key, "state": state})


@bp.post("/workspace/<job_id>/manual")
def workspace_manual(job_id: str):
    if not _advanced_unlocked():
        return jsonify({"error": "locked"}), 403
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "no job"}), 404
    from app.modules.workspace import add_manual_finding
    add_manual_finding(
        job,
        request.form.get("title", ""),
        request.form.get("host", ""),
        request.form.get("risk", "medium"),
        request.form.get("detail", ""),
    )
    return jsonify({"ok": True})


# ── Manual severity override (Advanced only) ───────────────────────────────────

def _rerender_advanced_report(job, job_id, app):
    """Re-render the advanced report HTML+PDF after report_data changed (e.g. a
    severity override). Recomputes derived narrative bits so counts/score match."""
    rd = job.get("report_data")
    if rd is None:
        return
    # Refresh derived narrative/compliance that depend on findings + severity.
    try:
        from app.modules.compliance import map_findings
        from app.modules.runbook import build_runbook
        from app.modules.report_builder import _executive_summary
        if rd.findings:
            rd.compliance = map_findings(rd.findings)
            rd.runbook_steps = build_runbook(rd.findings)
        rd.executive_summary = _executive_summary(rd)
    except Exception:
        pass
    with app.app_context():
        html_content = render_template("report.html", r=rd)
    html_path = _REPORTS_DIR / f"{job_id}.html"
    html_path.write_text(html_content, encoding="utf-8")
    job["report_html"] = str(html_path)
    from app.modules.pdf import render_pdf, last_error
    pdf_path = _REPORTS_DIR / f"{job_id}.pdf"
    if render_pdf(html_content, pdf_path):
        job["report_pdf"] = str(pdf_path)
        job["pdf_error"] = ""
    else:
        job["report_pdf"] = None
        job["pdf_error"] = last_error()
    job["stats"]["findings"] = rd.total_findings
    job["stats"]["critical"] = rd.critical_count


@bp.post("/workspace/<job_id>/severity")
def workspace_severity(job_id: str):
    """Override a finding's severity, apply it to the report, and re-render."""
    if not _advanced_unlocked():
        return jsonify({"error": "locked"}), 403
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "no job"}), 404
    key = request.form.get("key", "")
    risk = request.form.get("risk", "").strip().lower()
    from app.modules.workspace import set_severity, apply_severity_overrides
    if not set_severity(job, key, risk):
        return jsonify({"error": "invalid severity"}), 400
    rd = job.get("report_data")
    if rd is not None:
        apply_severity_overrides(rd, job.get("severity_overrides", {}))
        from flask import current_app
        try:
            _rerender_advanced_report(job, job_id, current_app._get_current_object())
        except Exception as exc:
            return jsonify({"ok": True, "key": key, "risk": risk,
                            "warning": f"severity set but report re-render failed: {exc}"})
    return jsonify({"ok": True, "key": key, "risk": risk,
                    "critical": job.get("stats", {}).get("critical"),
                    "findings": job.get("stats", {}).get("findings")})


# ── Deploy a Fix (Advanced only) — generate reviewable, reversible fix scripts ──

def _job_findings(job):
    """Return the report Finding objects for a job, or []."""
    rd = job.get("report_data")
    return list(getattr(rd, "findings", [])) if rd is not None else []


def _connect_host(host: str) -> str:
    """Extract a bare connect target from a finding host that may read
    "HOSTNAME (10.0.0.5)" — return the IP in the parentheses, else the value
    as-is (stripped). Prevents trying to SSH/WinRM to "HOSTNAME (ip)"."""
    h = (host or "").strip()
    if "(" in h and h.endswith(")"):
        inner = h[h.rfind("(") + 1:-1].strip()
        if inner:
            return inner
    return h


def _find_fix(job, key):
    """Generate the FixScript for the finding matching `key`, or None."""
    from app.modules.workspace import finding_key
    from app.modules.fixgen import generate_fix
    domain = job.get("domain", "")
    for f in _job_findings(job):
        if finding_key(f.host, f.port, f.title) == key:
            return generate_fix(f, domain=domain)
    return None


@bp.get("/fix/<job_id>")
def fix_list(job_id: str):
    """JSON list of available fixes for a job's findings (Advanced only)."""
    if not _advanced_unlocked():
        return jsonify({"error": "locked"}), 403
    job = _jobs.get(job_id)
    if not job or job.get("mode") == "free":
        return jsonify({"error": "not available"}), 404
    from app.modules.workspace import finding_key
    from app.modules.fixgen import generate_fix
    from app.modules.fixrun import is_runnable, remote_available
    domain = job.get("domain", "")
    out = []
    for f in _job_findings(job):
        fx = generate_fix(f, domain=domain)
        if not fx:
            continue
        out.append({
            "key": finding_key(f.host, f.port, f.title),
            "title": fx.title, "finding": fx.finding_title, "host": fx.host,
            "port": fx.port, "platform": fx.platform, "language": fx.language,
            "summary": fx.summary, "steps": fx.steps, "warnings": fx.warnings,
            "note": fx.note, "fix_script": fx.fix_script, "rollback_script": fx.rollback_script,
            "location": fx.location, "run_hint": fx.run_hint,
            # execution metadata for the "Run the fix" UI
            "runnable": is_runnable(fx),
            # bare host to actually connect to (fx.host may read "NAME (ip)")
            "connect_host": _connect_host(fx.host),
            # sensible default remote login for the platform
            "default_user": "Administrator" if fx.platform == "windows" else "root",
        })
    return jsonify({"fixes": out, "count": len(out), "remote": remote_available()})


@bp.get("/fix/<job_id>/<kind>/<path:key>")
def fix_download(job_id: str, kind: str, key: str):
    """Download a fix or rollback script for a finding (Advanced only)."""
    if not _advanced_unlocked():
        return "Locked.", 403
    if kind not in ("fix", "rollback"):
        return "Unknown.", 404
    job = _jobs.get(job_id)
    if not job or job.get("mode") == "free":
        return "Not available.", 404
    fx = _find_fix(job, key)
    if not fx:
        return "No fix available for this finding.", 404
    content = fx.fix_script if kind == "fix" else fx.rollback_script
    fname = fx.fix_filename if kind == "fix" else fx.rollback_filename
    from flask import Response
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@bp.post("/fix/run/<job_id>/<path:key>")
def fix_run(job_id: str, key: str):
    """Execute a generated fix locally or on a remote host (Advanced only).

    Body (JSON): {mode: "local"|"remote", target?, username?, password?, key_text?}
    Credentials, when present, are used only to open the remote transport and are
    NEVER written to disk or logged. We do not echo them back; fixrun also scrubs
    them from any captured output as a backstop.
    """
    if not _advanced_unlocked():
        return jsonify({"ok": False, "error": "locked"}), 403
    job = _jobs.get(job_id)
    if not job or job.get("mode") == "free":
        return jsonify({"ok": False, "error": "not available"}), 404
    fx = _find_fix(job, key)
    if not fx:
        return jsonify({"ok": False, "error": "No fix available for this finding."}), 404

    data = request.get_json(silent=True) or {}
    mode = (data.get("mode") or "").strip()
    # Normalise the target so "NAME (ip)" can never reach the transport.
    target = _connect_host(data.get("target") or fx.host or "")
    username = (data.get("username") or "").strip()
    # Fall back to the platform default login if the operator left it blank
    # (and isn't using a key) — Administrator for Windows, root for Linux.
    if not username and not (data.get("key_text") or "").strip():
        username = "Administrator" if fx.platform == "windows" else "root"
    password = data.get("password") or ""        # not stripped — passwords may have edge whitespace
    key_text = data.get("key_text") or ""

    from app.modules.fixrun import run_fix
    try:
        result = run_fix(fx, mode=mode, target=target,
                         username=username, password=password, key_text=key_text)
    finally:
        # Drop the credential references as soon as the call returns. (Python may
        # keep them briefly until GC, but we never persist or log them anywhere.)
        password = key_text = ""
    # Attach the rollback download path so the operator can revert in one click.
    result["rollback_url"] = f"/fix/{job_id}/rollback/{key}"
    return jsonify(result)


@bp.get("/api/subnets")
def api_subnets():
    """Discover routed neighbouring subnets (slow ~10s — called async)."""
    from app.modules.netinfo import detect, discover_routed_subnets
    try:
        net = detect()
        subs = discover_routed_subnets(net.subnet)
        return jsonify({"subnets": subs, "local": net.subnet})
    except Exception as e:
        return jsonify({"subnets": [], "error": str(e)})


@bp.get("/api/netinfo")
def api_netinfo():
    """Live network auto-detect for the form (re-detect button)."""
    from app.modules.netinfo import detect
    try:
        net = detect()
        return jsonify({
            "subnet": net.subnet, "gateway": net.gateway,
            "public_ip": net.public_ip, "isp": net.isp,
            "asn": net.asn, "city": net.city, "country": net.country,
            "hostname": net.hostname,
        })
    except Exception as e:
        return jsonify({"error": str(e)})


# ── FREE scan ─────────────────────────────────────────────────────────────────

@bp.get("/free")
def free_form():
    nmap_found = bool(find_nmap())
    from app.modules.netinfo import detect
    try:
        net = detect()
    except Exception:
        net = None
    return render_template("free.html", nmap_found=nmap_found, net=net)


@bp.post("/free/scan")
def free_start():
    client_name = request.form.get("client_name", "").strip()[:100] or "Quick Scan"
    target = request.form.get("target", "").strip()[:50]

    errors: list[str] = []
    if not target:
        errors.append("Target subnet or IP is required.")
    else:
        valid, err = validate_target(target)
        if not valid:
            errors.append(err)
    if errors:
        from app.modules.netinfo import detect
        try:
            net = detect()
        except Exception:
            net = None
        return render_template("free.html", errors=errors, nmap_found=bool(find_nmap()),
                               net=net, client_name=client_name, target=target)

    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {
        "status": "running", "log": [], "mode": "free",
        "client_name": client_name, "domain": "", "target": target,
        "profile": "quick",
        "report_html": None, "report_pdf": None, "error": None,
        "stats": {"hosts": 0, "ports": 0, "findings": 0, "critical": 0},
    }
    from flask import current_app
    app = current_app._get_current_object()
    threading.Thread(target=_run_free_job, args=(job_id, app), daemon=True).start()
    return redirect(url_for("main.progress", job_id=job_id))


def _run_free_job(job_id: str, app) -> None:
    job = _jobs[job_id]
    client_name = job["client_name"]
    target = job["target"]

    def log(msg: str) -> None:
        job["log"].append(f"{_ts()}  {msg}")

    def raw(msg: str) -> None:
        job["log"].append(msg)

    try:
        log("╔══ SOUN RUNNER — FREE QUICK SCAN ══╗")
        log(f"Target: {target}")
        log("")
        log("[*] Host discovery & exposed-service check")
        scan_result = run_scan_streaming(target, "quick", log=raw, job_id=job_id)
        if scan_result.error:
            log(f"    Scan error: {scan_result.error}")
        else:
            ports = sum(len(h.open_ports) for h in scan_result.hosts)
            job["stats"]["hosts"] = scan_result.host_count
            job["stats"]["ports"] = ports
            log(f"    → {scan_result.host_count} host(s), {ports} open service(s)")
        log("")

        log("[*] Building reports (client + engineer)")
        from app.modules.free_report import build_free_report
        free = build_free_report(client_name, target, scan_result)
        job["stats"]["findings"] = free.total_findings
        job["stats"]["critical"] = free.critical_count
        log(f"    → {free.total_findings} exposed-service finding(s)")

        # Generate BOTH variants: client (plain language) + engineer (fix steps)
        from app.modules.pdf import render_pdf, last_error
        for variant in ("client", "engineer"):
            with app.app_context():
                html_content = render_template("free_report.html", r=free, variant=variant)
            html_path = _REPORTS_DIR / f"{job_id}_{variant}.html"
            html_path.write_text(html_content, encoding="utf-8")
            job[f"report_html_{variant}"] = str(html_path)
            pdf_path = _REPORTS_DIR / f"{job_id}_{variant}.pdf"
            if render_pdf(html_content, pdf_path):
                job[f"report_pdf_{variant}"] = str(pdf_path)
                log(f"    → {variant} report PDF generated")
            else:
                job["pdf_error"] = last_error()
                log(f"    {variant} PDF skipped: {last_error()}")

        # default report links point to the client report
        job["report_html"] = job.get("report_html_client")
        job["report_pdf"] = job.get("report_pdf_client")

        log("")
        log("╚══ FREE SCAN COMPLETE ══╝")
        job["status"] = "done"
    except Exception as exc:
        import traceback
        job["error"] = str(exc)
        job["status"] = "error"
        log(f"[!] {exc}")
        log(traceback.format_exc().splitlines()[-1])


# ── Re-scan pre-fill (GET) ────────────────────────────────────────────────────

@bp.get("/scan")
def rescan_prefill():
    """Pre-fill the console from a prior job for a verify/re-scan run."""
    rescan_id = request.args.get("rescan", "").strip()[:8]
    prior = _jobs.get(rescan_id)
    from app.modules.netinfo import detect
    try:
        net = detect()
    except Exception:
        net = None
    if not prior:
        return redirect(url_for("main.landing"))
    return render_template(
        "index.html", nmap_found=bool(find_nmap()), net=net, recent=_recent_jobs(),
        client_name=prior["client_name"], domain=prior["domain"],
        target=prior["target"], profile=prior["profile"], rescan_of=rescan_id,
    )


def _recent_jobs():
    return [
        {"id": jid, "client_name": j["client_name"], "target": j["target"],
         "profile": j["profile"], "status": j["status"]}
        for jid, j in list(_jobs.items())[-6:]
        if j["status"] == "done"
    ][::-1]


# ── Engineer field checklist ──────────────────────────────────────────────────

@bp.get("/checklist/<job_id>")
def checklist(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return redirect(url_for("main.landing"))
    from app.modules.engineer_modules import MODULES
    saved = job.get("engineer_answers", {})
    return render_template("checklist.html", job_id=job_id, job=job, modules=MODULES, saved=saved)


@bp.post("/checklist/<job_id>")
def save_checklist(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return redirect(url_for("main.landing"))
    # capture all engineer.* answers
    answers = {k: v for k, v in request.form.items() if "." in k}
    job["engineer_answers"] = answers
    # rebuild the report with engineer findings folded in
    from flask import current_app
    app = current_app._get_current_object()
    threading.Thread(target=_rebuild_with_engineer, args=(job_id, app), daemon=True).start()
    return redirect(url_for("main.progress", job_id=job_id))


def _rebuild_with_engineer(job_id: str, app) -> None:
    """Rebuild the report HTML/PDF folding in engineer checklist answers,
    WITHOUT re-running the network scan (uses the cached ReportData)."""
    job = _jobs[job_id]
    cached = job.get("report_data")
    if cached is None:
        # no cached scan — fall back to a full re-run
        _run_job(job_id, app)
        return

    job["log"].append(f"{_ts()}  [*] Folding engineer field-assessment into report …")
    try:
        from app.modules.engineer_modules import evaluate as eval_modules
        from app.modules.report_builder import Finding, RISK_ORDER
        answers = job.get("engineer_answers", {})

        # Remove any prior engineer findings, then re-add fresh ones
        cached.findings = [f for f in cached.findings if getattr(f, "category", "") != "engineer"]
        cached.engineer_results = eval_modules(answers)
        for mr in cached.engineer_results:
            for ef in mr.findings:
                cached.findings.append(Finding(
                    risk=ef["risk"], title=ef["title"], host=mr.title,
                    detail=ef["detail"], recommendation=ef["recommendation"],
                    category="engineer",
                ))
        cached.findings.sort(key=lambda f: RISK_ORDER.get(f.risk, 99))

        # rebuild compliance + runbook + executive summary to include new findings
        from app.modules.compliance import map_findings
        from app.modules.runbook import build_runbook
        from app.modules.report_builder import _executive_summary
        cached.compliance = map_findings(cached.findings)
        cached.runbook_steps = build_runbook(cached.findings)
        cached.executive_summary = _executive_summary(cached)

        with app.app_context():
            html_content = render_template("report.html", r=cached)
        html_path = _REPORTS_DIR / f"{job_id}.html"
        html_path.write_text(html_content, encoding="utf-8")
        job["report_html"] = str(html_path)
        from app.modules.pdf import render_pdf, last_error
        pdf_path = _REPORTS_DIR / f"{job_id}.pdf"
        if render_pdf(html_content, pdf_path):
            job["report_pdf"] = str(pdf_path)
            job["pdf_error"] = ""
        else:
            job["report_pdf"] = None   # don't point at a now-removed stale PDF
            job["pdf_error"] = last_error()
        job["stats"]["findings"] = cached.total_findings
        job["stats"]["critical"] = cached.critical_count
        job["log"].append(f"{_ts()}  [*] Report updated with field assessment.")
        job["status"] = "done"
    except Exception as exc:
        job["error"] = str(exc)
        job["status"] = "error"
        job["log"].append(f"{_ts()}  [!] Rebuild failed: {exc}")


# ── Start assessment ──────────────────────────────────────────────────────────

@bp.post("/scan")
def start_scan():
    if not _advanced_unlocked():
        return redirect(url_for("main.landing"))
    client_name = request.form.get("client_name", "").strip()[:100]
    domain      = request.form.get("domain", "").strip()[:100]
    target      = request.form.get("target", "").strip()[:50]
    profile     = request.form.get("profile", "standard")
    check_ssl   = request.form.get("check_ssl") == "1"
    check_cves  = request.form.get("check_cves") == "1"
    check_topo  = request.form.get("check_topo") == "1"
    check_deep  = request.form.get("check_deep") == "1"
    check_web   = request.form.get("check_web") == "1"
    check_compliance = request.form.get("check_compliance") == "1"
    check_cred  = request.form.get("check_cred") == "1"
    cred_auth   = request.form.get("cred_authorized") == "1"
    check_agent = request.form.get("check_agent") == "1"
    agent_resilience = request.form.get("agent_resilience") == "1"
    rescan_of   = request.form.get("rescan", "").strip()[:8]

    if profile not in ("quick", "standard", "thorough"):
        profile = "standard"

    # cred testing only runs with explicit authorization
    if check_cred and not cred_auth:
        check_cred = False

    errors: list[str] = []
    if not client_name:
        errors.append("Client name is required.")
    if not target:
        errors.append("Target subnet or IP is required.")
    else:
        valid, err = validate_target(target)
        if not valid:
            errors.append(err)

    if errors:
        from app.modules.netinfo import detect
        try:
            net = detect()
        except Exception:
            net = None
        return render_template("index.html", errors=errors, nmap_found=bool(find_nmap()),
                               net=net, client_name=client_name, domain=domain,
                               target=target, profile=profile)

    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {
        "status": "running", "log": [], "mode": "advanced",
        "client_name": client_name, "domain": domain,
        "target": target, "profile": profile,
        "check_ssl": check_ssl, "check_cves": check_cves, "check_topo": check_topo,
        "check_deep": check_deep, "check_web": check_web,
        "check_compliance": check_compliance, "check_cred": check_cred,
        "check_agent": check_agent, "agent_resilience": agent_resilience,
        "rescan_of": rescan_of,
        "report_html": None, "report_pdf": None, "error": None,
        "findings_snapshot": [],
        "stats": {"hosts": 0, "ports": 0, "findings": 0, "critical": 0},
    }

    from flask import current_app
    app = current_app._get_current_object()

    threading.Thread(
        target=_run_job,
        args=(job_id, app),
        daemon=True,
    ).start()

    return redirect(url_for("main.progress", job_id=job_id))


# ── Progress ──────────────────────────────────────────────────────────────────

@bp.get("/progress/<job_id>")
def progress(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return redirect(url_for("main.landing"))
    return render_template("progress.html", job_id=job_id, job=job)


@bp.get("/status/<job_id>")
def job_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"status": "not_found"})
    return jsonify({
        "status": job["status"],
        "log": job["log"][-200:],
        "error": job.get("error"),
        "stats": job.get("stats", {}),
    })


@bp.post("/wipe")
@bp.post("/wipe/<job_id>")
def wipe_app(job_id: str = ""):
    """Private-tool self-destruct: save reports, delete the app, shut down.

    Exports all reports to a safe folder on the Desktop (verified), then
    schedules removal of the app (the frozen .exe, or the source tree) and shuts
    the server down. If the export fails, nothing is deleted.

    job_id is accepted for symmetry with the progress/workspace pages but is not
    used — the wipe always exports the whole reports dir, so it can also be fired
    from the landing page (no job in flight) to clean a machine between visits.
    """
    global _wiping
    if _wiping:
        return jsonify({"ok": True, "message": "Wipe already in progress."})
    _wiping = True

    from app.modules.selfwipe import wipe as _do_wipe

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    try:
        result = _do_wipe(_REPORTS_DIR, stamp)
    except Exception as exc:
        _wiping = False
        return jsonify({"ok": False, "message": f"Wipe failed: {exc}"}), 500

    if not result.get("ok"):
        # Export/cleanup failed — report it, allow retry, do NOT shut down.
        _wiping = False
        return jsonify(result), 500

    # Drop a sentinel in TEMP (outside the app dir, so it survives the wipe) so
    # the Windows launcher knows this exit was a deliberate self-destruct and can
    # close its console window instead of stopping at "Press any key".
    try:
        import tempfile
        Path(tempfile.gettempdir(), "_sr_wiped").write_text("1", encoding="utf-8")
    except Exception:
        pass

    # Success: respond, then exit the process shortly after so the response
    # reaches the browser first. os._exit avoids Flask reloader/atexit hooks.
    def _shutdown():
        import time
        time.sleep(1.5)
        os._exit(0)

    threading.Thread(target=_shutdown, daemon=True).start()
    return jsonify(result)


# ── Report ────────────────────────────────────────────────────────────────────

@bp.get("/report/<job_id>")
def report(job_id: str):
    job = _jobs.get(job_id)
    if not job or job["status"] != "done":
        return redirect(url_for("main.progress", job_id=job_id))
    html_path = job.get("report_html")
    if not html_path or not Path(html_path).exists():
        return "Report not found.", 404
    return Path(html_path).read_text(encoding="utf-8")


@bp.get("/report/<job_id>/<variant>")
def report_variant(job_id: str, variant: str):
    """Serve the client or engineer variant of a free report."""
    job = _jobs.get(job_id)
    if not job or job["status"] != "done":
        return redirect(url_for("main.progress", job_id=job_id))
    if variant not in ("client", "engineer"):
        variant = "client"
    html_path = job.get(f"report_html_{variant}")
    if not html_path or not Path(html_path).exists():
        return "Report not found.", 404
    return Path(html_path).read_text(encoding="utf-8")


@bp.get("/download/<variant>/pdf/<job_id>")
def download_variant_pdf(job_id: str, variant: str):
    job = _jobs.get(job_id)
    if not job:
        return "Job not found.", 404
    if variant not in ("client", "engineer"):
        return "Unknown report.", 404
    pdf_path = job.get(f"report_pdf_{variant}")
    if not pdf_path or not Path(pdf_path).exists():
        # Use the per-job error only (the module global can bleed across
        # concurrent jobs under the threaded server).
        reason = job.get("pdf_error") or "PDF was not generated."
        return (
            f"<h2>PDF not available</h2><p><b>Reason:</b> {reason}</p>"
            f"<p>The HTML report still works — "
            f"<a href='/download/{variant}/html/{job_id}'>download the HTML version</a> "
            f"and use your browser's Print &rarr; Save as PDF.</p>"
        ), 404
    return send_file(pdf_path, as_attachment=True,
                     download_name=f"SounRunner-{_safe_name(job['client_name'])}-{variant}.pdf")


@bp.get("/download/<variant>/html/<job_id>")
def download_variant_html(job_id: str, variant: str):
    job = _jobs.get(job_id)
    if not job:
        return "Job not found.", 404
    if variant not in ("client", "engineer"):
        return "Unknown report.", 404
    html_path = job.get(f"report_html_{variant}")
    if not html_path or not Path(html_path).exists():
        return "HTML not available.", 404
    return send_file(html_path, as_attachment=True,
                     download_name=f"SounRunner-{_safe_name(job['client_name'])}-{variant}.html")


@bp.get("/download/pdf/<job_id>")
def download_pdf(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return "Job not found.", 404
    pdf_path = job.get("report_pdf")
    if not pdf_path or not Path(pdf_path).exists():
        # Use the per-job error only (the module global can bleed across
        # concurrent jobs under the threaded server).
        reason = job.get("pdf_error") or "PDF was not generated."
        return (
            f"<h2>PDF not available</h2><p><b>Reason:</b> {reason}</p>"
            f"<p>The HTML report still works — "
            f"<a href='/download/html/{job_id}'>download the HTML version</a> "
            f"and use your browser's Print &rarr; Save as PDF.</p>"
        ), 404
    return send_file(pdf_path, as_attachment=True,
                     download_name=f"SounRunner-{_safe_name(job['client_name'])}.pdf")


@bp.get("/download/html/<job_id>")
def download_html(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return "Job not found.", 404
    html_path = job.get("report_html")
    if not html_path or not Path(html_path).exists():
        return "HTML not available.", 404
    return send_file(html_path, as_attachment=True,
                     download_name=f"SounRunner-{_safe_name(job['client_name'])}.html")


# ── Background job — the full streaming pipeline ──────────────────────────────

def _run_job(job_id: str, app) -> None:
    job = _jobs[job_id]
    client_name = job["client_name"]
    domain      = job["domain"]
    target      = job["target"]
    profile     = job["profile"]
    check_ssl   = job["check_ssl"]
    check_cves  = job["check_cves"]
    check_topo  = job["check_topo"]
    check_deep  = job.get("check_deep", False)
    check_web   = job.get("check_web", False)
    check_compliance = job.get("check_compliance", True)
    check_cred  = job.get("check_cred", False)
    check_agent = job.get("check_agent", False)
    agent_resilience = job.get("agent_resilience", False)
    rescan_of   = job.get("rescan_of", "")

    def log(msg: str) -> None:
        job["log"].append(f"{_ts()}  {msg}")

    def raw(msg: str) -> None:
        job["log"].append(msg)

    try:
        log(f"╔══ SOUN RUNNER ASSESSMENT ENGINE ══╗")
        log(f"Operator: Soun Al Hosn  ·  Client: {client_name}")
        log(f"Scope: {target}  ·  Profile: {profile.upper()}")
        log("")

        # ── 0. Auto-detect network context ────────────────────────────────────
        log("[*] PHASE 0 — Network reconnaissance")
        from app.modules.netinfo import detect as detect_net
        netinfo = None
        try:
            netinfo = detect_net()
            log(f"    Local host : {netinfo.hostname} ({netinfo.local_ip})")
            log(f"    Gateway    : {netinfo.gateway}")
            if netinfo.public_ip:
                log(f"    Public IP  : {netinfo.public_ip}")
                log(f"    ISP        : {netinfo.isp}")
                log(f"    ASN        : {netinfo.asn}")
                log(f"    Location   : {netinfo.city}, {netinfo.country}")
        except Exception as e:
            log(f"    Recon warning: {e}")
        gateway = netinfo.gateway if netinfo else ""
        log("")

        # ── 1. Streaming network scan (discovery + service enum) ──────────────
        log("[*] PHASE 1 — Host discovery & service enumeration")
        scan_result = run_scan_streaming(target, profile, gateway=gateway, log=raw, job_id=job_id)
        if scan_result.error:
            log(f"    Scan error: {scan_result.error}")
        else:
            port_count = sum(len(h.open_ports) for h in scan_result.hosts)
            job["stats"]["hosts"] = scan_result.host_count
            job["stats"]["ports"] = port_count
            log(f"    → {scan_result.host_count} hosts, {port_count} open services")
        log("")

        # ── 2. Path / topology discovery ──────────────────────────────────────
        topology = None
        if check_topo and not scan_result.error:
            log("[*] PHASE 2 — Perimeter path discovery (LAN → ISP edge → internet)")
            from app.modules.topology import trace_path
            # Trace to a public anchor so the path actually traverses the ISP edge.
            # (Tracing to the client's own NAT'd public IP dead-ends at their firewall.)
            try:
                topology = trace_path("1.1.1.1", max_hops=15, log=raw)
                edge = topology.isp_edge
                if edge:
                    log(f"    → First public hop (ISP edge): {edge.ip} ({edge.isp})")
                log(f"    → {len(topology.internal_hops)} internal hop(s), {len(topology.external_hops)} public hop(s)")
            except Exception as e:
                log(f"    Topology warning: {e}")
            log("")

        # ── 3. CVE lookup ─────────────────────────────────────────────────────
        if check_cves and not scan_result.error:
            log("[*] PHASE 3 — CVE intelligence (NIST NVD)")
            from app.modules.vuln_lookup import lookup_cves, get_search_term
            cve_count = 0
            for host in scan_result.hosts:
                for svc in host.services:
                    if svc.risk in ("critical", "high", "medium") and svc.product:
                        term = get_search_term(svc.name, svc.product)
                        cves = lookup_cves(term, svc.version, max_results=3)
                        if cves:
                            svc.cves = cves
                            cve_count += len(cves)
                            raw(f"    CVE → {host.ip}:{svc.port} {svc.product} {svc.version} : {cves[0].cve_id} (CVSS {cves[0].cvss_score})")
            log(f"    → {cve_count} CVE(s) matched")
            log("")

        # ── 3b. Deep service probing (NSE) ────────────────────────────────────
        deep_findings = []
        if check_deep and not scan_result.error:
            log("[*] PHASE 3 — Deep service probing (config-level audit)")
            from app.modules.deepprobe import probe_host
            for host in scan_result.hosts:
                pf = probe_host(host.ip, host.open_ports, log=raw)
                deep_findings.extend(pf)
            log(f"    → {len(deep_findings)} config-level finding(s)")
            log("")

        # ── 3c. Web / admin panel discovery ───────────────────────────────────
        web_results = []
        if check_web and not scan_result.error:
            log("[*] PHASE 3 — Web / admin panel discovery")
            from app.modules.webscan import scan_web_hosts
            web_results = scan_web_hosts(scan_result.hosts, log=raw)
            panels = sum(1 for w in web_results if w.panel_type)
            log(f"    → {len(web_results)} web service(s), {panels} admin panel(s) identified")
            log("")

        # ── 3d. Default-credential testing (consent-gated) ────────────────────
        cred_findings = []
        if check_cred and web_results:
            log("[*] PHASE 3 — Default-credential testing (authorized)")
            from app.modules.credtest import run_cred_tests
            cred_findings = run_cred_tests(web_results, authorized=True, log=raw)
            log(f"    → {len(cred_findings)} default-credential issue(s)")
            log("")

        # ── 3e. Active Validation Agent ───────────────────────────────────────
        validation = None
        if check_agent and not scan_result.error and scan_result.hosts:
            log("[*] PHASE 3 — Active Validation Agent (segmentation + deep enum)")
            from app.modules.validation_agent import run_validation
            validation = run_validation(scan_result.hosts, log=raw,
                                        resilience_authorized=agent_resilience)
            log(f"    → {len(validation.findings)} validated finding(s), {validation.lateral_paths} reachable path(s)")
            log("")

        # ── 4. Email security ─────────────────────────────────────────────────
        dns_result = None
        if domain:
            log(f"[*] PHASE 4 — Email security (SPF / DKIM / DMARC) for {domain}")
            dns_result = check_domain(domain)
            if dns_result.error:
                log(f"    DNS warning: {dns_result.error}")
            else:
                issues = len(dns_result.failed_checks) + len(dns_result.warned_checks)
                for c in dns_result.checks:
                    raw(f"    {c.status.upper():>5}  {c.name}")
                log(f"    → {issues} issue(s)")
            log("")

        # ── 5. SSL / TLS ──────────────────────────────────────────────────────
        ssl_results = None
        if check_ssl and domain:
            log(f"[*] PHASE 5 — SSL/TLS analysis for {domain}")
            from app.modules.ssl_check import check_ssl as do_ssl
            ssl_results = {}
            for port in (443, 8443):
                res = do_ssl(domain, port)
                if res.succeeded or res.findings:
                    ssl_results[f"{domain}:{port}"] = res
                    if res.protocol:
                        raw(f"    {domain}:{port} → {res.protocol} {res.cipher}")
            issues = sum(len(r.failed) for r in ssl_results.values())
            log(f"    → {issues} issue(s)")
            log("")

        # ── 6. Build report ───────────────────────────────────────────────────
        log("[*] PHASE 6 — Correlating findings, compliance mapping & runbook")

        # Re-scan: pull prior findings snapshot for proof-of-fix diff
        prior_findings = None
        if rescan_of and rescan_of in _jobs:
            prior_findings = _jobs[rescan_of].get("findings_snapshot") or None
            if prior_findings:
                log(f"    Re-scan mode — comparing against prior job {rescan_of}")

        # Engineer answers attached to this job (from checklist), if any
        engineer_answers = job.get("engineer_answers")

        report_data = build_report(
            client_name=client_name,
            domain=domain or "N/A",
            target=target,
            scan_profile=profile,
            scan_result=scan_result,
            dns_result=dns_result,
            ssl_results=ssl_results,
            netinfo=netinfo,
            topology=topology,
            deep_findings=deep_findings,
            web_results=web_results,
            cred_findings=cred_findings,
            engineer_answers=engineer_answers,
            prior_findings=prior_findings,
            validation=validation,
            enable_compliance=check_compliance,
        )
        # snapshot findings for future re-scan diffs (immutable copies — the
        # checklist rebuild mutates report_data.findings in place, so we must
        # not alias that list here or the diff baseline would be corrupted).
        from types import SimpleNamespace
        job["findings_snapshot"] = [
            SimpleNamespace(host=f.host, port=f.port, title=f.title, risk=f.risk)
            for f in report_data.findings
        ]
        job["report_data"] = report_data
        job["stats"]["findings"] = report_data.total_findings
        job["stats"]["critical"] = report_data.critical_count
        log(f"    → Risk score: {report_data.risk_score}/100 ({report_data.overall_risk_label})")
        log(f"    → {report_data.total_findings} findings · {report_data.critical_count} critical · {report_data.high_count} high")
        if report_data.has_compliance:
            log(f"    → {report_data.compliance.gap_count} compliance control gap(s)")
        if report_data.has_runbook:
            log(f"    → Remediation runbook: {len(report_data.runbook_steps)} step(s)")

        with app.app_context():
            html_content = render_template("report.html", r=report_data)

        html_path = _REPORTS_DIR / f"{job_id}.html"
        html_path.write_text(html_content, encoding="utf-8")
        job["report_html"] = str(html_path)

        # ── 7. PDF ────────────────────────────────────────────────────────────
        from app.modules.pdf import render_pdf, last_error
        pdf_path = _REPORTS_DIR / f"{job_id}.pdf"
        if render_pdf(html_content, pdf_path):
            job["report_pdf"] = str(pdf_path)
            log("    → PDF report generated")
        else:
            job["pdf_error"] = last_error()
            log(f"    PDF skipped: {last_error()}")

        log("")
        log("╚══ ASSESSMENT COMPLETE ══╝")
        job["status"] = "done"

    except Exception as exc:
        import traceback
        job["error"] = str(exc)
        job["status"] = "error"
        log(f"[!] FATAL: {exc}")
        log(traceback.format_exc().splitlines()[-1])
