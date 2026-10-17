import ipaddress
import json
import logging
import os
import re

from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import ScanRecord
from .workflow_models import Alert, Investigation, utcnow
from .workflow import (
    ALERT_CATEGORIES,
    ALERT_STATUSES,
    INVESTIGATION_STATUSES,
    OPEN_ALERT_STATUSES,
    SEVERITY_RANK,
    apply_investigation_update,
    change_alert_status,
    evaluate_intel,
    evaluate_scan,
    serialize_alert,
    serialize_investigation,
)

logger = logging.getLogger("sentinelx")


# --------------------------------------------------
# App setup
# --------------------------------------------------

app = FastAPI(
    title="Sentinel X API",
    version="0.5.0",
    description=(
        "Sentinel X URL risk analysis, URL forensics, optional external "
        "threat intelligence, security alerts and investigation workflow."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "https://sentinel-8eeiw0i06-ms31.vercel.app/",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)

Base.metadata.create_all(bind=engine)


# --------------------------------------------------
# Configuration
# --------------------------------------------------

MAX_URL_LENGTH = 2048
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_TIMEOUT_SECONDS = 5
MAX_INTELLIGENCE_RESPONSE_BYTES = 256_000

# Last observed URLhaus outcome (in memory; resets when the backend restarts).
URLHAUS_STATE = {"last_status": None, "last_checked": None}

SUSPICIOUS_TERMS = {
    "login", "signin", "verify", "verification",
    "password", "credential", "wallet", "payment",
    "banking", "account", "authenticate", "recover",
    "reset", "secure",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "buff.ly", "cutt.ly", "shorturl.at",
    "ow.ly", "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz",
    "work", "gq", "tk", "country",
}


# --------------------------------------------------
# Request schemas
# --------------------------------------------------

class URLAnalysisRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)


class AlertStatusUpdate(BaseModel):
    status: str
    note: Optional[str] = Field(default=None, max_length=1000)


class InvestigationUpdate(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    status: Optional[str] = None
    note: Optional[str] = Field(default=None, max_length=1000)


# --------------------------------------------------
# Shared helpers
# --------------------------------------------------

def is_ip_address(host: str) -> bool:
    """Return True if host is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def get_hostname_labels(host: str) -> list[str]:
    return host.split(".") if host else []


def normalize_url(raw_url: str) -> str:
    """Validate and normalize an HTTP or HTTPS URL."""

    if not isinstance(raw_url, str):
        raise ValueError("URL must be text.")

    value = raw_url.strip()

    if not value:
        raise ValueError("Please enter a URL.")

    if len(value) > MAX_URL_LENGTH:
        raise ValueError(
            f"URL must not exceed {MAX_URL_LENGTH} characters."
        )

    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("URL contains invalid control characters.")

    if "\\" in value:
        raise ValueError("URL must not contain backslashes.")

    try:
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must include a hostname.")

        # Validate malformed ports.
        _ = parsed.port

        hostname = parsed.hostname.lower().rstrip(".")

    except ValueError as exc:
        raise ValueError(f"Invalid URL: {exc}") from exc

    if any(char.isspace() for char in hostname):
        raise ValueError("Hostname must not contain spaces.")

    host_is_ip = is_ip_address(hostname)

    if not host_is_ip:
        if len(hostname) > 253:
            raise ValueError("Hostname is too long.")

        labels = hostname.split(".")
        label_pattern = re.compile(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
            re.IGNORECASE,
        )

        if (
            not labels
            or any(not label for label in labels)
            or any(
                not label_pattern.fullmatch(label)
                for label in labels
            )
        ):
            raise ValueError("Hostname contains invalid characters.")

    # Keep user-info visible for analysis. Normalize only the host portion.
    if "@" in parsed.netloc:
        userinfo, host_port = parsed.netloc.rsplit("@", 1)
        netloc = f"{userinfo}@{host_port.lower()}"
    else:
        netloc = parsed.netloc.lower()

    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def serialize_scan(record: ScanRecord) -> dict:
    return {
        "id": record.id,
        "scan_id": record.id,
        "submitted_url": record.submitted_url,
        "normalized_url": record.normalized_url,
        "hostname": record.hostname,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "signal_count": record.signal_count,
        "signals": record.signals,
        "recommendation": record.recommendation,
        "analysis_method": record.analysis_method,
        "created_at": (
            record.created_at.isoformat()
            if record.created_at
            else None
        ),
    }


# --------------------------------------------------
# URL forensics
# --------------------------------------------------

def inspect_url(normalized_url: str) -> dict:
    """
    Extract static URL components only.
    This does not connect to or visit the destination website.
    """

    parsed = urlsplit(normalized_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    labels = get_hostname_labels(hostname)
    host_is_ip = is_ip_address(hostname)

    try:
        port = parsed.port
    except ValueError:
        port = None

    query_parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True,
        max_num_fields=500,
    )

    try:
        ip_obj = ipaddress.ip_address(hostname) if host_is_ip else None
        ip_version = ip_obj.version if ip_obj else None
        ip_is_global = ip_obj.is_global if ip_obj else None
    except ValueError:
        ip_version = None
        ip_is_global = None

    # A simple label count, not a public-suffix-aware domain calculation.
    subdomain_count = max(0, len(labels) - 2) if not host_is_ip else 0

    return {
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": port,
        "path": parsed.path or "/",
        "query_parameter_count": len(query_parameters),
        "query_parameter_names": [
            name for name, _ in query_parameters
        ][:50],
        "fragment_present": bool(parsed.fragment),
        "url_length": len(normalized_url),
        "hostname_label_count": len(labels),
        "subdomain_count": subdomain_count,
        "userinfo_present": "@" in parsed.netloc,
        "hostname_is_ip": host_is_ip,
        "ip_version": ip_version,
        "ip_is_global": ip_is_global,
        "punycode_present": any(
            label.startswith("xn--") for label in labels
        ),
        "https_used": parsed.scheme == "https",
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
    }


# --------------------------------------------------
# Optional URLhaus threat-intelligence lookup
# --------------------------------------------------

def _query_urlhaus(normalized_url: str) -> dict:
    """
    Query URLhaus for an exact URL match.

    This submits the URL to URLhaus when configured.
    It never fetches the submitted destination itself.
    """

    auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()

    if not auth_key:
        return {
            "provider": "URLhaus",
            "status": "not_configured",
            "matched": None,
            "message": (
                "URLhaus is not configured. Set URLHAUS_AUTH_KEY "
                "on the backend to enable reputation lookups."
            ),
        }

    body = urlencode({"url": normalized_url}).encode("utf-8")

    request = Request(
        URLHAUS_API_URL,
        data=body,
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Sentinel-X-Student-Project/1.0",
        },
        method="POST",
    )

    try:
        with urlopen(
            request,
            timeout=URLHAUS_TIMEOUT_SECONDS,
        ) as response:
            raw_response = response.read(
                MAX_INTELLIGENCE_RESPONSE_BYTES + 1
            )

        if len(raw_response) > MAX_INTELLIGENCE_RESPONSE_BYTES:
            return {
                "provider": "URLhaus",
                "status": "lookup_error",
                "matched": None,
                "message": "URLhaus response exceeded the size limit.",
            }

        data = json.loads(raw_response.decode("utf-8"))
        query_status = data.get("query_status")

        if query_status == "no_results":
            return {
                "provider": "URLhaus",
                "status": "no_match",
                "matched": False,
                "message": (
                    "URLhaus returned no exact URL match. "
                    "This does not establish that the URL is safe."
                ),
            }

        if query_status != "ok":
            return {
                "provider": "URLhaus",
                "status": "lookup_error",
                "matched": None,
                "message": (
                    "URLhaus returned an unexpected response. "
                    "The heuristic assessment remains available."
                ),
            }

        return {
            "provider": "URLhaus",
            "status": "match",
            "matched": True,
            "url_status": data.get("url_status", "unknown"),
            "threat": data.get("threat"),
            "date_added": data.get("date_added"),
            "tags": data.get("tags", []),
            "reference": data.get("urlhaus_reference"),
            "message": (
                "URLhaus returned a matching URL record. "
                "Review its reported status and reference."
            ),
        }

    except HTTPError as exc:
        return {
            "provider": "URLhaus",
            "status": "unavailable",
            "matched": None,
            "message": (
                f"URLhaus returned HTTP status {exc.code}. "
                "Threat intelligence was not confirmed."
            ),
        }

    except (URLError, TimeoutError, OSError):
        return {
            "provider": "URLhaus",
            "status": "unavailable",
            "matched": None,
            "message": (
                "URLhaus could not be reached. "
                "The heuristic assessment remains available."
            ),
        }

    except (ValueError, UnicodeDecodeError):
        return {
            "provider": "URLhaus",
            "status": "lookup_error",
            "matched": None,
            "message": (
                "URLhaus returned an unreadable response. "
                "Threat intelligence was not confirmed."
            ),
        }


def lookup_urlhaus(normalized_url: str) -> dict:
    """Run the lookup and remember the outcome for the health endpoint."""
    result = _query_urlhaus(normalized_url)
    URLHAUS_STATE["last_status"] = result.get("status")
    URLHAUS_STATE["last_checked"] = utcnow().isoformat()
    return result


# --------------------------------------------------
# Heuristic analyzer
# --------------------------------------------------

def analyze_url(raw_url: str) -> dict:
    normalized = normalize_url(raw_url)
    parsed = urlsplit(normalized)

    host = (parsed.hostname or "").lower().rstrip(".")
    host_labels = get_hostname_labels(host)
    host_is_ip = is_ip_address(host)

    reasons = []
    score = 0

    def flag(points: int, title: str, detail: str) -> None:
        nonlocal score
        score += points
        reasons.append({
            "signal": title,
            "detail": detail,
            "points": points,
            "category": "heuristic",
        })

    # HTTPS indicator
    if parsed.scheme != "https":
        flag(
            12,
            "No HTTPS",
            (
                "The URL uses HTTP rather than HTTPS. "
                "This is a security weakness, but does not "
                "by itself prove malicious intent."
            ),
        )
    else:
        reasons.append({
            "signal": "HTTPS present",
            "detail": (
                "HTTPS protects the connection in transit, "
                "but does not establish that the destination is trustworthy."
            ),
            "points": 0,
            "category": "transport",
        })

    # IP address hostname
    if host_is_ip:
        flag(
            25,
            "IP address hostname",
            "The destination uses an IP address instead of a domain name.",
        )

    # User-info syntax, such as https://trusted.example@other.example
    if "@" in parsed.netloc:
        flag(
            25,
            "URL contains user-info syntax",
            (
                "Text before the @ symbol can make the actual "
                "destination hostname harder to notice."
            ),
        )

    # Punycode labels
    if any(label.startswith("xn--") for label in host_labels):
        flag(
            15,
            "Punycode hostname",
            (
                "An internationalized hostname is present. "
                "Review it for possible lookalike characters."
            ),
        )

    # URL length
    if len(normalized) > 150:
        flag(10, "Very long URL", "The URL is unusually long.")
    elif len(normalized) > 75:
        flag(5, "Long URL", "The URL is longer than typical.")

    if len(host) > 50:
        flag(8, "Long hostname", "The hostname itself is unusually long.")

    # Many subdomains
    if len(host_labels) >= 5:
        flag(
            12,
            "Many subdomains",
            "The hostname contains several subdomain levels.",
        )

    # Mixed letters and digits
    if (
        any(char.isdigit() for char in host)
        and any(char.isalpha() for char in host)
    ):
        flag(
            3,
            "Mixed hostname characters",
            "The hostname contains both letters and digits.",
        )

    # Embedded URL inside the query
    if re.search(
        r"https?(?:://|%3a%2f%2f)",
        parsed.query,
        re.IGNORECASE,
    ):
        flag(
            8,
            "Embedded URL in query",
            (
                "The query contains another URL, which can occur "
                "in redirects and link-wrapping systems."
            ),
        )

    # Suspicious terms in path/query only
    searchable = f"{parsed.path}?{parsed.query}".lower()

    matched_terms = sorted(
        term
        for term in SUSPICIOUS_TERMS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
            searchable,
        )
    )

    if matched_terms:
        points = min(18, 6 + 3 * (len(matched_terms) - 1))
        flag(
            points,
            "Sensitive-action keywords",
            (
                "Potentially relevant terms were found: "
                + ", ".join(matched_terms[:6])
                + ". These terms alone do not prove phishing."
            ),
        )

    # URL shorteners
    if host in URL_SHORTENERS:
        flag(
            15,
            "URL shortener",
            "The shortened URL hides its eventual destination.",
        )

    # TLD review list
    tld = host_labels[-1] if host_labels else ""

    if tld in SUSPICIOUS_TLDS:
        flag(
            8,
            "TLD worth reviewing",
            (
                f".{tld} is on the application's review list. "
                "The TLD alone is not proof of abuse."
            ),
        )

    score = min(max(score, 0), 100)

    if score >= 60:
        risk_level = "High"
        recommendation = (
            "Avoid interacting until the destination is independently verified."
        )
    elif score >= 30:
        risk_level = "Medium"
        recommendation = (
            "Review the indicators and verify the domain through a trusted channel."
        )
    else:
        risk_level = "Low"
        recommendation = (
            "Few heuristic warning signs were found. "
            "This does not prove the URL is safe."
        )

    forensics = inspect_url(normalized)

    return {
        "submitted_url": raw_url,
        "normalized_url": normalized,
        "hostname": host,
        "risk_score": score,
        "risk_level": risk_level,
        "signals": reasons,
        "signal_count": sum(
            1 for item in reasons if item["points"] > 0
        ),
        "forensics": forensics,
        "recommendation": recommendation,
        "analysis_method": "heuristic",
        "disclaimer": (
            "This is a rule-based risk assessment, not a calibrated "
            "probability or definitive verdict. Heuristic signals alone "
            "cannot confirm that a URL is malicious or safe."
        ),
    }

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(ENV_FILE)


# --------------------------------------------------
# Health endpoint
# --------------------------------------------------

@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception:
        database = "error"

    configured = bool(os.getenv("URLHAUS_AUTH_KEY", "").strip())
    last_status = URLHAUS_STATE["last_status"]

    if not configured:
        availability = "not_configured"
    elif last_status is None:
        availability = "untested"
    elif last_status in ("match", "no_match"):
        availability = "reachable"
    else:
        availability = "degraded"

    return {
        "status": "ok" if database == "ok" else "degraded",
        "service": "Sentinel X API",
        "version": app.version,
        "database": database,
        "analysis_method": "heuristic",
        "threat_intelligence": {
            "urlhaus_configured": configured,
            "urlhaus_availability": availability,
            "urlhaus_last_status": last_status,
            "urlhaus_last_checked": URLHAUS_STATE["last_checked"],
        },
    }


# --------------------------------------------------
# Analyze URL and save the scan
# --------------------------------------------------

@app.post("/api/analyze-url")
def analyze_url_endpoint(
    request: URLAnalysisRequest,
    db: Session = Depends(get_db),
):
    try:
        result = analyze_url(request.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    record = ScanRecord(
        submitted_url=result["submitted_url"],
        normalized_url=result["normalized_url"],
        hostname=result["hostname"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        signal_count=result["signal_count"],
        signals=result["signals"],
        recommendation=result["recommendation"],
        analysis_method=result["analysis_method"],
    )

    try:
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not save the scan to the database.",
        ) from exc

    result["scan_id"] = record.id
    result["created_at"] = (
        record.created_at.isoformat()
        if record.created_at
        else None
    )
    result["alerts"] = []

    # The scan is already saved; a failure here must not break the response.
    try:
        raised = evaluate_scan(db, record)
        db.commit()
        result["alerts"] = [serialize_alert(alert) for alert in raised]
    except Exception:
        db.rollback()
        logger.exception("Alert evaluation failed for scan %s", result["scan_id"])

    return result


# --------------------------------------------------
# Scan history
# --------------------------------------------------

@app.get("/api/history")
def get_history(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    records = (
        db.query(ScanRecord)
        .order_by(ScanRecord.id.desc())
        .limit(limit)
        .all()
    )

    return [serialize_scan(record) for record in records]


# --------------------------------------------------
# Standalone URLhaus lookup
# --------------------------------------------------

def record_intel_alert(db, url, hostname, reputation, score=None) -> None:
    try:
        if evaluate_intel(
            db, url=url, hostname=hostname, reputation=reputation, score=score
        ) is not None:
            db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not record threat-intelligence alert")


@app.post("/api/urlhaus-lookup")
def urlhaus_lookup_endpoint(
    request: URLAnalysisRequest,
    db: Session = Depends(get_db),
):
    try:
        normalized = normalize_url(request.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    reputation = lookup_urlhaus(normalized)
    record_intel_alert(db, normalized, urlsplit(normalized).hostname, reputation)
    return reputation


# --------------------------------------------------
# Combined detailed threat intelligence endpoint
# --------------------------------------------------

@app.post("/api/threat-intelligence")
def threat_intelligence_endpoint(
    request: URLAnalysisRequest,
    db: Session = Depends(get_db),
):
    try:
        analysis = analyze_url(request.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    reputation = lookup_urlhaus(analysis["normalized_url"])
    record_intel_alert(
        db,
        analysis["normalized_url"],
        analysis["hostname"],
        reputation,
        analysis["risk_score"],
    )

    return {
        "submitted_url": analysis["submitted_url"],
        "normalized_url": analysis["normalized_url"],
        "hostname": analysis["hostname"],
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "signals": analysis["signals"],
        "signal_count": analysis["signal_count"],
        "forensics": analysis["forensics"],
        "recommendation": analysis["recommendation"],
        "intelligence": {
            "urlhaus": reputation,
        },
        "analysis_method": "heuristic_with_optional_reputation",
        "disclaimer": (
            "Heuristic indicators and reputation results are different "
            "types of evidence. A missing reputation match does not "
            "establish that a URL is safe. No destination website is "
            "visited by this endpoint."
        ),
    }


# --------------------------------------------------
# Security alerts
# --------------------------------------------------

@app.get("/api/alerts")
def list_alerts(
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    days: Optional[int] = Query(default=None, ge=1, le=365),
    limit: int = Query(default=200, ge=1, le=500),
    db: Session = Depends(get_db),
):
    if severity and severity not in SEVERITY_RANK:
        raise HTTPException(status_code=422, detail="Unknown severity filter.")
    if status and status not in ALERT_STATUSES:
        raise HTTPException(status_code=422, detail="Unknown status filter.")
    if category and category not in ALERT_CATEGORIES:
        raise HTTPException(status_code=422, detail="Unknown category filter.")

    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if category:
        query = query.filter(Alert.category == category)
    if days:
        query = query.filter(Alert.created_at >= utcnow() - timedelta(days=days))

    total_matching = query.count()
    items = query.order_by(Alert.id.desc()).limit(limit).all()

    # Triage order: open alerts first, then severity, then newest.
    items.sort(
        key=lambda a: (
            a.status not in OPEN_ALERT_STATUSES,
            -SEVERITY_RANK.get(a.severity, 0),
            -a.id,
        )
    )

    by_status = dict(
        db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    )
    open_by_severity = {key: 0 for key in SEVERITY_RANK}
    for sev, count in (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.status.in_(OPEN_ALERT_STATUSES))
        .group_by(Alert.severity)
        .all()
    ):
        open_by_severity[sev] = count

    return {
        "items": [serialize_alert(a) for a in items],
        "total_matching": total_matching,
        "counts": {"by_status": by_status, "open_by_severity": open_by_severity},
    }


@app.patch("/api/alerts/{alert_id}")
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    if payload.status not in ALERT_STATUSES:
        raise HTTPException(status_code=422, detail="Unknown alert status.")

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")

    note = (payload.note or "").strip() or None
    try:
        change_alert_status(alert, payload.status, note)
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not update the alert.") from exc

    db.refresh(alert)
    return serialize_alert(alert)


# --------------------------------------------------
# Investigation workflow
# --------------------------------------------------

@app.post("/api/investigations")
def update_investigation(
    payload: InvestigationUpdate,
    db: Session = Depends(get_db),
):
    try:
        normalized = normalize_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if payload.status is not None and payload.status not in INVESTIGATION_STATUSES:
        raise HTTPException(status_code=422, detail="Unknown investigation status.")

    note = (payload.note or "").strip() or None
    if payload.status is None and note is None:
        raise HTTPException(status_code=422, detail="Provide a status or a note.")

    try:
        inv = apply_investigation_update(
            db,
            url=normalized,
            hostname=urlsplit(normalized).hostname,
            status=payload.status,
            note=note,
        )
        db.commit()
        db.refresh(inv)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not save the investigation.",
        ) from exc

    return serialize_investigation(inv)


# --------------------------------------------------
# Command center summary
# --------------------------------------------------

@app.get("/api/command-center")
def command_center(
    tz: int = Query(default=0, ge=-840, le=840),
    db: Session = Depends(get_db),
):
    """`tz` is the browser's UTC offset in minutes, used to bucket trend days."""
    now = utcnow()
    offset = timedelta(minutes=tz)

    # ---- totals
    total = db.query(func.count(ScanRecord.id)).scalar() or 0
    levels = {"high": 0, "medium": 0, "low": 0}
    for level, count in (
        db.query(func.lower(ScanRecord.risk_level), func.count(ScanRecord.id))
        .group_by(func.lower(ScanRecord.risk_level))
        .all()
    ):
        if level in levels:
            levels[level] += count
    avg = db.query(func.avg(ScanRecord.risk_score)).scalar()
    unique_urls = (
        db.query(func.count(func.distinct(ScanRecord.normalized_url))).scalar() or 0
    )
    last_24h = (
        db.query(func.count(ScanRecord.id))
        .filter(ScanRecord.created_at >= now - timedelta(hours=24))
        .scalar()
        or 0
    )
    last_scan = db.query(func.max(ScanRecord.created_at)).scalar()

    # ---- 14-day trend, bucketed in the browser's local days
    days = 14
    start_local = (now + offset).date() - timedelta(days=days - 1)
    start_utc = datetime.combine(start_local, datetime.min.time()) - offset
    buckets: dict = {}
    for created, score, level in (
        db.query(ScanRecord.created_at, ScanRecord.risk_score, ScanRecord.risk_level)
        .filter(ScanRecord.created_at >= start_utc)
        .all()
    ):
        if created is None:
            continue
        buckets.setdefault((created + offset).date(), []).append(
            (int(score or 0), (level or "").lower())
        )

    trend = []
    for i in range(days):
        day = start_local + timedelta(days=i)
        values = buckets.get(day, [])
        scores = [s for s, _ in values]
        trend.append({
            "date": day.isoformat(),
            "label": day.strftime("%d %b"),
            "scans": len(values),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
            "max_score": max(scores) if scores else None,
            "high": sum(1 for _, lv in values if lv == "high"),
            "medium": sum(1 for _, lv in values if lv == "medium"),
            "low": sum(1 for _, lv in values if lv == "low"),
        })

    # ---- score distribution and most frequent signals (latest 500 scans)
    bands = [("0-19", 0, 19), ("20-39", 20, 39), ("40-59", 40, 59), ("60-79", 60, 79), ("80-100", 80, 100)]
    distribution = [{"band": name, "count": 0} for name, _, _ in bands]
    signal_counts: dict = {}
    for score, signals in (
        db.query(ScanRecord.risk_score, ScanRecord.signals)
        .order_by(ScanRecord.id.desc())
        .limit(500)
        .all()
    ):
        value = int(score or 0)
        for idx, (_, lo, hi) in enumerate(bands):
            if lo <= value <= hi:
                distribution[idx]["count"] += 1
                break
        if isinstance(signals, list):
            for sig in signals:
                if isinstance(sig, dict) and (sig.get("points") or 0) > 0 and sig.get("signal"):
                    signal_counts[sig["signal"]] = signal_counts.get(sig["signal"], 0) + 1
    top_signals = [
        {"signal": name, "count": count}
        for name, count in sorted(signal_counts.items(), key=lambda kv: -kv[1])[:6]
    ]

    # ---- latest detections
    detections = (
        db.query(ScanRecord)
        .filter(func.lower(ScanRecord.risk_level).in_(["high", "medium"]))
        .order_by(ScanRecord.id.desc())
        .limit(5)
        .all()
    )

    # ---- investigation queue: latest scan per URL that is High or Medium
    latest = (
        db.query(
            func.max(ScanRecord.id).label("last_id"),
            func.count(ScanRecord.id).label("scan_count"),
        )
        .group_by(ScanRecord.normalized_url)
        .subquery()
    )
    rows = (
        db.query(ScanRecord, latest.c.scan_count)
        .join(latest, ScanRecord.id == latest.c.last_id)
        .filter(func.lower(ScanRecord.risk_level).in_(["high", "medium"]))
        .order_by(ScanRecord.risk_score.desc(), ScanRecord.id.desc())
        .limit(100)
        .all()
    )

    urls = [record.normalized_url for record, _ in rows]
    investigations: dict = {}
    open_alert_counts: dict = {}
    if urls:
        investigations = {
            inv.normalized_url: inv
            for inv in db.query(Investigation)
            .filter(Investigation.normalized_url.in_(urls))
            .all()
        }
        open_alert_counts = dict(
            db.query(Alert.normalized_url, func.count(Alert.id))
            .filter(
                Alert.normalized_url.in_(urls),
                Alert.status.in_(OPEN_ALERT_STATUSES),
            )
            .group_by(Alert.normalized_url)
            .all()
        )

    queue = []
    for record, scan_count in rows:
        inv = investigations.get(record.normalized_url)
        queue.append({
            "normalized_url": record.normalized_url,
            "hostname": record.hostname,
            "risk_score": record.risk_score,
            "risk_level": record.risk_level,
            "last_scan_id": record.id,
            "last_scanned": record.created_at.isoformat() if record.created_at else None,
            "scan_count": scan_count,
            "status": inv.status if inv else "new",
            "investigation": serialize_investigation(inv) if inv else None,
            "open_alerts": open_alert_counts.get(record.normalized_url, 0),
        })
    # Open items first; the sort is stable so score order is kept.
    queue.sort(key=lambda item: item["status"] in ("resolved", "dismissed"))

    # ---- alerts summary
    open_by_severity = {key: 0 for key in SEVERITY_RANK}
    for sev, count in (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.status.in_(OPEN_ALERT_STATUSES))
        .group_by(Alert.severity)
        .all()
    ):
        open_by_severity[sev] = count
    new_count = (
        db.query(func.count(Alert.id)).filter(Alert.status == "new").scalar() or 0
    )
    open_alerts = (
        db.query(Alert)
        .filter(Alert.status.in_(OPEN_ALERT_STATUSES))
        .order_by(Alert.id.desc())
        .limit(300)
        .all()
    )
    priority = sorted(
        open_alerts,
        key=lambda a: (-SEVERITY_RANK.get(a.severity, 0), a.status != "new", -a.id),
    )[:6]

    return {
        "generated_at": now.isoformat(),
        "totals": {
            "scans": total,
            "unique_urls": unique_urls,
            "high": levels["high"],
            "medium": levels["medium"],
            "low": levels["low"],
            "avg_score": round(float(avg), 1) if avg is not None else 0,
            "last_24h": last_24h,
            "last_scan": last_scan.isoformat() if last_scan else None,
        },
        "trend": trend,
        "score_distribution": distribution,
        "top_signals": top_signals,
        "latest_detections": [serialize_scan(r) for r in detections],
        "queue": queue,
        "alerts": {
            "open": sum(open_by_severity.values()),
            "new": new_count,
            "open_by_severity": open_by_severity,
            "priority": [serialize_alert(a) for a in priority],
        },
    }


# --------------------------------------------------
# Data reset (Settings > Danger zone)
# --------------------------------------------------

@app.delete("/api/data")
def reset_data(
    confirm: str = Query(default=""),
    db: Session = Depends(get_db),
):
    if confirm != "DELETE":
        raise HTTPException(status_code=422, detail="Confirmation text must be DELETE.")
    try:
        deleted = {
            "scans": db.query(ScanRecord).delete(),
            "alerts": db.query(Alert).delete(),
            "investigations": db.query(Investigation).delete(),
        }
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not reset the data.") from exc
    return {"deleted": deleted}