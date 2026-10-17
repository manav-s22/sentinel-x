"""Alert rules, alert lifecycle and investigation workflow for Sentinel X."""

from typing import Optional

from sqlalchemy.orm import Session

from .models import ScanRecord
from .workflow_models import Alert, Investigation, utcnow

SEVERITY_RANK = {"informational": 0, "medium": 1, "high": 2, "critical": 3}
ALERT_STATUSES = ("new", "acknowledged", "resolved", "dismissed")
OPEN_ALERT_STATUSES = ("new", "acknowledged")
ALERT_CATEGORIES = ("intel_match", "heuristic_risk", "risk_change")
INVESTIGATION_STATUSES = ("new", "investigating", "resolved", "dismissed")
RISK_CHANGE_THRESHOLD = 20

ALERT_TRANSITIONS = {
    "new": {"acknowledged", "dismissed"},
    "acknowledged": {"resolved", "dismissed"},
    "resolved": {"new"},
    "dismissed": {"new"},
}


def iso(value):
    return value.isoformat() if value else None


def _event(status: str, note: Optional[str] = None) -> dict:
    event = {"status": status, "at": iso(utcnow())}
    if note:
        event["note"] = note
    return event


# ---------------------------------------------------------------
# Alert creation
# ---------------------------------------------------------------

def _raise_alert(
    db: Session, *, key: str, category: str, severity: str, title: str,
    url: str, hostname: Optional[str], scan_id: Optional[int],
    score: Optional[int], source: str, evidence: list, recommendation: str,
) -> Alert:
    """Create an alert, or refresh the open alert with the same dedupe key."""
    now = utcnow()
    existing = (
        db.query(Alert)
        .filter(Alert.dedupe_key == key, Alert.status.in_(OPEN_ALERT_STATUSES))
        .order_by(Alert.id.desc())
        .first()
    )

    if existing is not None:
        existing.occurrences = (existing.occurrences or 1) + 1
        existing.updated_at = now
        existing.scan_id = scan_id
        existing.risk_score = score
        existing.evidence = evidence
        existing.recommendation = recommendation

        if SEVERITY_RANK[severity] > SEVERITY_RANK.get(existing.severity, 0):
            existing.severity = severity
            existing.title = title
            if existing.status == "acknowledged":
                existing.status = "new"
                existing.acknowledged_at = None
                existing.timeline = [
                    *(existing.timeline or []),
                    _event("new", "Severity escalated; alert re-opened for triage."),
                ]
        return existing

    alert = Alert(
        category=category, severity=severity, status="new", title=title,
        normalized_url=url, hostname=hostname, scan_id=scan_id,
        risk_score=score, source=source, evidence=evidence,
        recommendation=recommendation, dedupe_key=key, occurrences=1,
        timeline=[_event("new")], created_at=now, updated_at=now,
    )
    db.add(alert)
    return alert


def evaluate_scan(db: Session, record: ScanRecord) -> list:
    """Apply the heuristic-risk and risk-change rules to a saved scan."""
    level = (record.risk_level or "").lower()
    score = int(record.risk_score or 0)
    url = record.normalized_url
    signals = record.signals if isinstance(record.signals, list) else []
    risky = sorted(
        (s for s in signals if (s.get("points") or 0) > 0),
        key=lambda s: -(s.get("points") or 0),
    )
    top_evidence = [
        {"label": s.get("signal"), "detail": s.get("detail"), "points": s.get("points")}
        for s in risky[:8]
    ]
    raised = []

    # Rule: heuristic risk
    if level in ("high", "medium"):
        high = level == "high"
        raised.append(_raise_alert(
            db,
            key=f"heuristic_risk:{url}",
            category="heuristic_risk",
            severity="high" if high else "medium",
            title=f"{'High' if high else 'Elevated'} heuristic risk (score {score}/100)",
            url=url, hostname=record.hostname, scan_id=record.id, score=score,
            source="Sentinel X heuristics", evidence=top_evidence,
            recommendation=(
                "Do not interact with this URL until its destination is verified "
                "through a trusted channel. Run a threat-intelligence lookup to "
                "check for a reputation match."
                if high else
                "Review the listed indicators and verify the domain independently "
                "before trusting this link."
            ),
        ))

    # Rule: significant risk change after a rescan
    previous = (
        db.query(ScanRecord)
        .filter(ScanRecord.normalized_url == url, ScanRecord.id < record.id)
        .order_by(ScanRecord.id.desc())
        .first()
    )
    if previous is not None and previous.risk_score is not None:
        delta = score - int(previous.risk_score)
        if abs(delta) >= RISK_CHANGE_THRESHOLD:
            up = delta > 0
            evidence = [
                {"label": "Previous score", "detail": f"{previous.risk_score}/100 (scan #{previous.id})"},
                {"label": "Current score", "detail": f"{score}/100 (scan #{record.id})"},
                {"label": "Change", "detail": f"{delta:+d} points"},
            ] + top_evidence[:3]
            raised.append(_raise_alert(
                db,
                key=f"risk_change:{'up' if up else 'down'}:{url}",
                category="risk_change",
                severity=("high" if level == "high" else "medium") if up else "informational",
                title=f"Risk {'increased' if up else 'decreased'} by {abs(delta)} points after rescan",
                url=url, hostname=record.hostname, scan_id=record.id, score=score,
                source="Sentinel X heuristics", evidence=evidence,
                recommendation=(
                    "Compare both scans and re-verify this URL before use."
                    if up else
                    "The score dropped. Confirm the change is expected before "
                    "treating the URL as lower risk."
                ),
            ))
    return raised


def evaluate_intel(
    db: Session, *, url: str, hostname: Optional[str], reputation: dict,
    score: Optional[int] = None, scan_id: Optional[int] = None,
) -> Optional[Alert]:
    """Rule: a URLhaus exact match raises a Critical (or High if offline) alert."""
    if not reputation or reputation.get("status") != "match":
        return None

    url_status = str(reputation.get("url_status") or "unknown").lower()
    severity = "high" if url_status == "offline" else "critical"
    tags = reputation.get("tags") or []

    evidence = [
        {"label": "Source", "detail": "URLhaus exact URL match"},
        {"label": "Listing status", "detail": url_status},
    ]
    if reputation.get("threat"):
        evidence.append({"label": "Threat type", "detail": str(reputation["threat"])})
    if tags:
        evidence.append({"label": "Tags", "detail": ", ".join(str(t) for t in tags)})
    if reputation.get("date_added"):
        evidence.append({"label": "Date added", "detail": str(reputation["date_added"])})
    if reputation.get("reference"):
        evidence.append({"label": "Reference", "detail": str(reputation["reference"])})
    if score is not None:
        evidence.append({"label": "Heuristic score", "detail": f"{score}/100"})

    return _raise_alert(
        db,
        key=f"intel_match:{url}",
        category="intel_match",
        severity=severity,
        title="URL listed by URLhaus" + (" (reported offline)" if url_status == "offline" else ""),
        url=url, hostname=hostname, scan_id=scan_id, score=score,
        source="URLhaus", evidence=evidence,
        recommendation=(
            "URLhaus lists this URL but reports it offline. Avoid it, and check "
            "whether the content has simply moved."
            if severity == "high" else
            "Block this URL and do not open it. Review the URLhaus reference and "
            "check proxy or mail logs for anyone who already visited it."
        ),
    )


# ---------------------------------------------------------------
# Alert lifecycle
# ---------------------------------------------------------------

def change_alert_status(alert: Alert, new_status: str, note: Optional[str] = None) -> None:
    if new_status not in ALERT_TRANSITIONS.get(alert.status, set()):
        raise ValueError(f"An alert that is {alert.status} cannot move to {new_status}.")

    now = utcnow()
    alert.status = new_status
    alert.updated_at = now
    if new_status == "acknowledged":
        alert.acknowledged_at = now
    elif new_status in ("resolved", "dismissed"):
        alert.closed_at = now
    elif new_status == "new":  # reopened
        alert.acknowledged_at = None
        alert.closed_at = None
    alert.timeline = [*(alert.timeline or []), _event(new_status, note)]


def serialize_alert(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "category": alert.category,
        "severity": alert.severity,
        "status": alert.status,
        "title": alert.title,
        "normalized_url": alert.normalized_url,
        "hostname": alert.hostname,
        "scan_id": alert.scan_id,
        "risk_score": alert.risk_score,
        "source": alert.source,
        "evidence": alert.evidence or [],
        "recommendation": alert.recommendation,
        "occurrences": alert.occurrences or 1,
        "timeline": alert.timeline or [],
        "created_at": iso(alert.created_at),
        "updated_at": iso(alert.updated_at),
        "acknowledged_at": iso(alert.acknowledged_at),
        "closed_at": iso(alert.closed_at),
    }


# ---------------------------------------------------------------
# Investigation workflow
# ---------------------------------------------------------------

def apply_investigation_update(
    db: Session, *, url: str, hostname: Optional[str],
    status: Optional[str], note: Optional[str],
) -> Investigation:
    now = utcnow()
    inv = db.query(Investigation).filter(Investigation.normalized_url == url).first()

    if inv is None:
        inv = Investigation(
            normalized_url=url, hostname=hostname, status="new",
            created_at=now, updated_at=now,
            timeline=[{"type": "created", "status": "new", "at": iso(now)}],
        )
        db.add(inv)

    timeline = list(inv.timeline or [])
    if status and status != inv.status:
        inv.status = status
        inv.closed_at = now if status in ("resolved", "dismissed") else None
        timeline.append({"type": "status", "status": status, "at": iso(now)})
    if note:
        timeline.append({"type": "note", "text": note, "at": iso(now)})

    inv.timeline = timeline
    inv.updated_at = now
    return inv


def serialize_investigation(inv: Investigation) -> dict:
    return {
        "id": inv.id,
        "normalized_url": inv.normalized_url,
        "status": inv.status,
        "timeline": inv.timeline or [],
        "created_at": iso(inv.created_at),
        "updated_at": iso(inv.updated_at),
        "closed_at": iso(inv.closed_at),
    }