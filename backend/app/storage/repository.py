import datetime
import logging
from typing import List, Dict, Any, Optional
from app.storage.supabase_client import get_supabase_client, is_supabase_configured

logger = logging.getLogger("securemailscope.storage")
TABLE_NAME = "analysis_results"

# Cache for detected column types to avoid redundant schema checks
_schema_cache: Optional[Dict[str, str]] = None


def _get_table_schema() -> Dict[str, str]:
    """
    Inspects the schema of analysis_results table via Supabase/PostgREST.
    Returns mapping of column_name -> data_type.
    """
    global _schema_cache
    if _schema_cache is not None:
        return _schema_cache

    _schema_cache = {}
    if not is_supabase_configured():
        return _schema_cache

    try:
        client = get_supabase_client()
        # PostgREST exposes OpenAPI definitions at root
        # Or we can do a limit=0 select to check returned column names
        res = client.table(TABLE_NAME).select("*").limit(1).execute()
        if res.data and len(res.data) > 0:
            sample = res.data[0]
            for k, v in sample.items():
                _schema_cache[k] = type(v).__name__
    except Exception as e:
        logger.debug(f"Schema introspection note: {e}")

    return _schema_cache


def extract_storage_row(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts and maps canonical database columns from an analyzed PCAP result dictionary.
    Columns in table 'analysis_results':
      - capture_id
      - filename
      - protocol
      - analyzed_at
      - ai_risk_score
      - ai_risk_tier
      - security_posture
      - posture_status
      - anomaly_status
      - tls_version
      - cipher
      - certificate_status
      - findings (JSON/JSONB)
    """
    filename = result.get("filename") or "capture.pcap"
    capture_id = result.get("capture_id") or f"pcap_{filename}"

    # Timestamp
    analyzed_at = result.get("analyzed_at")
    if not analyzed_at:
        analyzed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Identify primary session for session-level attributes
    sessions = result.get("sessions") or []
    primary_session = None
    if sessions:
        # Prioritize session with findings or take first
        vulnerable = [
            s for s in sessions
            if (isinstance(s, dict) and (
                (s.get("assessment") or {}).get("findings") or
                (s.get("posture") or {}).get("security_posture") in ("AT_RISK", "COMPROMISED")
            ))
        ]
        primary_session = vulnerable[0] if vulnerable else sessions[0]

    # Protocol
    protocol = None
    protocols_list = result.get("protocols") or []
    if protocols_list and isinstance(protocols_list, list) and len(protocols_list) > 0:
        first_proto = protocols_list[0]
        if isinstance(first_proto, dict):
            protocol = first_proto.get("protocol")
        elif isinstance(first_proto, str):
            protocol = first_proto
    if not protocol and primary_session:
        protocol = primary_session.get("protocol")
    if not protocol:
        protocol = "UNKNOWN"

    # AI Risk Score and Tier
    ai_risk = result.get("ai_risk") or (primary_session.get("ai_risk") if primary_session else {})
    if not isinstance(ai_risk, dict):
        ai_risk = {}
    ai_risk_score = ai_risk.get("score")
    if ai_risk_score is not None:
        try:
            ai_risk_score = float(ai_risk_score)
        except (ValueError, TypeError):
            ai_risk_score = 0.0
    ai_risk_tier = ai_risk.get("operational_risk_tier") or ai_risk.get("label") or "LOW"

    # Security Posture Score & Status
    posture = result.get("posture") or (primary_session.get("posture") if primary_session else {})
    if not isinstance(posture, dict):
        posture = {}
    posture_score = posture.get("score")
    if posture_score is not None:
        try:
            posture_score = int(posture_score)
        except (ValueError, TypeError):
            posture_score = 100
    else:
        posture_score = 100

    posture_status = (
        posture.get("security_posture") or
        result.get("posture_status") or
        ("SECURE" if posture_score >= 80 else "AT_RISK")
    )

    # Anomaly Status
    ai_analysis = (primary_session.get("ai_analysis") if primary_session else {}) or {}
    if not isinstance(ai_analysis, dict):
        ai_analysis = {}
    if ai_analysis.get("anomaly_detected") is True:
        anomaly_status = "ANOMALOUS"
    elif ai_analysis.get("anomaly_detected") is False:
        anomaly_status = "NORMAL"
    else:
        anomaly_status = ai_analysis.get("prediction") or ai_analysis.get("status") or "NORMAL"

    # TLS Information
    tls_info = (primary_session.get("tls") if primary_session else {}) or {}
    if not isinstance(tls_info, dict):
        tls_info = {}
    tls_version = tls_info.get("version")
    cipher = tls_info.get("cipher_suite")

    # Certificate Status
    cert_info = tls_info.get("certificate") or {}
    if not isinstance(cert_info, dict):
        cert_info = {}
    if cert_info.get("self_signed"):
        certificate_status = "SELF_SIGNED"
    elif cert_info.get("expiration_status") == "EXPIRED":
        certificate_status = "EXPIRED"
    elif cert_info.get("expiration_status") in ("VALID", "EXPIRING_SOON"):
        certificate_status = "VALID"
    elif cert_info.get("expiration_status"):
        certificate_status = cert_info.get("expiration_status")
    elif tls_version:
        certificate_status = "NOT_OBSERVABLE"
    else:
        certificate_status = "NONE"

    # Findings: collect assessment findings across sessions (JSON/JSONB)
    findings = []
    seen_finding_keys = set()
    for s in sessions:
        if isinstance(s, dict):
            s_findings = (s.get("assessment") or {}).get("findings") or []
            for f in s_findings:
                if isinstance(f, dict):
                    f_key = (f.get("finding_id") or f.get("id"), f.get("title"))
                    if f_key not in seen_finding_keys:
                        seen_finding_keys.add(f_key)
                        findings.append(f)

    # If top-level findings exist
    if not findings and result.get("findings"):
        findings = result.get("findings")

    # Adapt security_posture field to table column type (integer score vs string status)
    schema = _get_table_schema()
    sec_posture_col_type = schema.get("security_posture", "").lower()
    if "str" in sec_posture_col_type or "text" in sec_posture_col_type or "varchar" in sec_posture_col_type:
        sec_posture_val = posture_status
    else:
        # Default to integer posture score (0-100)
        sec_posture_val = posture_score

    row = {
        "capture_id": str(capture_id),
        "filename": str(filename),
        "protocol": str(protocol),
        "analyzed_at": str(analyzed_at),
        "ai_risk_score": ai_risk_score,
        "ai_risk_tier": str(ai_risk_tier),
        "security_posture": sec_posture_val,
        "posture_status": str(posture_status),
        "anomaly_status": str(anomaly_status),
        "tls_version": tls_version,
        "cipher": cipher,
        "certificate_status": str(certificate_status),
        "findings": findings,
    }

    return row


def format_db_row_to_capture(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms a database row from table 'analysis_results' into the frontend-compatible
    capture format, ensuring both top-level columns and nested structures (ai_risk, posture, sessions)
    are present so that all frontend views render seamlessly without modification.
    """
    capture_id = row.get("capture_id") or f"cap_{row.get('id', 'unknown')}"
    filename = row.get("filename") or "capture.pcap"
    protocol = row.get("protocol") or "UNKNOWN"
    analyzed_at = row.get("analyzed_at")
    ai_risk_score = row.get("ai_risk_score")
    if ai_risk_score is not None:
        try:
            ai_risk_score = float(ai_risk_score)
        except (ValueError, TypeError):
            ai_risk_score = None

    ai_risk_tier = row.get("ai_risk_tier") or "LOW"
    security_posture = row.get("security_posture")
    posture_status = row.get("posture_status") or "SECURE"
    anomaly_status = row.get("anomaly_status") or "NORMAL"
    tls_version = row.get("tls_version")
    cipher = row.get("cipher")
    certificate_status = row.get("certificate_status") or "NOT_OBSERVABLE"
    findings = row.get("findings") or []
    if not isinstance(findings, list):
        findings = []

    # Derive numeric score and string posture cleanly
    if isinstance(security_posture, (int, float)):
        posture_score = int(security_posture)
    else:
        posture_score = 100 if posture_status == "SECURE" else 40

    top_risk_factors = []
    for f in findings[:3]:
        if isinstance(f, dict):
            top_risk_factors.append({
                "feature": f.get("finding_id", "rule"),
                "label": f.get("title", ""),
                "observed": True
            })
    if not top_risk_factors:
        top_risk_factors = [{
            "feature": "none",
            "label": "No significant risk factors observed",
            "observed": False
        }]

    return {
        # Supabase record columns at top level
        "id": row.get("id"),
        "capture_id": capture_id,
        "filename": filename,
        "protocol": protocol,
        "protocols": [{"protocol": protocol, "confidence": "HIGH"}] if protocol else [],
        "analyzed_at": analyzed_at,
        "ai_risk_score": ai_risk_score,
        "ai_risk_tier": ai_risk_tier,
        "security_posture": security_posture,
        "posture_status": posture_status,
        "anomaly_status": anomaly_status,
        "tls_version": tls_version,
        "cipher": cipher,
        "certificate_status": certificate_status,
        "findings": findings,

        # Standard nested objects required by ExecutiveDashboard, OverviewScreen, ForensicsScreen
        "ai_risk": {
            "score": ai_risk_score,
            "operational_risk_tier": ai_risk_tier,
            "label": ai_risk_tier,
            "confidence": 0.85,
            "top_risk_factors": top_risk_factors
        },
        "posture": {
            "score": posture_score,
            "security_posture": posture_status,
            "configuration_posture": posture_status,
            "explanation": f"Security posture: {posture_status}. Protocol: {protocol}. TLS: {tls_version or 'N/A'}. Cipher: {cipher or 'N/A'}.",
            "finding_summary": {
                "critical": sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "CRITICAL"),
                "high": sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "HIGH"),
                "medium": sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "MEDIUM"),
                "low": sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "LOW"),
            }
        },
        "sessions": [
            {
                "session_id": "TCP-001",
                "protocol": protocol,
                "tls": {
                    "detected": bool(tls_version),
                    "version": tls_version,
                    "cipher_suite": cipher,
                    "certificate": {
                        "certificate_present": certificate_status not in ("NOT_OBSERVABLE", "NONE", None),
                        "expiration_status": certificate_status,
                        "status": certificate_status
                    }
                },
                "assessment": {
                    "findings": findings
                },
                "posture": {
                    "score": posture_score,
                    "security_posture": posture_status
                },
                "ai_analysis": {
                    "status": "EVALUATED",
                    "prediction": anomaly_status
                },
                "ai_risk": {
                    "score": ai_risk_score,
                    "operational_risk_tier": ai_risk_tier,
                    "label": ai_risk_tier
                }
            }
        ]
    }


def save_analysis_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Persists an analyzed PCAP result dictionary into the Supabase 'analysis_results' table.
    Preserves duplicate capture replacement behavior:
    - If capture_id already exists, updates/replaces the existing record.
    - If capture_id does not exist, inserts a new record.
    Returns the saved record dictionary.
    """
    row_data = extract_storage_row(result)
    capture_id = row_data["capture_id"]

    client = get_supabase_client()

    # Check for existing record by capture_id to preserve duplicate replacement behavior
    existing = client.table(TABLE_NAME).select("id").eq("capture_id", capture_id).execute()

    if existing.data and len(existing.data) > 0:
        # Update existing record
        response = client.table(TABLE_NAME).update(row_data).eq("capture_id", capture_id).execute()
    else:
        # Insert new record
        response = client.table(TABLE_NAME).insert(row_data).execute()

    if response.data and len(response.data) > 0:
        saved_row = response.data[0]
        # Attach persisted database metadata back to result
        result["id"] = saved_row.get("id")
        result["capture_id"] = saved_row.get("capture_id")
        result["analyzed_at"] = saved_row.get("analyzed_at")
        return saved_row

    return row_data


def get_analysis_results() -> List[Dict[str, Any]]:
    """
    Retrieves all stored analysis results from Supabase 'analysis_results',
    ordered by analyzed_at descending (latest first).
    Returns list of capture dictionaries compatible with frontend state.
    """
    client = get_supabase_client()
    response = client.table(TABLE_NAME).select("*").order("analyzed_at", desc=True).execute()

    results = []
    if response.data:
        for row in response.data:
            results.append(format_db_row_to_capture(row))

    return results


def get_analysis_result(capture_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a single analysis result by capture_id from Supabase.
    Returns formatted capture dictionary or None if not found.
    """
    client = get_supabase_client()
    response = client.table(TABLE_NAME).select("*").eq("capture_id", capture_id).execute()

    if response.data and len(response.data) > 0:
        return format_db_row_to_capture(response.data[0])

    return None


def delete_analysis_result(capture_id: str) -> bool:
    """
    Deletes an analysis result by capture_id from Supabase.
    Returns True if deleted, False otherwise.
    """
    client = get_supabase_client()
    response = client.table(TABLE_NAME).delete().eq("capture_id", capture_id).execute()
    return bool(response.data and len(response.data) > 0)


def get_available_periods() -> Dict[str, List[Dict[str, str]]]:
    """
    Retrieves available filter periods (distinct dates and months) dynamically
    from actual 'analysis_results.analyzed_at' values in Supabase.
    Dates are formatted as ISO 'YYYY-MM-DD' and human-readable '11 Sep 2026'.
    Months are formatted as ISO 'YYYY-MM' and human-readable 'September 2026'.
    Both lists are sorted newest-first (descending).
    """
    if not is_supabase_configured():
        return {"dates": [], "months": []}

    client = get_supabase_client()
    rows = []
    try:
        response = client.table(TABLE_NAME).select("analyzed_at").order("analyzed_at", desc=True).execute()
        rows = response.data or []
    except Exception as e:
        logger.warning(f"Failed to query analyzed_at with order: {e}. Trying full select.")
        try:
            response = client.table(TABLE_NAME).select("analyzed_at").execute()
            rows = response.data or []
        except Exception as e2:
            logger.error(f"Failed to select analyzed_at: {e2}")
            rows = []

    if not rows:
        return {"dates": [], "months": []}

    dates_map: Dict[str, str] = {}
    months_map: Dict[str, str] = {}

    for row in rows:
        raw_ts = row.get("analyzed_at")
        if not raw_ts:
            continue
        ts_str = str(raw_ts).strip().strip('"').strip("'")
        if not ts_str:
            continue
        try:
            # Handle ISO string with or without Z, or space-separated
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(clean_ts)
            date_key = dt.strftime("%Y-%m-%d")
            date_label = dt.strftime("%d %b %Y")
            if date_key not in dates_map:
                dates_map[date_key] = date_label

            month_key = dt.strftime("%Y-%m")
            month_label = dt.strftime("%B %Y")
            if month_key not in months_map:
                months_map[month_key] = month_label
        except Exception as parse_err:
            # Fallback simple string slice for YYYY-MM-DD
            if len(ts_str) >= 10 and ts_str[4] == "-" and ts_str[7] == "-":
                date_key = ts_str[:10]
                month_key = ts_str[:7]
                try:
                    parts = date_key.split("-")
                    fallback_d = datetime.date(int(parts[0]), int(parts[1]), int(parts[2]))
                    dates_map[date_key] = fallback_d.strftime("%d %b %Y")
                    months_map[month_key] = fallback_d.strftime("%B %Y")
                except Exception:
                    logger.debug(f"Fallback parse failed for {ts_str}: {parse_err}")

    sorted_dates = [
        {"value": k, "label": dates_map[k]}
        for k in sorted(dates_map.keys(), reverse=True)
    ]
    sorted_months = [
        {"value": k, "label": months_map[k]}
        for k in sorted(months_map.keys(), reverse=True)
    ]

    return {
        "dates": sorted_dates,
        "months": sorted_months
    }


def _score_to_risk_tier(score: Optional[float]) -> str:
    if score is None:
        return "Unscored"
    if score <= 20.0:
        return "LOW"
    if score <= 50.0:
        return "MODERATE"
    if score <= 80.0:
        return "HIGH"
    return "CRITICAL"


def _get_risk_styling(tier: str) -> tuple[str, str]:
    if tier == "LOW":
        return "#10b981", "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
    elif tier == "MODERATE":
        return "#f59e0b", "text-amber-400 border-amber-500/30 bg-amber-500/10"
    elif tier == "HIGH":
        return "#f43f5e", "text-rose-400 border-rose-500/30 bg-rose-500/10"
    elif tier == "CRITICAL":
        return "#991b1b", "text-rose-300 border-rose-600/40 bg-rose-950/40"
    return "#94a3b8", "text-slate-400 border-slate-700 bg-slate-800"


def get_dashboard_trends(
    period: str,
    date_str: Optional[str] = None,
    month_str: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieves trend and security status aggregation points for the Executive Dashboard graphs
    filtered strictly by Daily or Monthly period from Supabase 'analysis_results'.
    Performs careful date/time boundary queries against timestamptz analyzed_at.
    """
    # Validate period and provided date/month formats before database check
    if period == "daily":
        if date_str:
            try:
                datetime.date.fromisoformat(date_str)
            except (ValueError, TypeError):
                raise ValueError(f"Invalid date format '{date_str}'. Expected 'YYYY-MM-DD'.")
    elif period == "monthly":
        if month_str:
            try:
                parts = month_str.split("-")
                if len(parts) != 2:
                    raise ValueError()
                year = int(parts[0])
                month = int(parts[1])
                datetime.datetime(year, month, 1)
            except (ValueError, TypeError, IndexError):
                raise ValueError(f"Invalid month format '{month_str}'. Expected 'YYYY-MM'.")
    else:
        raise ValueError(f"Invalid period '{period}'. Must be 'daily' or 'monthly'.")

    if not is_supabase_configured():
        return {
            "period": period,
            "date": date_str,
            "month": month_str,
            "points": [],
            "summary": {
                "total": 0, "secure": 0, "insecure": 0,
                "securePct": 0, "insecurePct": 0, "avgRisk": None, "totalSessions": 0
            }
        }

    client = get_supabase_client()

    # Determine period boundaries
    if period == "daily":
        if not date_str:
            periods = get_available_periods()
            if periods["dates"]:
                date_str = periods["dates"][0]["value"]
            else:
                date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

        try:
            parsed_date = datetime.date.fromisoformat(date_str)
        except ValueError:
            raise ValueError(f"Invalid date format '{date_str}'. Expected 'YYYY-MM-DD'.")

        start_dt = datetime.datetime(parsed_date.year, parsed_date.month, parsed_date.day, 0, 0, 0, tzinfo=datetime.timezone.utc)
        end_dt = start_dt + datetime.timedelta(days=1)

    elif period == "monthly":
        if not month_str:
            periods = get_available_periods()
            if periods["months"]:
                month_str = periods["months"][0]["value"]
            else:
                month_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")

        try:
            parts = month_str.split("-")
            year = int(parts[0])
            month = int(parts[1])
            start_dt = datetime.datetime(year, month, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            if month == 12:
                end_dt = datetime.datetime(year + 1, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            else:
                end_dt = datetime.datetime(year, month + 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        except (ValueError, IndexError):
            raise ValueError(f"Invalid month format '{month_str}'. Expected 'YYYY-MM'.")
    else:
        raise ValueError(f"Invalid period '{period}'. Must be 'daily' or 'monthly'.")

    # Query only the required columns within the exact datetime boundary
    response = (
        client.table(TABLE_NAME)
        .select("id, capture_id, filename, analyzed_at, ai_risk_score, ai_risk_tier, security_posture, posture_status")
        .gte("analyzed_at", start_dt.isoformat())
        .lt("analyzed_at", end_dt.isoformat())
        .order("analyzed_at", desc=False)
        .execute()
    )

    rows = response.data or []

    # Overall period summary calculations
    total_reports = len(rows)
    total_secure = 0
    all_scores: List[float] = []

    for r in rows:
        is_sec = (r.get("posture_status") == "SECURE" or r.get("security_posture") == "SECURE")
        if is_sec:
            total_secure += 1
        if r.get("ai_risk_score") is not None:
            try:
                all_scores.append(float(r["ai_risk_score"]))
            except (ValueError, TypeError):
                pass

    total_insecure = total_reports - total_secure
    secure_pct = round((total_secure / total_reports) * 100) if total_reports > 0 else 0
    insecure_pct = round((total_insecure / total_reports) * 100) if total_reports > 0 else 0
    avg_risk = round(sum(all_scores) / len(all_scores), 1) if all_scores else None

    summary = {
        "total": total_reports,
        "secure": total_secure,
        "insecure": total_insecure,
        "securePct": secure_pct,
        "insecurePct": insecure_pct,
        "avgRisk": avg_risk,
        "totalSessions": total_reports
    }

    # Group rows into chart points
    buckets: Dict[str, Dict[str, Any]] = {}

    for r in rows:
        ts_str = r.get("analyzed_at")
        if not ts_str:
            continue
        try:
            dt = datetime.datetime.fromisoformat(ts_str)
        except Exception:
            continue

        if period == "monthly":
            # Group by day within month
            bucket_key = dt.strftime("%Y-%m-%d")
            bucket_label = dt.strftime("%d %b")
        else:
            # Daily: group by minute/time within day
            bucket_key = dt.strftime("%Y-%m-%dT%H:%M")
            bucket_label = dt.strftime("%H:%M")

        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "key": f"point-{bucket_key}",
                "dayKey": dt.strftime("%Y-%m-%d"),
                "label": bucket_label,
                "rows": []
            }

        buckets[bucket_key]["rows"].append(r)

    points: List[Dict[str, Any]] = []

    for b_key in sorted(buckets.keys()):
        b_data = buckets[b_key]
        b_rows = b_data["rows"]
        b_total = len(b_rows)
        b_secure = sum(1 for x in b_rows if (x.get("posture_status") == "SECURE" or x.get("security_posture") == "SECURE"))
        b_insecure = b_total - b_secure

        b_scores: List[float] = []
        for x in b_rows:
            if x.get("ai_risk_score") is not None:
                try:
                    b_scores.append(float(x["ai_risk_score"]))
                except (ValueError, TypeError):
                    pass

        has_valid_risk = len(b_scores) > 0
        b_avg_risk = round(sum(b_scores) / len(b_scores)) if has_valid_risk else None
        risk_tier = _score_to_risk_tier(b_avg_risk) if b_avg_risk is not None else None
        risk_level = risk_tier if risk_tier is not None else "Unscored"
        risk_dot_color, risk_badge_class = _get_risk_styling(risk_level)

        filenames = [x.get("filename") or "capture.pcap" for x in b_rows]
        pcaps_list = ", ".join(filenames)

        points.append({
            "key": b_data["key"],
            "dayKey": b_data["dayKey"],
            "label": b_data["label"],
            "secureReports": b_secure,
            "insecureReports": b_insecure,
            "totalReports": b_total,
            "reports": b_total,
            "avgRisk": b_avg_risk,
            "hasValidRisk": has_valid_risk,
            "riskLevel": risk_level,
            "riskTier": risk_tier,
            "riskDotColor": risk_dot_color,
            "riskBadgeClass": risk_badge_class,
            "totalSessions": b_total,
            "pcapsList": pcaps_list
        })

    return {
        "period": period,
        "date": date_str if period == "daily" else None,
        "month": month_str if period == "monthly" else None,
        "points": points,
        "summary": summary
    }

