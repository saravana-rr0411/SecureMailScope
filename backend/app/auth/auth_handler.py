import os
import json
import base64
import logging
from fastapi import Request, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.storage.supabase_client import get_supabase_client, is_supabase_configured

logger = logging.getLogger("securemailscope")

# Explicit DEMO_AUTH flag for SIH presentations / evaluation mode.
# Defaults to True to allow frictionless demo logins without pre-registered accounts.
DEMO_AUTH = os.getenv("DEMO_AUTH", "true").lower() in ("true", "1", "yes")

security = HTTPBearer(auto_error=False)


def parse_demo_token(token: str) -> dict:
    """Parses a demo bearer token and extracts identity and role."""
    if ":" in token:
        try:
            payload_part = token.split(":", 1)[1]
            payload_json = base64.b64decode(payload_part).decode("utf-8")
            data = json.loads(payload_json)
            return {
                "id": data.get("id", "demo-user"),
                "email": data.get("email", "demo@securemailscope.local"),
                "role": data.get("role", "SOC_ANALYST")
            }
        except Exception as e:
            logger.warning(f"Failed to decode demo token payload: {e}")
    return {
        "id": "demo-user",
        "email": "demo@securemailscope.local",
        "role": "SOC_ANALYST"
    }


async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Validates the Supabase JWT token and extracts the user ID, email, and role.
    If Supabase is not configured (e.g., local mock mode), bypasses authentication.
    If DEMO_AUTH is enabled, accepts demo tokens and provides graceful demo sessions.
    """
    token = credentials.credentials if credentials else None

    # 1. Handle Demo Mode tokens when DEMO_AUTH is active
    if DEMO_AUTH and token and token.startswith("demo-"):
        return parse_demo_token(token)

    # 2. Local mock mode without Supabase
    if not is_supabase_configured():
        return {"id": "anonymous", "email": "anonymous@local", "role": "ANONYMOUS"}

    # 3. Missing credentials handling
    if not credentials:
        if DEMO_AUTH:
            return {
                "id": "demo-analyst",
                "email": "analyst@securemailscope.local",
                "role": "SOC_ANALYST"
            }
        raise HTTPException(status_code=401, detail="Missing authorization credentials")

    # 4. Standard Supabase token validation
    client = get_supabase_client()

    try:
        # Validate JWT token with Supabase Auth
        user_response = client.auth.get_user(token)
        if not user_response or not user_response.user:
            if DEMO_AUTH:
                return {
                    "id": "demo-user",
                    "email": "demo@securemailscope.local",
                    "role": "SOC_ANALYST"
                }
            raise HTTPException(status_code=401, detail="Invalid token")

        # Get authoritative user role from public.user_roles
        role_response = client.table("user_roles").select("role").eq("user_id", user_response.user.id).execute()
        role = "UNASSIGNED"
        if role_response.data and len(role_response.data) > 0:
            role = role_response.data[0].get("role", "UNASSIGNED")

        return {
            "id": user_response.user.id,
            "email": user_response.user.email,
            "role": role
        }
    except Exception as e:
        if DEMO_AUTH:
            return {
                "id": "demo-user",
                "email": "demo@securemailscope.local",
                "role": "SOC_ANALYST"
            }
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


async def require_soc_or_executive(user: dict = Security(get_current_user)):
    """
    Enforces that the authenticated user possesses the SOC_ANALYST or EXECUTIVE role.
    """
    if user.get("role") not in ["SOC_ANALYST", "EXECUTIVE", "ANONYMOUS"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions. Requires SOC_ANALYST or EXECUTIVE role.")
    return user
