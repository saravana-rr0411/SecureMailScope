from fastapi import Request, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.storage.supabase_client import get_supabase_client, is_supabase_configured

security = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Validates the Supabase JWT token and extracts the user ID and role.
    If Supabase is not configured (e.g., local mock mode), bypasses authentication.
    """
    if not is_supabase_configured():
        return {"id": "anonymous", "role": "ANONYMOUS"}
    
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing authorization credentials")
        
    token = credentials.credentials
    client = get_supabase_client()
    
    try:
        # Validate JWT token with Supabase Auth
        user_response = client.auth.get_user(token)
        if not user_response or not user_response.user:
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
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


async def require_soc_or_executive(user: dict = Security(get_current_user)):
    """
    Enforces that the authenticated user possesses the SOC_ANALYST or EXECUTIVE role.
    """
    if user.get("role") not in ["SOC_ANALYST", "EXECUTIVE", "ANONYMOUS"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions. Requires SOC_ANALYST or EXECUTIVE role.")
    return user
