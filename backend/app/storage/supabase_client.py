import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from supabase import create_client, Client

# Automatically find and load .env from project root, current directory, or backend directory
_current_file = Path(__file__).resolve()
_backend_dir = _current_file.parent.parent.parent
_project_root = _backend_dir.parent

# Load .env candidates in order
for env_path in [
    _project_root / ".env",
    _backend_dir / ".env",
    Path.cwd() / ".env"
]:
    if env_path.is_file():
        load_dotenv(dotenv_path=env_path, override=False)

_client_instance: Optional[Client] = None


def get_supabase_credentials() -> tuple[str, str]:
    """
    Retrieves and validates SUPABASE_URL and SUPABASE_KEY / SUPABASE_SERVICE_ROLE_KEY from environment variables.
    Fails clearly if either is missing or unconfigured.
    Credentials remain backend-only.
    """
    supabase_url = os.getenv("SUPABASE_URL", "").strip()
    supabase_key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY", "")).strip()

    missing = []
    if not supabase_url:
        missing.append("SUPABASE_URL")
    if not supabase_key:
        missing.append("SUPABASE_KEY or SUPABASE_SERVICE_ROLE_KEY")

    if missing:
        raise RuntimeError(
            f"Missing required Supabase environment variable(s): {', '.join(missing)}. "
            "Please configure SUPABASE_URL and SUPABASE_KEY (or SUPABASE_SERVICE_ROLE_KEY) in your backend .env file or environment."
        )

    return supabase_url, supabase_key


def is_supabase_configured() -> bool:
    """Returns True if both SUPABASE_URL and SUPABASE_KEY / SUPABASE_SERVICE_ROLE_KEY are present in the environment."""
    url = os.getenv("SUPABASE_URL", "").strip()
    key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY", "")).strip()
    return bool(url and key)


def get_supabase_client() -> Client:
    """
    Initializes and returns the singleton Supabase client.
    Fails clearly with descriptive RuntimeError if credentials are not configured.
    """
    global _client_instance
    if _client_instance is not None:
        return _client_instance

    url, key = get_supabase_credentials()
    try:
        _client_instance = create_client(url, key)
        return _client_instance
    except Exception as e:
        raise RuntimeError(f"Failed to initialize Supabase client: {str(e)}") from e


def reset_supabase_client() -> None:
    """Resets the cached client instance, useful for testing or environment reloads."""
    global _client_instance
    _client_instance = None
