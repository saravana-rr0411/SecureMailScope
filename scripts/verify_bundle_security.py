#!/usr/bin/env python3
"""
Bundle Security Verification Script.
Scans the frontend production build directory (frontend/dist/) and verifies:
1. No capture-agent secret or token ('sms-capture-secret-dev-key', etc.) is exposed.
2. No long-lived authorization headers or API keys are leaked into production bundles.
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "frontend" / "dist"

FORBIDDEN_PATTERNS = [
    "sms-capture-secret-dev-key",
    "Bearer sms-capture",
    "CAPTURE_AGENT_SECRET_KEY",
    "CAPTURE_AGENT_API_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "service_role",
    "sbp_",
]


def verify_bundle():
    if not DIST_DIR.exists():
        print(f"[-] Error: {DIST_DIR} does not exist. Run 'npm run build' first.")
        sys.exit(1)

    found_violations = []
    scanned_files = 0

    for root, _, files in os.walk(DIST_DIR):
        for f in files:
            file_path = Path(root) / f
            if file_path.suffix in (".js", ".html", ".css", ".map"):
                scanned_files += 1
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for pattern in FORBIDDEN_PATTERNS:
                        if pattern in content:
                            found_violations.append((str(file_path.relative_to(PROJECT_ROOT)), pattern))
                except Exception as e:
                    print(f"[-] Warning reading {file_path}: {e}")

    print(f"[*] Scanned {scanned_files} production bundle files in {DIST_DIR.relative_to(PROJECT_ROOT)}...")

    if found_violations:
        print("[-] SECURITY VIOLATION: Hardcoded secret pattern(s) found in production bundle:")
        for path, pattern in found_violations:
            print(f"    - File: {path}, Pattern: '{pattern}'")
        sys.exit(1)

    print("[+] SUCCESS: Zero capture-agent secrets or long-lived keys found in production bundle!")


if __name__ == "__main__":
    verify_bundle()
