#!/usr/bin/env python3
"""
SecureMailScope - Initial User Provisioning Script

Safely provisions the initial application accounts with authoritative database roles
using the Supabase Auth Admin API and service-role credentials.

Supported Roles:
  1. SOC_ANALYST  -> Workstation: Overview, Forensics & AI Risk
  2. EXECUTIVE    -> Workstation: Executive Dashboard

Usage:
  python scripts/create_initial_users.py
  python scripts/create_initial_users.py --soc-email analyst@example.com --exec-email exec@example.com
"""

import os
import sys
import argparse
import getpass
from pathlib import Path
from dotenv import load_dotenv

# Automatically resolve root .env
_script_dir = Path(__file__).resolve().parent
_project_root = _script_dir.parent
load_dotenv(_project_root / ".env")

try:
    from supabase import create_client, Client
except ImportError:
    print("Error: 'supabase' Python package is required. Install with: pip install supabase")
    sys.exit(1)


def get_admin_client() -> Client:
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_KEY", "").strip()

    if not url or not key:
        print("Error: Missing SUPABASE_URL or SUPABASE_KEY in .env file.")
        print("Please ensure your backend credentials are configured before provisioning users.")
        sys.exit(1)

    try:
        return create_client(url, key)
    except Exception as e:
        print(f"Failed to initialize Supabase admin client: {e}")
        sys.exit(1)


def provision_user(client: Client, email: str, password: str, role: str) -> str:
    """
    Creates an authenticated user in Supabase Auth (if not already existing)
    and assigns the authoritative application role in public.user_roles.
    """
    print(f"\n[*] Provisioning user: {email} [Role: {role}]")

    user_id = None

    # 1. Check if user already exists in auth.users
    try:
        existing_users = client.auth.admin.list_users()
        user_list = existing_users if isinstance(existing_users, list) else getattr(existing_users, "users", [])
        for u in user_list:
            if getattr(u, "email", "").lower() == email.lower():
                user_id = getattr(u, "id", None)
                print(f"  [i] User already exists in Supabase Auth (ID: {user_id}).")
                break
    except Exception as e:
        print(f"  [!] Warning while listing users: {e}")

    # 2. Create user if not present
    if not user_id:
        try:
            created = client.auth.admin.create_user({
                "email": email,
                "password": password,
                "email_confirm": True,
            })
            # Handle SDK response wrapper
            user_obj = getattr(created, "user", created)
            user_id = getattr(user_obj, "id", None)
            if not user_id and isinstance(created, dict):
                user_id = created.get("user", {}).get("id") or created.get("id")

            print(f"  [+] Supabase Auth account created successfully (ID: {user_id}).")
        except Exception as e:
            print(f"  [-] Failed to create user in Supabase Auth: {e}")
            return None

    # 3. Assign role in public.user_roles table
    try:
        res = client.table("user_roles").upsert({
            "user_id": user_id,
            "role": role,
        }).execute()
        print(f"  [+] Role '{role}' successfully assigned in public.user_roles.")
        return user_id
    except Exception as e:
        print(f"  [-] Failed to assign role in public.user_roles: {e}")
        print("      Make sure you have executed the schema migration in database/schema.sql in Supabase SQL Editor.")
        return None


def main():
    parser = argparse.ArgumentParser(description="Provision initial SecureMailScope application accounts.")
    parser.add_argument("--soc-email", help="Email for SOC Analyst account (placeholder: SOC_ANALYST_EMAIL)")
    parser.add_argument("--exec-email", help="Email for Executive account (placeholder: EXECUTIVE_EMAIL)")
    args = parser.parse_args()

    print("==================================================================")
    print(" SecureMailScope - Initial User & Role Provisioning Utility")
    print("==================================================================")

    client = get_admin_client()

    # 1. Provision SOC Analyst Account
    soc_email = args.soc_email
    if not soc_email:
        soc_email = input("\nEnter SOC Analyst Email (e.g. analyst@example.com): ").strip()
    if not soc_email:
        print("Error: SOC Analyst email is required.")
        sys.exit(1)

    soc_password = getpass.getpass(f"Enter password for SOC Analyst ({soc_email}): ")
    if not soc_password:
        print("Error: Password cannot be empty.")
        sys.exit(1)

    soc_id = provision_user(client, soc_email, soc_password, "SOC_ANALYST")

    # 2. Provision Executive Account
    exec_email = args.exec_email
    if not exec_email:
        exec_email = input("\nEnter Executive Email (e.g. executive@example.com): ").strip()
    if not exec_email:
        print("Error: Executive email is required.")
        sys.exit(1)

    exec_password = getpass.getpass(f"Enter password for Executive ({exec_email}): ")
    if not exec_password:
        print("Error: Password cannot be empty.")
        sys.exit(1)

    exec_id = provision_user(client, exec_email, exec_password, "EXECUTIVE")

    print("\n==================================================================")
    print(" Provisioning Summary:")
    print(f"  - SOC Analyst: {soc_email} -> Role: SOC_ANALYST (Status: {'SUCCESS' if soc_id else 'FAILED'})")
    print(f"  - Executive:   {exec_email} -> Role: EXECUTIVE   (Status: {'SUCCESS' if exec_id else 'FAILED'})")
    print("==================================================================")


if __name__ == "__main__":
    main()
