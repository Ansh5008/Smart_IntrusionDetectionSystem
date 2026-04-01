"""Authentication module — Supabase GoTrue Auth (sign_up / sign_in_with_password)."""
from __future__ import annotations

import re
try:
    from gotrue.errors import AuthApiError
except ImportError:
    AuthApiError = Exception  # type: ignore[assignment,misc]

from backend.supabase_config import supabase


# ── Validation ────────────────────────────────────────────────────────────────
def _validate_signup(username: str, email: str, password: str, confirm: str) -> str | None:
    if not username or len(username) < 3:
        return "Username must be at least 3 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return "Username may only contain letters, digits, and underscores."
    if not email or "@" not in email:
        return "Enter a valid email address."
    if len(password) < 6:
        return "Password must be at least 6 characters."
    if password != confirm:
        return "Passwords do not match."
    return None


# ── Public API ────────────────────────────────────────────────────────────────
def signup_user(
    username: str,
    email: str,
    password: str,
    confirm: str,
    full_name: str = "",
    role: str = "analyst",
) -> tuple[bool, str]:
    err = _validate_signup(username, email, password, confirm)
    if err:
        return False, err

    # Check username uniqueness (email uniqueness is enforced by Supabase Auth)
    try:
        existing = supabase.table("profiles").select("id").eq("username", username).execute()
        if existing.data:
            return False, "Username already taken."
    except Exception as e:
        return False, f"Sign-up error: {e}"

    try:
        # Register with Supabase Auth — GoTrue handles password hashing & storage
        res = supabase.auth.sign_up(
            {
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username,
                        "full_name": full_name,
                        "role": role,
                    }
                },
            }
        )

        if res.user is None:
            return False, "Sign-up failed. The email may already be registered."

        # Profile is created automatically by the on_auth_user_created trigger
        # which reads username, full_name, and role from raw_user_meta_data.
        return True, "Account created successfully!"

    except AuthApiError as e:
        msg = str(e)
        if "already registered" in msg.lower() or "already exists" in msg.lower():
            return False, "Email already registered."
        return False, f"Sign-up error: {msg}"
    except Exception as e:
        return False, f"Sign-up error: {e}"


def login_user(username_or_email: str, password: str) -> tuple[bool, str, dict | None]:
    """Login using email or username. Supabase Auth handles password verification."""
    email = username_or_email

    # If no '@', treat as username → look up associated email from profiles
    if "@" not in username_or_email:
        try:
            profile = (
                supabase.table("profiles")
                .select("email")
                .eq("username", username_or_email)
                .limit(1)
                .execute()
            )
            if not profile.data or not profile.data[0].get("email"):
                return False, "Username not found.", None
            email = profile.data[0]["email"]
        except Exception as e:
            return False, f"Login error: {e}", None

    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})

        if res.user is None:
            return False, "Login failed.", None

        # Fetch profile extras
        profile_res = (
            supabase.table("profiles")
            .select("username, full_name, role")
            .eq("id", res.user.id)
            .limit(1)
            .execute()
        )
        prof = profile_res.data[0] if profile_res.data else {}

        return True, "Login successful!", {
            "id": res.user.id,
            "email": res.user.email,
            "username": prof.get("username", res.user.email),
            "full_name": prof.get("full_name", ""),
            "role": prof.get("role", "analyst"),
        }

    except AuthApiError as e:
        msg = str(e).lower()
        if "invalid" in msg or "credentials" in msg:
            return False, "Invalid login credentials. If you signed up with Google, please use 'Continue with Google' below, or set a password via 'Recover Access'.", None
        return False, f"Login error: {e}", None
    except Exception as e:
        return False, f"Login error: {e}", None


def get_google_auth_url() -> str:
    """Get the Google OAuth sign-in URL from Supabase."""
    try:
        res = supabase.auth.sign_in_with_oauth(
            {
                "provider": "google",
                "options": {
                    "redirect_to": "http://localhost:8501"
                }
            }
        )
        return res.url
    except Exception:
        return ""


def get_user_count() -> int:
    try:
        result = supabase.table("profiles").select("id", count="exact").execute()
        return result.count if result.count is not None else 0
    except Exception:
        return 0


def send_password_reset_email(email: str) -> tuple[bool, str]:
    """Send a password reset email using Supabase Auth."""
    try:
        # Supabase expects the email to exist
        res = supabase.auth.reset_password_email(email)
        return True, "Password reset email sent!"
    except AuthApiError as e:
        msg = str(e).lower()
        if "rate limit" in msg:
            return False, "Rate limit exceeded. Try again later."
        return False, f"Failed to send reset email: {e}"
    except Exception as e:
        return False, f"Error: {e}"


def update_password(new_password: str) -> tuple[bool, str]:
    """Update password for the currently signed-in (session) user."""
    if len(new_password) < 6:
        return False, "Password must be at least 6 characters."
        
    try:
        res = supabase.auth.update_user({"password": new_password})
        if res.user:
            return True, "Password updated successfully!"
        return False, "Failed to update password."
    except Exception as e:
        return False, f"Error updating password: {e}"


def get_all_profiles() -> list[dict]:
    """Retrieve all user profiles from the profiles table (Admin only)."""
    try:
        res = supabase.table("profiles").select("*").execute()
        return res.data if res.data else []
    except Exception:
        return []


def update_profile(user_id: str, updates: dict) -> bool:
    """Allow a user to update their own profile data (name, avatar, etc)."""
    try:
        supabase.table("profiles").update(updates).eq("id", user_id).execute()
        return True
    except Exception:
        return False


def update_profile_role(user_id: str, new_role: str) -> bool:
    """Allow an Admin to update another user's role."""
    try:
        supabase.table("profiles").update({"role": new_role}).eq("id", user_id).execute()
        return True
    except Exception:
        return False

