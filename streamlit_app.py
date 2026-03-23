import base64
import json
import os
from datetime import datetime

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

PLATFORM_URL = os.getenv("PLATFORM_URL", "http://localhost:8001")
PROXY_BASE   = os.getenv("PROXY_BASE",   "http://localhost:8000")  # shown in setup guide only

st.set_page_config(page_title="AI Gateway", layout="wide")


# ── helpers ───────────────────────────────────────────────────────────────────

def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def decode_jwt(token: str) -> dict:
    try:
        seg = token.split(".")[1]
        seg += "=" * (4 - len(seg) % 4)
        return json.loads(base64.b64decode(seg))
    except Exception:
        return {}


def api_get(path: str, token: str, base: str = PLATFORM_URL):
    try:
        r = requests.get(f"{base}{path}", headers=_h(token), timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.error(f"API error ({path}): {exc}")
        return None


def api_post(path: str, body: dict, token: str | None = None, base: str = PLATFORM_URL):
    try:
        r = requests.post(
            f"{base}{path}",
            json=body,
            headers=_h(token) if token else {},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.error(f"API error ({path}): {exc}")
        return None


def api_delete(path: str, token: str, base: str = PLATFORM_URL) -> tuple[bool, str]:
    try:
        r = requests.delete(f"{base}{path}", headers=_h(token), timeout=10)
        r.raise_for_status()
        return True, ""
    except Exception as exc:
        return False, str(exc)


# ── USER APP ──────────────────────────────────────────────────────────────────

def user_login_page() -> None:
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.title("AI Gateway")
        st.markdown(" ")
        with st.form("user_login_form"):
            email    = st.text_input("Email")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Login", use_container_width=True):
                try:
                    r = requests.post(
                        f"{PLATFORM_URL}/auth/login",
                        json={"email": email, "password": password},
                        timeout=10,
                    )
                    if r.status_code == 200:
                        data    = r.json()
                        payload = decode_jwt(data["token"])
                        st.session_state.user_token = data["token"]
                        st.session_state.user_info  = {
                            "email":    email,
                            "team":     payload.get("team", ""),
                            "is_admin": data.get("is_admin", False),
                        }
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
                except Exception as exc:
                    st.error(f"Login failed: {exc}")


def user_sidebar() -> None:
    info = st.session_state.get("user_info", {})
    with st.sidebar:
        st.markdown(f"**{info.get('email', '')}**")
        team = info.get("team", "")
        if team:
            st.markdown(f"`{team}`")
        st.markdown("---")
        if st.button("Logout", key="user_logout_btn", use_container_width=True):
            for k in ("user_token", "user_info", "user_platform_token"):
                st.session_state.pop(k, None)
            st.rerun()


def section_token_status() -> None:
    jwt   = st.session_state.user_token
    usage = api_get("/portal/my-usage", jwt)
    if not usage:
        return

    status     = usage.get("token_status", "none")
    expires_at = usage.get("token_expires_at")

    BADGES = {
        "active":  "🟢 **Active**",
        "revoked": "🔴 **Revoked**",
        "expired": "🟡 **Expired**",
        "none":    "⚪ **No token**",
    }

    col_s, col_e, col_b = st.columns([2, 3, 2])
    col_s.markdown(BADGES.get(status, f"**{status.capitalize()}**"))

    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            col_e.markdown(f"Expires **{exp.strftime('%b %d, %Y')}**")
        except Exception:
            col_e.markdown(f"Expires {expires_at}")

    with col_b:
        if status == "active":
            if st.button("Rotate Token", key="rotate_btn"):
                _rotate_token(jwt)
        else:
            if st.button("Generate Token", key="gen_btn"):
                _generate_token(jwt)


def _generate_token(jwt: str, tool: str = "cursor") -> None:
    try:
        r = requests.post(
            f"{PLATFORM_URL}/portal/token/create",
            json={"tool": tool},
            headers=_h(jwt),
            timeout=10,
        )
        if r.ok:
            st.session_state.user_platform_token = r.json()["platform_token"]
            st.success("Token generated!")
            st.rerun()
        else:
            st.error(f"Failed: {r.text}")
    except Exception as exc:
        st.error(f"Error: {exc}")


def _rotate_token(jwt: str) -> None:
    try:
        tool = "cursor"
        tr   = requests.get(f"{PLATFORM_URL}/portal/token/my", headers=_h(jwt), timeout=10)
        if tr.status_code == 200:
            ts_list = tr.json()
            if not isinstance(ts_list, list):
                ts_list = [ts_list]
            active = next((t for t in ts_list if t.get("status") == "active"), None)
            if active:
                tool = active.get("tool", "cursor")

        requests.delete(f"{PLATFORM_URL}/portal/token/revoke", headers=_h(jwt), timeout=10)

        r = requests.post(
            f"{PLATFORM_URL}/portal/token/create",
            json={"tool": tool},
            headers=_h(jwt),
            timeout=10,
        )
        if r.ok:
            st.session_state.user_platform_token = r.json()["platform_token"]
            st.success("Token rotated!")
            st.rerun()
        else:
            st.error(f"Failed to create new token: {r.text}")
    except Exception as exc:
        st.error(f"Rotate failed: {exc}")


def section_setup_guide() -> None:
    plat_token = st.session_state.get("user_platform_token", "<your-token>")

    cline_tab, claude_tab = st.tabs(["Cline", "Claude Code"])

    with cline_tab:
        st.markdown("**Step 1 — Install Cline**")
        st.markdown("Open VS Code → Extensions → Search **Cline** → Install")

        st.markdown("**Step 2 — Open settings**")
        st.markdown("Click the Cline icon in the sidebar → click the gear icon ⚙")

        st.markdown("**Step 3 — Configure API Provider**")
        st.markdown("Set **API Provider** to **OpenAI Compatible**")

        st.markdown("**Step 4 — Set Base URL**")
        st.code(f"{PROXY_BASE}/v1", language="text")

        st.markdown("**Step 5 — Set API Key**")
        st.code(plat_token, language="text")

        st.markdown("**Step 6 — Set Model ID**")
        st.code("gpt-4o-mini", language="text")

        st.markdown("**Step 7 — Verify**")
        st.markdown("Type `say hello` in Cline chat to confirm everything is working")

    with claude_tab:
        st.markdown("**Step 1 — Install Claude Code**")
        st.code("npm install -g @anthropic-ai/claude-code", language="bash")

        st.markdown("**Step 2 — Set environment variables**")
        st.code(
            f"export ANTHROPIC_API_URL={PROXY_BASE}/v1\n"
            f"export ANTHROPIC_API_KEY={plat_token}",
            language="bash",
        )

        st.markdown("**Step 3 — Make permanent (optional)**")
        st.markdown("Add the above lines to `~/.zshrc` or `~/.bashrc`")

        st.markdown("**Step 4 — Run Claude Code**")
        st.code("claude", language="bash")
        st.markdown("Run this in any project folder to start")


def user_dashboard() -> None:
    user_sidebar()

    # If the logged-in user is an admin, redirect them to the admin panel
    if st.session_state.get("user_info", {}).get("is_admin"):
        st.info("You are logged in as an admin. Redirecting to the Admin Panel…")
        st.query_params["page"] = "admin"
        # Clear user session so admin login page is shown
        for k in ("user_token", "user_info", "user_platform_token"):
            st.session_state.pop(k, None)
        st.rerun()
        return

    st.title("AI Gateway")

    st.markdown("---")
    st.subheader("Token Status")
    section_token_status()

    st.markdown("---")
    st.subheader("Setup Instructions")
    section_setup_guide()


def show_user_app() -> None:
    if "user_token" not in st.session_state:
        user_login_page()
    else:
        user_dashboard()


# ── ADMIN APP ─────────────────────────────────────────────────────────────────

def admin_login_page() -> None:
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.title("Admin Panel")
        st.subheader("Restricted access")
        st.markdown(" ")
        with st.form("admin_login_form"):
            email    = st.text_input("Email",    key="adm_email_in")
            password = st.text_input("Password", key="adm_pwd_in", type="password")
            if st.form_submit_button("Login", use_container_width=True):
                try:
                    r = requests.post(
                        f"{PLATFORM_URL}/admin/auth/login",
                        json={"email": email, "password": password},
                        timeout=10,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if not data.get("is_admin"):
                            st.error("Access denied — admin credentials required")
                        else:
                            st.session_state.admin_token = data["token"]
                            st.session_state.admin_user  = {"email": email}
                            st.rerun()
                    else:
                        st.error("Access denied — admin credentials required")
                except Exception as exc:
                    st.error(f"Login failed: {exc}")


def admin_sidebar() -> None:
    with st.sidebar:
        st.markdown("**Admin Panel**")
        st.markdown("---")
        admin = st.session_state.get("admin_user", {})
        st.markdown(admin.get("email", ""))
        if st.button("Logout", key="admin_logout_btn", use_container_width=True):
            st.session_state.pop("admin_token", None)
            st.session_state.pop("admin_user",  None)
            st.rerun()


@st.fragment(run_every=30)
def admin_tab_overview() -> None:
    token = st.session_state.get("admin_token")
    if not token:
        return

    stats = api_get("/admin/stats", token, base=PLATFORM_URL)
    if stats:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Active Tokens",         stats.get("active_tokens", 0))
        c2.metric("Requests Today",        stats.get("requests_today", 0))
        c3.metric("Requests (last 5 min)", stats.get("requests_last_5min", 0))
        c4.metric("Revocations This Week", stats.get("revocations_this_week", 0))

    st.markdown("---")

def admin_tab_users() -> None:
    token = st.session_state.get("admin_token")
    if not token:
        return

    st.markdown("### User List")
    users = api_get("/admin/users", token, base=PLATFORM_URL)
    if users:
        keep = ["id", "email", "team", "is_admin", "token_status", "total_requests", "requests_today", "created_at"]
        df   = pd.DataFrame(users)
        cols = [c for c in keep if c in df.columns]
        st.dataframe(df[cols] if cols else df, use_container_width=True, hide_index=True)
    else:
        users = []

    st.markdown("---")
    st.markdown("### Manage User")
    if users:
        user_options = {f"{u['email']} (id={u['id']})": u for u in users}
        selected_label = st.selectbox("Select user", list(user_options.keys()), key="admin_sel_user")
        selected = user_options[selected_label]

        col_a, col_b, col_c = st.columns(3)

        with col_a:
            st.markdown("**Toggle Admin**")
            new_admin = not selected["is_admin"]
            label = "Revoke Admin" if selected["is_admin"] else "Grant Admin"
            if st.button(label, key="admin_toggle_btn"):
                try:
                    r = requests.patch(
                        f"{PLATFORM_URL}/admin/users/{selected['id']}",
                        json={"is_admin": new_admin},
                        headers=_h(token),
                        timeout=10,
                    )
                    if r.ok:
                        st.success(f"Updated — is_admin={new_admin}")
                        st.rerun()
                    else:
                        st.error(r.text)
                except Exception as exc:
                    st.error(str(exc))

        with col_b:
            st.markdown("**Revoke Active Token**")
            active_tid = selected.get("active_token_id")
            if active_tid and selected.get("token_status") == "active":
                if st.button("Revoke Token", key="admin_revoke_sel_btn"):
                    ok, err = api_delete(f"/admin/tokens/{active_tid}", token, base=PLATFORM_URL)
                    if ok:
                        st.success("Token revoked")
                        st.rerun()
                    else:
                        st.error(err)
            else:
                st.caption("No active token")

        with col_c:
            st.markdown("**Delete User**")
            if st.button("Delete User", key="admin_del_user_btn", type="primary"):
                try:
                    r = requests.delete(
                        f"{PLATFORM_URL}/admin/users/{selected['id']}",
                        headers=_h(token),
                        timeout=10,
                    )
                    if r.ok:
                        st.success("User deleted")
                        st.rerun()
                    else:
                        st.error(r.text)
                except Exception as exc:
                    st.error(str(exc))

    st.markdown("---")
    st.markdown("### Add New User")
    with st.form("admin_add_user_form"):
        new_email    = st.text_input("Email",    key="admin_nu_email")
        new_password = st.text_input("Password", key="admin_nu_pwd",  type="password")
        new_team     = st.text_input("Team",     key="admin_nu_team")
        new_is_admin = st.checkbox("Admin?",     key="admin_nu_is_admin")
        if st.form_submit_button("Create User", use_container_width=True):
            if new_email and new_password and new_team:
                try:
                    r = requests.post(
                        f"{PLATFORM_URL}/admin/users",
                        json={"email": new_email, "password": new_password,
                              "team": new_team, "is_admin": new_is_admin},
                        headers=_h(token),
                        timeout=10,
                    )
                    if r.ok:
                        st.success(f"User {new_email} created")
                        st.rerun()
                    else:
                        st.error(r.text)
                except Exception as exc:
                    st.error(str(exc))
            else:
                st.warning("Fill in all fields")


def admin_tab_settings() -> None:
    token = st.session_state.get("admin_token")
    if not token:
        return

    settings = api_get("/admin/settings", token, base=PLATFORM_URL)
    if not settings:
        return

    st.markdown("**Global Rate Limit Configuration**")
    st.caption("Changes take effect on the proxy within 5 minutes.")

    with st.form("admin_settings_form"):
        new_limit  = st.number_input(
            "Max requests per window",
            min_value=1, max_value=10000,
            value=settings.get("rate_limit", 30),
            key="admin_rate_limit",
        )
        new_window = st.number_input(
            "Window size (seconds)",
            min_value=1, max_value=3600,
            value=settings.get("rate_window", 60),
            key="admin_rate_window",
        )
        if st.form_submit_button("Save Settings", use_container_width=True):
            try:
                r = requests.put(
                    f"{PLATFORM_URL}/admin/settings",
                    json={"rate_limit": int(new_limit), "rate_window": int(new_window)},
                    headers=_h(token),
                    timeout=10,
                )
                if r.ok:
                    st.success(f"Saved — {new_limit} req / {new_window}s window")
                else:
                    st.error(r.text)
            except Exception as exc:
                st.error(str(exc))


def admin_dashboard() -> None:
    admin_sidebar()
    st.title("Admin Dashboard")

    tab1, tab2, tab3 = st.tabs([
        "Overview", "Users", "Settings"
    ])

    with tab1:
        admin_tab_overview()
    with tab2:
        admin_tab_users()
    with tab3:
        admin_tab_settings()


def show_admin_app() -> None:
    if "admin_token" not in st.session_state:
        admin_login_page()
    else:
        admin_dashboard()


# ── ROUTING ───────────────────────────────────────────────────────────────────

page = st.query_params.get("page", "user")
if page == "admin":
    show_admin_app()
else:
    show_user_app()
