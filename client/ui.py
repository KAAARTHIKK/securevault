"""Shared Streamlit helpers: session access, the identity sidebar, key re-fetch.

These live apart from client/app.py on purpose. Streamlit runs each page as its
own script, so a page importing the entry script would execute the login form a
second time.
"""
import streamlit as st

from client import vault as vaultlib  # noqa: F401  (keystore_path below)
from client.api import ApiError


_CSS = """
<style>
#MainMenu, footer, [data-testid="stDecoration"] {visibility: hidden;}
.block-container {padding-top: 2.2rem; max-width: 1150px;}
h1 {font-weight: 700; letter-spacing: -0.02em;}
[data-testid="stForm"], [data-testid="stMetric"], [data-testid="stExpander"] {
  background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px;
}
[data-testid="stForm"] {padding: 1.4rem 1.4rem 0.6rem;}
[data-testid="stMetric"] {padding: 0.9rem 1.1rem;}
[data-testid="stSidebar"] {background: #0f172a;}
[data-testid="stSidebar"] * {color: #e2e8f0;}
[data-testid="stSidebar"] button {background: #1e293b; border: 1px solid #334155;}
[data-testid="stSidebar"] [data-testid="stExpander"] {background: #1e293b; border-color: #334155;}
.sv-pill {display: inline-block; margin: 2px 4px 2px 0; padding: 2px 9px; border-radius: 999px;
  background: #1e3a8a; color: #dbeafe !important; font-size: 0.75rem; font-weight: 600;}
.sv-brand {font-size: 1.15rem; font-weight: 700; margin-bottom: 0.2rem;}
.sv-muted {color: #94a3b8 !important; font-size: 0.8rem;}
</style>
"""


def apply_style():
    st.markdown(_CSS, unsafe_allow_html=True)


def pills(names):
    return "".join('<span class="sv-pill">%s</span>' % n for n in names)


def get_vault():
    """The unlocked Vault for this session, or None if not signed in."""
    return st.session_state.get("vault")


def require_vault():
    """Page guard: stops rendering unless signed in."""
    v = get_vault()
    if v is None:
        st.warning("Sign in on the main page first.")
        st.stop()
    return v


def reissue_key():
    """Issue a fresh ABE secret key for the current attribute versions.

    The API client also does this automatically on a 409 KEY_STALE; this button
    is for re-fetching before an operation rather than in reaction to one.
    """
    v = get_vault()
    if v is None:
        st.sidebar.error("Sign in again to re-fetch the key.")
        return
    try:
        v.refresh_key(keystore_password=st.session_state.get("keystore_password"))
        st.sidebar.success("Fresh key issued.")
        st.rerun()
    except ApiError as exc:
        st.sidebar.error(exc.message)


def sidebar_identity():
    """Identity panel shared by every page."""
    apply_style()
    v = get_vault()
    with st.sidebar:
        st.markdown('<div class="sv-brand">🔐 SecureVault</div>', unsafe_allow_html=True)
        if v is None:
            st.markdown('<span class="sv-muted">Not signed in</span>', unsafe_allow_html=True)
            return
        st.markdown(
            "**%s**%s" % (v.username, " · admin" if v.user.get("is_admin") else ""),
        )
        st.markdown(pills(v.user.get("attributes", [])), unsafe_allow_html=True)
        st.write("")
        with st.expander("ABE key"):
            st.caption("Versioned attributes in this key:")
            for a in v.versioned_attributes:
                st.caption("- %s" % a)
            st.caption("Stored at %s" % vaultlib.keystore_path(v.username))
        if st.button("Re-fetch ABE key", help="Issue a fresh key for the current attribute versions"):
            reissue_key()
        if st.button("Sign out"):
            for key in ("vault", "login_password", "keystore_password"):
                st.session_state.pop(key, None)
            st.rerun()
