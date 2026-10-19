"""Shared Streamlit helpers: session access, the identity sidebar, key re-fetch.

These live apart from client/app.py on purpose. Streamlit runs each page as its
own script, so a page importing the entry script would execute the login form a
second time.
"""
import streamlit as st

from client import vault as vaultlib  # noqa: F401  (keystore_path below)
from client.api import ApiError


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
    v = get_vault()
    with st.sidebar:
        st.markdown("### SecureVault")
        if v is None:
            st.caption("Not signed in")
            return
        st.write("**%s**%s" % (v.username, " (admin)" if v.user.get("is_admin") else ""))
        st.caption("Attributes")
        for a in v.user.get("attributes", []):
            st.caption("- %s" % a)
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
