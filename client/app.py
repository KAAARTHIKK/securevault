"""SecureVault Streamlit client -- login, key fetch, keystore unlock (doc 06 Phase 3).

Run with:  streamlit run client/app.py

All encryption and decryption happens in this process. The backend only ever
sees ciphertext, ABE ciphertexts of the file key, and metadata.
"""
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from client import vault as vaultlib  # noqa: E402
from client.api import ApiError, DEFAULT_BASE_URL, SecureVaultApi  # noqa: E402
from client.ui import get_vault, sidebar_identity  # noqa: E402

st.set_page_config(page_title="SecureVault", page_icon="*", layout="wide")


def login_form():
    st.title("SecureVault")
    st.caption(
        "Zero-trust encrypted storage. Files are encrypted on this machine with AES-256-GCM; "
        "the file key is sealed with CP-ABE so only attributes satisfying the policy can open it."
    )

    with st.form("login"):
        base_url = st.text_input("API base URL", value=DEFAULT_BASE_URL)
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        keystore_password = st.text_input(
            "Keystore password (optional)", type="password",
            help="Protects the local ABE secret key file. Defaults to your login password.",
        )
        verify_tls = st.checkbox(
            "Verify TLS certificate", value=True,
            help="Uncheck only for the self-signed certificate in the local demo.",
        )
        submitted = st.form_submit_button("Sign in")

    if not submitted:
        return

    api = SecureVaultApi(base_url, verify=verify_tls)
    try:
        with st.spinner("Signing in, fetching public params and unlocking your ABE key..."):
            v = vaultlib.login(api, username, password, keystore_password=keystore_password or None)
    except ApiError as exc:
        st.error(exc.message)
        return
    except Exception as exc:
        st.error(
            "Could not unlock the local keystore (%s). If you forgot the keystore password, "
            "delete %s and sign in again to be issued a fresh key."
            % (type(exc).__name__, vaultlib.keystore_path(username))
        )
        return

    st.session_state["vault"] = v
    st.session_state["login_password"] = password
    st.session_state["keystore_password"] = keystore_password or password
    st.rerun()


def dashboard():
    v = get_vault()
    st.title("Signed in as %s" % v.username)

    if v.user.get("key_stale"):
        st.warning(
            "Your attribute versions changed since this key was issued. "
            "Use **Re-fetch ABE key** in the sidebar before uploading or downloading."
        )
    else:
        st.success("ABE secret key unlocked and current.")

    col1, col2, col3 = st.columns(3)
    col1.metric("Attributes", len(v.user.get("attributes", [])))
    try:
        files = v.api.files_list()
        col2.metric("Files visible", len(files))
        col3.metric("Files you own", sum(1 for f in files if f["owner_id"] == str(v.user_id)))
    except ApiError as exc:
        st.error(exc.message)

    st.markdown(
        "Use the pages in the sidebar: **Upload** to seal a file under a policy, "
        "**Files** to download and decrypt, **Admin** to grant or revoke attributes."
    )


sidebar_identity()
if get_vault() is None:
    login_form()
else:
    dashboard()
