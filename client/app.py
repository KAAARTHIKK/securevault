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
from client.ui import get_vault, pills, sidebar_identity  # noqa: E402

st.set_page_config(page_title="SecureVault", page_icon="🔐", layout="wide")


def login_form():
    _, card, _ = st.columns([1, 1.3, 1])
    with card:
        st.title("🔐 SecureVault")
        st.caption(
            "Zero-trust encrypted storage. Files are encrypted on this machine with "
            "AES-256-GCM, and each file key is sealed with CP-ABE."
        )
        alert = st.empty()

        with st.form("login"):
            username = st.text_input("Username", placeholder="e.g. prof_a")
            password = st.text_input("Password", type="password")
            with st.expander("Advanced"):
                base_url = st.text_input("API base URL", value=DEFAULT_BASE_URL)
                keystore_password = st.text_input(
                    "Keystore password (optional)", type="password",
                    help="Protects the local ABE secret key file. Defaults to your login password.",
                )
                verify_tls = st.checkbox(
                    "Verify TLS certificate", value=True,
                    help="Uncheck only for the self-signed certificate in the local demo.",
                )
            submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)

        with st.expander("Demo accounts"):
            st.markdown(
                "| User | Password | Attributes |\n|---|---|---|\n"
                "| `prof_a` | `prof-a-pass` | DEPT_CSE, ROLE_FACULTY |\n"
                "| `hod` | `hod-pass` | DEPT_CSE, ROLE_HOD, ROLE_FACULTY |\n"
                "| `prof_b` | `prof-b-pass` | DEPT_CSE (ROLE_FACULTY revoked) |\n"
                "| `student_s` | `student-s-pass` | DEPT_CSE, ROLE_STUDENT, YEAR_4 |\n"
                "| `admin` | `admin-pass` | all attributes, admin |"
            )

    if not submitted:
        return

    # copy-pasted credentials often carry a stray space, which otherwise looks like a silent hang
    username, password = username.strip(), password.strip()
    if not username or not password:
        alert.warning("Enter a username and password.")
        return

    api = SecureVaultApi(base_url.strip(), verify=verify_tls)
    try:
        with card, st.spinner("Signing in and unlocking your ABE key… (a few seconds)"):
            v = vaultlib.login(api, username, password, keystore_password=keystore_password or None)
    except ApiError as exc:
        alert.error("**Sign-in failed:** %s" % exc.message)
        return
    except Exception as exc:
        alert.error(
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
    st.title("Welcome, %s" % v.username)
    st.markdown(pills(v.user.get("attributes", [])), unsafe_allow_html=True)
    st.write("")

    if v.user.get("key_stale"):
        st.warning(
            "Your attribute versions changed since this key was issued. "
            "Use **Re-fetch ABE key** in the sidebar before uploading or downloading."
        )
    else:
        st.success("ABE secret key unlocked and current.", icon="✅")

    col1, col2, col3 = st.columns(3)
    col1.metric("Attributes", len(v.user.get("attributes", [])))
    try:
        files = v.api.files_list()
        col2.metric("Files visible", len(files))
        col3.metric("Files you own", sum(1 for f in files if f["owner_id"] == str(v.user_id)))
    except ApiError as exc:
        st.error(exc.message)

    st.subheader("Go to")
    a, b, c = st.columns(3)
    a.page_link("pages/1_Upload.py", label="Upload — seal a file under a policy", icon="⬆️")
    b.page_link("pages/2_Files.py", label="Files — download and decrypt", icon="📂")
    if v.user.get("is_admin"):
        c.page_link("pages/3_Admin.py", label="Admin — users, revoke, re-key, audit", icon="🛡️")


sidebar_identity()
if get_vault() is None:
    login_form()
else:
    dashboard()
