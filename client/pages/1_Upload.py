"""Upload page: file picker, policy builder, ABE/ECC toggle, progress bar (doc 06 Phase 3)."""
import sys
import uuid
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from client import vault as vaultlib  # noqa: E402
from client.api import ApiError, KeyStaleError  # noqa: E402
from client.ui import require_vault, sidebar_identity  # noqa: E402
from crypto import aes_stream, policy as policylib  # noqa: E402

MAX_POLICY_ROWS = 6

sidebar_identity()
v = require_vault()

st.title("Upload")
st.caption(
    "The file is encrypted here, on this machine. The backend receives only the ciphertext "
    "(via a pre-signed S3 PUT), the ABE ciphertext of the file key, and the policy."
)

try:
    known_attributes, versions = v.attribute_versions()
except ApiError as exc:
    st.error(exc.message)
    st.stop()

attribute_names = sorted(known_attributes)

uploaded = st.file_uploader("File to encrypt and upload", type=None)

st.subheader("Access policy")
st.caption("Attributes inside a row are joined with **AND**. Rows are joined with **OR**.")

wrap_mode = st.radio(
    "Key wrapping mode", ["ABE", "ECC"], horizontal=True,
    help=(
        "ABE: one ciphertext of the file key, decryptable by anyone whose attributes satisfy "
        "the policy. ECC: the fallback mode, one X25519-wrapped copy of the key per named "
        "recipient (metadata grows with the number of recipients)."
    ),
)

rows = st.number_input("Policy rows (OR groups)", min_value=1, max_value=MAX_POLICY_ROWS, value=1, step=1)
groups = []
for i in range(int(rows)):
    picked = st.multiselect("Row %d (AND)" % (i + 1), attribute_names, key="policy_row_%d" % i)
    if picked:
        groups.append(picked)

logical_policy = ""
if groups:
    parts = []
    for group in groups:
        parts.append("(%s)" % " and ".join(group) if len(group) > 1 else group[0])
    logical_policy = " or ".join(parts)

recipients = []
if wrap_mode == "ECC":
    st.subheader("Recipients (ECC mode)")
    try:
        directory = v.api.ecc_recipients()
    except ApiError as exc:
        directory = []
        st.error(exc.message)
    if not directory:
        st.info("No users have registered an X25519 public key yet. They register one on first sign-in.")
    else:
        by_label = {"%s" % d["username"]: d for d in directory}
        chosen = st.multiselect("Wrap the file key for", sorted(by_label))
        recipients = [by_label[c] for c in chosen]

if logical_policy:
    st.code(logical_policy, language="text")
    try:
        versioned_preview = policylib.to_versioned(logical_policy, known_attributes, versions)
        st.caption("Encrypted under: `%s`" % versioned_preview)
    except ValueError as exc:
        st.error("Invalid policy: %s" % exc)

if uploaded is not None:
    predicted = aes_stream.ciphertext_size_for(uploaded.size)
    st.caption(
        "%s - %s plaintext, %s ciphertext (%d chunks of %d B + tags)"
        % (
            uploaded.name,
            "{:,}".format(uploaded.size),
            "{:,}".format(predicted),
            aes_stream.total_chunks_for(uploaded.size),
            aes_stream.DEFAULT_CHUNK_SIZE,
        )
    )

disabled = uploaded is None or not logical_policy or (wrap_mode == "ECC" and not recipients)
if st.button("Encrypt and upload", disabled=disabled, type="primary"):
    bar = st.progress(0.0, text="Preparing...")
    work = vaultlib.KEYSTORE_DIR / "tmp"
    work.mkdir(parents=True, exist_ok=True)
    staged = work / ("upload-%s.bin" % uuid.uuid4())
    try:
        staged.write_bytes(uploaded.getbuffer())

        def on_progress(fraction):
            bar.progress(min(1.0, fraction), text="Encrypting and uploading...")

        detail = v.upload(
            str(staged), uploaded.name, logical_policy,
            wrap_mode=wrap_mode, recipients=recipients, progress=on_progress,
        )
        bar.progress(1.0, text="Done")
        st.success("Uploaded. Object key: %s" % detail["object_key"])
        st.json({
            "file_id": detail["id"],
            "object_key": detail["object_key"],
            "policy_logical": detail["policy_logical"],
            "policy_versioned": detail["policy_versioned"],
            "wrap_mode": detail["wrap_mode"],
            "ciphertext_size": detail["ciphertext_size"],
            "ciphertext_sha256": detail["ciphertext_sha256"],
        })
        st.caption("Note the object key carries no filename -- the filename itself is encrypted.")
    except KeyStaleError:
        st.error("Your key is stale. Use **Re-fetch ABE key** in the sidebar, then try again.")
    except ValueError as exc:
        st.error("Invalid policy: %s" % exc)
    except ApiError as exc:
        st.error(exc.message)
    finally:
        vaultlib.shred(staged)
