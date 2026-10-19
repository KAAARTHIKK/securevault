"""Files page: owner/policy/size table, Download, and policy-denial box (doc 06 Phase 3)."""
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from client import vault as vaultlib  # noqa: E402
from client.api import ApiError, KeyStaleError  # noqa: E402
from client.ui import require_vault, sidebar_identity  # noqa: E402

sidebar_identity()
v = require_vault()

st.title("Files")
st.caption(
    "Filenames are encrypted, so a row shows a name only after your key successfully "
    "decrypts it. Denial is decided by the cryptography on this machine, not by the server."
)

col_a, col_b = st.columns([1, 2])
mine_only = col_a.checkbox("Only files I own", value=False)
download_dir = col_b.text_input("Download folder", value=str(Path.home() / "Downloads"))

try:
    files = v.api.files_list(mine=mine_only)
    users = {}
    if v.user.get("is_admin"):
        try:
            users = {u["id"]: u["username"] for u in v.api.admin_users()}
        except ApiError:
            users = {}
except ApiError as exc:
    st.error(exc.message)
    st.stop()

if not files:
    st.info("No files yet. Upload one from the Upload page.")
    st.stop()


def _human(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return "%.0f %s" % (value, unit) if unit == "B" else "%.1f %s" % (value, unit)
        value /= 1024.0


st.markdown("---")
header = st.columns([3, 3, 2, 2, 2, 2])
for col, label in zip(header, ("File", "Policy", "Mode", "Size", "Status", "")):
    col.markdown("**%s**" % label)

for f in files:
    cols = st.columns([3, 3, 2, 2, 2, 2])
    owner = users.get(f["owner_id"], f["owner_id"][:8])
    is_mine = f["owner_id"] == str(v.user_id)
    cols[0].write("`%s`" % f["id"][:8])
    cols[0].caption("owner: %s" % ("you" if is_mine else owner))
    cols[1].write(f.get("policy_logical") or "-")
    cols[2].write(f["wrap_mode"])
    cols[3].write(_human(f["plaintext_size"]))
    cols[3].caption("%s on S3" % _human(f["ciphertext_size"]))
    cols[4].write(f["status"])

    if f["status"] == "rekeying":
        cols[5].caption("re-keying")
        continue

    if cols[5].button("Download", key="dl_%s" % f["id"]):
        bar = st.progress(0.0, text="Fetching ciphertext...")
        try:
            path, filename = v.download(
                f["id"], download_dir,
                progress=lambda fr: bar.progress(min(1.0, fr), text="Decrypting..."),
            )
            bar.progress(1.0, text="Done")
            st.success("Decrypted **%s** to `%s`" % (filename, path))
            try:
                with open(path, "rb") as fh:
                    st.download_button(
                        "Save a copy", fh.read(), file_name=filename,
                        key="save_%s" % f["id"],
                    )
            except OSError:
                pass
        except vaultlib.AccessDenied:
            bar.empty()
            st.error("Access denied by policy")
            st.caption(
                "Your attributes do not satisfy `%s`. The ABE decapsulation returned no key, "
                "so the ciphertext stays unreadable -- nothing was decrypted locally."
                % (f.get("policy_logical") or "the file policy")
            )
        except vaultlib.IntegrityError as exc:
            bar.empty()
            st.error("Integrity failure: %s" % exc)
            st.caption("The ciphertext was altered, reordered, or truncated. No plaintext was written.")
        except KeyStaleError:
            bar.empty()
            st.error("Your key is stale. Use **Re-fetch ABE key** in the sidebar, then try again.")
        except ApiError as exc:
            bar.empty()
            st.error(exc.message)

    if is_mine or v.user.get("is_admin"):
        if cols[5].button("Delete", key="del_%s" % f["id"]):
            try:
                v.api.file_delete(f["id"])
                st.rerun()
            except ApiError as exc:
                st.error(exc.message)
