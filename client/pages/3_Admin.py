"""Admin page: users, grant/revoke, re-key job progress, audit log (doc 06 Phase 3)."""
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from client import vault as vaultlib  # noqa: E402
from client.api import ApiError, KeyStaleError  # noqa: E402
from client.ui import require_vault, sidebar_identity  # noqa: E402

sidebar_identity()
v = require_vault()

if not v.user.get("is_admin"):
    st.error("Admin privileges required.")
    st.stop()

st.title("Admin")

try:
    attribute_names = sorted(a["name"] for a in v.api.attributes())
    users = v.api.admin_users()
except KeyStaleError:
    st.error("Your admin key is stale. Use **Re-fetch ABE key** in the sidebar first.")
    st.stop()
except ApiError as exc:
    st.error(exc.message)
    st.stop()

tab_users, tab_rekey, tab_audit = st.tabs(["Users & attributes", "Re-key jobs", "Audit log"])

# ------------------------------------------------------------- users tab

with tab_users:
    st.subheader("Users")
    for u in users:
        with st.container():
            cols = st.columns([2, 4, 2])
            cols[0].write("**%s**%s" % (u["username"], " (admin)" if u["is_admin"] else ""))
            cols[0].caption("key_stale: %s" % u["key_stale"])
            cols[1].write(", ".join(sorted(u["attributes"])) or "-")

            with cols[2].popover("Grant"):
                grantable = [a for a in attribute_names if a not in u["attributes"]]
                if grantable:
                    attr = st.selectbox("Attribute", grantable, key="grant_sel_%s" % u["id"])
                    if st.button("Grant %s" % attr, key="grant_btn_%s" % u["id"]):
                        try:
                            v.api.admin_grant(u["id"], attr)
                            st.rerun()
                        except ApiError as exc:
                            st.error(exc.message)
                else:
                    st.caption("Holds every attribute.")

            with cols[2].popover("Revoke"):
                if u["attributes"]:
                    attr = st.selectbox("Attribute", sorted(u["attributes"]), key="rev_sel_%s" % u["id"])
                    st.caption(
                        "Revoking bumps the attribute version, marks every other holder's key "
                        "stale, and queues a re-key job for the affected files."
                    )
                    if st.button("Revoke %s" % attr, key="rev_btn_%s" % u["id"]):
                        try:
                            result = v.api.admin_revoke(u["id"], attr)
                            st.success(
                                "Revoked. Job %s covers %d file(s)."
                                % (result.get("job_id"), result.get("files_total", 0))
                            )
                            st.rerun()
                        except ApiError as exc:
                            st.error(exc.message)
                else:
                    st.caption("Holds no attributes.")
        st.markdown("---")

    with st.expander("Create a user"):
        with st.form("create_user"):
            new_username = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            new_attrs = st.multiselect("Attributes", attribute_names)
            new_admin = st.checkbox("Admin")
            if st.form_submit_button("Create") and new_username and new_password:
                try:
                    v.api.admin_create_user(new_username, new_password, new_attrs, new_admin)
                    st.success("Created %s." % new_username)
                    st.rerun()
                except ApiError as exc:
                    st.error(exc.message)

    st.subheader("Attribute versions")
    st.caption("Files are encrypted under the versioned names; a revoke bumps the version.")
    st.table([{"attribute": a["name"], "current_version": a["current_version"]} for a in v.api.attributes()])

# ------------------------------------------------------------- rekey tab

with tab_rekey:
    st.subheader("Re-key jobs")
    st.caption(
        "The backend never holds enough ABE attributes to re-encrypt. This page (or "
        "`python -m client.rekey_worker --job N`) does the work with the admin's key."
    )
    try:
        jobs = v.api.rekey_jobs()
    except ApiError as exc:
        jobs = []
        st.error(exc.message)

    if not jobs:
        st.info("No re-key jobs.")
    for job in jobs:
        total = max(1, job["files_total"])
        st.write(
            "**Job %d** - attribute %d, v%d -> v%d - %s"
            % (job["id"], job["attribute_id"], job["old_version"], job["new_version"], job["status"])
        )
        st.progress(min(1.0, job["files_done"] / float(total)),
                    text="%d / %d files" % (job["files_done"], job["files_total"]))

        if job["status"] != "done" and job["files_total"] > job["files_done"]:
            if st.button("Run re-key now", key="rekey_%d" % job["id"], type="primary"):
                try:
                    items = v.api.rekey_job_files(job["id"])
                except ApiError as exc:
                    items = []
                    st.error(exc.message)
                bar = st.progress(0.0, text="Starting...")
                done = 0
                for item in items:
                    try:
                        new_policy = v.rekey_file(job["id"], item)
                        done += 1
                        bar.progress(done / float(len(items)),
                                     text="%d / %d re-encrypted" % (done, len(items)))
                        st.caption("%s -> `%s`" % (item["file_id"][:8], new_policy))
                    except vaultlib.AccessDenied as exc:
                        st.error(str(exc))
                    except ApiError as exc:
                        st.error("%s: %s" % (item["file_id"][:8], exc.message))
                if done:
                    st.success("Re-encrypted %d file(s)." % done)
                st.rerun()
        st.markdown("---")

# ------------------------------------------------------------- audit tab

with tab_audit:
    st.subheader("Audit log")
    actions = [
        "", "LOGIN", "KEY_ISSUE", "UPLOAD", "DOWNLOAD_OK", "DOWNLOAD_DENIED",
        "DELETE", "GRANT", "REVOKE", "REKEY", "USER_CREATE",
    ]
    cols = st.columns([2, 1])
    action = cols[0].selectbox("Action", actions, format_func=lambda a: a or "all")
    limit = cols[1].number_input("Rows", min_value=10, max_value=500, value=100, step=10)
    try:
        rows = v.api.audit(limit=int(limit), action=action or None)
    except ApiError as exc:
        rows = []
        st.error(exc.message)

    usernames = {u["id"]: u["username"] for u in users}
    st.table([
        {
            "at": r["created_at"],
            "user": usernames.get(r["user_id"], r["user_id"] or "-"),
            "action": r["action"],
            "file": (r["file_id"] or "")[:8],
            "detail": r["detail"] or "",
        }
        for r in rows
    ])
    st.caption("No row ever contains a file key, an ABE secret key, or plaintext.")
