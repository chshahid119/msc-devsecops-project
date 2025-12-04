# frontend/app.py
import streamlit as st
import pandas as pd
import requests
from datetime import datetime
import io
import os

# ----------------------------
# Configuration
# ----------------------------
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

st.set_page_config(page_title="DevSecOps Pulse (Runs Explorer)", layout="wide", initial_sidebar_state="expanded")

# ----------------------------
# Helper: API calls with caching
# ----------------------------
@st.cache_data(ttl=30)
def fetch_workflow_runs(page: int = 1, per_page: int = 50):
    try:
        resp = requests.get(f"{BACKEND_URL}/api/workflow-runs", params={"page": page, "per_page": per_page}, timeout=15)
        if resp.status_code == 200:
            payload = resp.json()
            data = payload.get("data", payload)  # handle wrapped response
            return data
        else:
            st.error(f"Backend error: {resp.status_code} - {resp.text}")
            return {"runs": []}
    except Exception as e:
        st.error(f"Error fetching workflow runs: {e}")
        return {"runs": []}

@st.cache_data(ttl=30)
def fetch_workflow_run_full(run_id: int):
    try:
        resp = requests.get(f"{BACKEND_URL}/api/workflow-run-full/{run_id}", timeout=20)
        if resp.status_code == 200:
            return resp.json().get("data", resp.json())
        else:
            st.error(f"Backend error: {resp.status_code} - {resp.text}")
            return None
    except Exception as e:
        st.error(f"Error fetching run details: {e}")
        return None

@st.cache_data(ttl=20)
def fetch_job_logs(job_id: int):
    try:
        resp = requests.get(f"{BACKEND_URL}/api/logs/{job_id}", timeout=20)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"{resp.status_code} - {resp.text}"}
    except Exception as e:
        return {"error": str(e)}

# ----------------------------
# UI: Sidebar Filters
# ----------------------------
st.sidebar.title("Explorer Filters")
page = st.sidebar.number_input("Page", min_value=1, step=1, value=1)
per_page = st.sidebar.selectbox("Runs per page", [10, 25, 50, 100], index=2)
search_branch = st.sidebar.text_input("Filter by branch (substring)")
status_filter = st.sidebar.multiselect("Status", ["success", "failure", "completed", "in_progress", "queued"], default=[])
refresh_button = st.sidebar.button("Refresh")

if refresh_button:
    st.cache_data.clear()
    st.experimental_rerun()

# ----------------------------
# Page header
# ----------------------------
st.title("🛡️ DevSecOps Pulse — Workflow Runs Explorer")
st.markdown("Browse GitHub Actions workflow runs and drill into jobs & logs. Click 'View Details' for a run to load job logs.")

# ----------------------------
# Fetch runs
# ----------------------------
data = fetch_workflow_runs(page=page, per_page=per_page)
runs = data.get("runs", [])

# Transform to DataFrame for easy table UI
df_rows = []
for r in runs:
    created = r.get("created_at")
    created_disp = created
    try:
        created_disp = datetime.fromisoformat(created.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    df_rows.append({
        "id": r.get("id"),
        "run_number": r.get("run_number"),
        "name": r.get("name"),
        "branch": r.get("head_branch"),
        "event": r.get("event"),
        "status": r.get("status"),
        "conclusion": r.get("conclusion"),
        "created_at": created_disp,
        "duration_s": r.get("duration"),
        "html_url": r.get("html_url"),
    })

df = pd.DataFrame(df_rows)

# Apply simple filters
if search_branch:
    df = df[df["branch"].str.contains(search_branch, case=False, na=False)]
if status_filter:
    df = df[df["conclusion"].isin(status_filter) | df["status"].isin(status_filter)]

st.subheader(f"Workflow Runs (page {page}, {per_page} per page) — {len(df)} shown")
if df.empty:
    st.info("No runs found for current filters.")
else:
    # Show interactive table
    st.dataframe(df[["run_number", "name", "branch", "event", "conclusion", "created_at", "duration_s"]], use_container_width=True)
    st.markdown("Select a run to view details:")

    # Create a selectbox keyed by run id (shows run_number + branch)
    run_options = { f"#{row.run_number} — {row.name} ({row.branch}) — {row.conclusion}": row.id for row in df.itertuples() }
    selected_label = st.selectbox("Choose run", options=list(run_options.keys()))
    selected_run_id = run_options[selected_label]

    if st.button("View Details", key=f"view_{selected_run_id}"):
        # Fetch details from backend
        details = fetch_workflow_run_full(selected_run_id)
        if not details:
            st.error("Could not load run details.")
        else:
            run = details.get("run", {})
            jobs = details.get("jobs", [])
            logs = details.get("logs", [])

            st.markdown("---")
            st.subheader(f"Run #{run.get('run_number')} — {run.get('name')}")
            st.write(f"**Branch:** `{run.get('head_branch')}` • **Event:** `{run.get('event')}` • **Status:** `{run.get('conclusion')}`")
            st.write(f"**Created:** {run.get('created_at')} • **Updated:** {run.get('updated_at')}")
            st.write(f"[Open in GitHub]({run.get('html_url')})")

            st.markdown("### Jobs")
            if not jobs:
                st.info("No jobs returned for this run.")
            else:
                for j in jobs:
                    st.write(f"- **{j.get('name')}** — {j.get('conclusion')} (id: {j.get('id')})")

            st.markdown("### Logs")
            # Use logs array returned from combined endpoint
            for item in logs:
                title = f"{item.get('name')} — {item.get('conclusion')}"
                with st.expander(title, expanded=False):
                    if item.get("logs"):
                        log_text = item.get("logs")
                        st.code(log_text, language="bash")
                        # Download button
                        b = io.BytesIO(log_text.encode("utf-8"))
                        st.download_button(label="Download logs", data=b, file_name=f"run_{selected_run_id}_job_{item.get('job_id')}.log")
                    else:
                        st.write(item.get("note") or "No logs available.")
                        # If note suggests html_url, show link
                        if item.get("html_url"):
                            st.markdown(f"[Open job on GitHub]({item.get('html_url')})")

            st.success("Loaded run details successfully.")
