import streamlit as st
import requests

st.set_page_config(page_title="GitHub Actions Dashboard")

API_BASE = "http://127.0.0.1:8000"

st.title("GitHub Workflows")

# Fetch workflow runs
resp = requests.get(f"{API_BASE}/runs")
runs = resp.json() if resp.status_code == 200 else []


for run in runs:
    with st.container(border=True):
        col1, col2 = st.columns([3,1])

        col1.write(f"### {run['name']}")
        col1.write(f"Status: **{run['status']}**")
        col1.write(f"Run ID: {run['id']}")

        # clicking this opens detailed page
        if col2.button("View Details", key=f"btn_{run['id']}"):
            st.query_params.update({"run_id": run["id"]})
            st.switch_page("pages/RunDetails.py")
