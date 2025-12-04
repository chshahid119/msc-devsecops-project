import streamlit as st
import requests

st.set_page_config(page_title="Run Details")

API_BASE = "http://127.0.0.1:8000"

params = st.query_params
run_id = params.get("run_id", None)

if run_id is None:
    st.error("No run selected")
    st.stop()

st.title(f"Run Details: {run_id}")

# Fetch run details
resp = requests.get(f"{API_BASE}/runs/{run_id}")
data = resp.json() if resp.status_code == 200 else None

if not data:
    st.error("Could not load details")
    st.stop()

# HEADER INFO
st.write(f"**Name:** {data['name']}")
st.write(f"**Status:** {data['status']}")
st.write(f"**Duration:** {data['duration']}")

st.divider()
st.subheader("Steps")

for step in data.get("steps", []):
    with st.expander(f"{step['name']} - {step['status']}"):
        st.code(step.get("logs", ""), language="bash")
