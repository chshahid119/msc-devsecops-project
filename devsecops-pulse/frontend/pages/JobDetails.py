import streamlit as st
import requests

API = "http://127.0.0.1:8000"

job_id = st.session_state.get("job_id")

st.title(f"📝 Job Details #{job_id}")

def fetch_job(job_id):
    r = requests.get(f"{API}/api/job-details/{job_id}")
    return r.json()

data = fetch_job(job_id)

steps = data.get("steps", [])
logs = data.get("logs", "")

for step in steps:
    name = step["name"]
    status = step.get("conclusion", "")

    with st.expander(f"{name} • {status}"):

        matched = [
            line for line in logs.splitlines()
            if name.lower() in line.lower()
        ]

        if matched:
            st.code("\n".join(matched), language="bash")
        else:
            st.write("_No logs available for this step_")
