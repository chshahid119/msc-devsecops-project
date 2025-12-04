from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import requests
import os

app = FastAPI(title="DevSecOps Pulse API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = "chshahid119"
REPO_NAME = "msc-devsecops-project"

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}


@app.get("/api/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ------------------------------
# LIST WORKFLOW RUNS
# ------------------------------
@app.get("/api/workflow-runs")
def get_runs():
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs"

    try:
        r = requests.get(url, headers=HEADERS)
        r.raise_for_status()

        runs = []

        for item in r.json().get("workflow_runs", []):
            runs.append({
                "id": item["id"],
                "run_number": item["run_number"],
                "status": item["status"],
                "conclusion": item["conclusion"],
                "head_branch": item["head_branch"],
                "created_at": item["created_at"],
                "html_url": item["html_url"],
            })

        return runs

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------
# RUN DETAILS + JOBS + LOGS
# ------------------------------
@app.get("/api/workflow-run-full/{run_id}")
def get_run_details(run_id: int):

    run_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}"
    jobs_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}/jobs"

    try:
        run_resp = requests.get(run_url, headers=HEADERS)
        jobs_resp = requests.get(jobs_url, headers=HEADERS)

        run_resp.raise_for_status()
        jobs_resp.raise_for_status()

        return {
            "run": run_resp.json(),
            "jobs": jobs_resp.json().get("jobs", [])
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------
# JOB DETAILS + STEPS + LOGS
# ------------------------------
@app.get("/api/job-details/{job_id}")
def get_job_details(job_id: int):

    job_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/jobs/{job_id}"
    logs_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/jobs/{job_id}/logs"

    try:
        job_resp = requests.get(job_url, headers=HEADERS)
        job_resp.raise_for_status()
        job_data = job_resp.json()

        logs_resp = requests.get(logs_url, headers=HEADERS)
        logs = logs_resp.text if logs_resp.status_code == 200 else ""

        return {
            "job": job_data,
            "steps": job_data.get("steps", []),
            "logs": logs
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------
# START SERVER
# ------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
