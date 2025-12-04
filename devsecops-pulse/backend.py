# backend/main.py
import os
import time
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="DevSecOps Pulse API (Enhanced)")

# Simple in-memory TTL cache
_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 30  # tune as needed

def set_cache(key: str, value: Any, ttl: int = CACHE_TTL_SECONDS):
    _CACHE[key] = {"value": value, "expires_at": time.time() + ttl}

def get_cache(key: str) -> Optional[Any]:
    item = _CACHE.get(key)
    if not item:
        return None
    if time.time() > item["expires_at"]:
        del _CACHE[key]
        return None
    return item["value"]

# Allow frontend to connect (adjust in prod)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GitHub settings - require token
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise RuntimeError("GITHUB_TOKEN environment variable is required. Set it before starting the backend.")

REPO_OWNER = os.getenv("REPO_OWNER", "chshahid119")
REPO_NAME = os.getenv("REPO_NAME", "msc-devsecops-project")
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# Helper: GitHub API request with error handling
def gh_get(url: str, params: Dict = None, stream: bool = False) -> requests.Response:
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=20, stream=stream)
        # GitHub rate limit status could be checked here
        resp.raise_for_status()
        return resp
    except requests.HTTPError as e:
        raise HTTPException(status_code=resp.status_code if 'resp' in locals() else 500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api/workflow-runs")
def list_workflow_runs(page: int = 1, per_page: int = 50):
    """
    List workflow runs for repository, paginated.
    Caches results for short TTL to avoid rate limits during dashboard refreshes.
    """
    cache_key = f"workflow_runs_page_{page}_per_{per_page}"
    cached = get_cache(cache_key)
    if cached is not None:
        return {"cached": True, "page": page, "per_page": per_page, "data": cached}

    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs"
    params = {"page": page, "per_page": per_page}
    resp = gh_get(url, params=params)
    data = resp.json()
    
    # Normalize runs: include duration calculation
    runs = []
    for run in data.get("workflow_runs", []):
        created = run.get("created_at")
        updated = run.get("updated_at")
        duration = None
        if created and updated:
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                updated_dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                duration = (updated_dt - created_dt).total_seconds()
            except Exception:
                duration = None

        runs.append({
            "id": run.get("id"),
            "run_number": run.get("run_number"),
            "name": run.get("name"),
            "workflow_id": run.get("workflow_id"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "created_at": run.get("created_at"),
            "updated_at": run.get("updated_at"),
            "head_branch": run.get("head_branch"),
            "head_sha": run.get("head_sha"),
            "event": run.get("event"),
            "duration": duration,
            "html_url": run.get("html_url"),
        })

    result = {
        "total_count": data.get("total_count", len(runs)),
        "runs": runs,
    }

    set_cache(cache_key, result)
    return {"cached": False, "page": page, "per_page": per_page, "data": result}

@app.get("/api/workflow-run/{run_id}")
def get_workflow_run(run_id: int):
    """Return raw run details from GitHub."""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}"
    resp = gh_get(url)
    return resp.json()

@app.get("/api/workflow-jobs/{run_id}")
def get_workflow_jobs(run_id: int):
    """Return jobs for a specific run."""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}/jobs"
    resp = gh_get(url)
    return resp.json()

@app.get("/api/logs/{job_id}")
def get_job_logs(job_id: int):
    """
    Return logs for a specific job.
    GitHub returns a zip stream endpoint for logs for a run; however there's also a job logs endpoint we can call.
    We'll try to fetch logs as text. If GitHub returns binary or zipped logs, we'll return a message indicating that.
    """
    # GitHub provides logs per-job via /actions/jobs/{job_id}/logs which returns a text/zip.
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/jobs/{job_id}/logs"
    try:
        resp = gh_get(url, stream=False)
        content_type = resp.headers.get("content-type", "")
        # If it's a zip or octet-stream, provide download URL (GitHub returns content blob)
        if "application/zip" in content_type or "application/octet-stream" in content_type:
            # Return base64 or instruct client to fetch from GitHub (we'll return a message with the raw bytes as fallback)
            return {"job_id": job_id, "note": "Logs are binary (zip). Download via html_url or the GitHub API directly.", "status_code": resp.status_code}
        else:
            # Try decode as text
            text = resp.text
            return {"job_id": job_id, "logs": text}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/workflow-run-full/{run_id}")
def get_workflow_run_full(run_id: int):
    """
    Return run details, jobs and logs for each job in a single JSON payload.
    Uses simple caching to reduce repeated GitHub calls during front-end interactions.
    """
    cache_key = f"run_full_{run_id}"
    cached = get_cache(cache_key)
    if cached is not None:
        return {"cached": True, "run_id": run_id, "data": cached}

    # 1) run details
    run_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}"
    run_resp = gh_get(run_url)
    run_data = run_resp.json()

    # 2) jobs for run
    jobs_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}/jobs"
    jobs_resp = gh_get(jobs_url)
    jobs_data = jobs_resp.json().get("jobs", [])

    # 3) logs per job — attempt best-effort; logs may return a zip or be unavailable (private repos/permissions)
    logs: List[Dict[str, Any]] = []
    for job in jobs_data:
        job_id = job.get("id")
        try:
            log_resp = gh_get(f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/jobs/{job_id}/logs")
            # If text, return text; if binary/zip, indicate unavailable
            ct = log_resp.headers.get("content-type", "")
            if "application/zip" in ct or "application/octet-stream" in ct:
                # Provide a link to GitHub UI for user to download, as proxying the zip is heavier
                logs.append({
                    "job_id": job_id,
                    "name": job.get("name"),
                    "conclusion": job.get("conclusion"),
                    "note": "Logs returned as binary (zip). Use GitHub Actions UI to download.",
                    "html_url": job.get("html_url", run_data.get("html_url"))
                })
            else:
                logs.append({
                    "job_id": job_id,
                    "name": job.get("name"),
                    "conclusion": job.get("conclusion"),
                    "logs": log_resp.text
                })
        except HTTPException:
            logs.append({
                "job_id": job_id,
                "name": job.get("name"),
                "conclusion": job.get("conclusion"),
                "note": "Unable to fetch logs (permission or not found)."
            })
        except Exception:
            logs.append({
                "job_id": job_id,
                "name": job.get("name"),
                "conclusion": job.get("conclusion"),
                "note": "Unexpected error fetching logs."
            })

    payload = {
        "run": run_data,
        "jobs": jobs_data,
        "logs": logs
    }

    # cache short-term
    set_cache(cache_key, payload, ttl=45)
    return {"cached": False, "run_id": run_id, "data": payload}

# Root info
@app.get("/")
def root():
    return {"message": "DevSecOps Pulse API - see /api/workflow-runs"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
