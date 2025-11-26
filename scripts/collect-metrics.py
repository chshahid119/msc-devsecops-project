import json
import os

def parse_build_logs(log_file):
    with open(log_file) as f:
        lines = f.readlines()
    success = sum(1 for l in lines if "SUCCESS" in l)
    fail = sum(1 for l in lines if "FAILURE" in l)
    return {"success": success, "fail": fail}

if __name__ == "__main__":
    logs = parse_build_logs("build.log")
    with open("pipeline_metrics.json", "w") as f:
        json.dump(logs, f, indent=4)
