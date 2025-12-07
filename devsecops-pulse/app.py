import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import random
import os

# -----------------------------------------------------------------
# ⭐ MUST BE FIRST STREAMLIT COMMAND
# -----------------------------------------------------------------
st.set_page_config(
    page_title="DevSecOps Pulse",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------
# 🎨 THEME MANAGEMENT
# -----------------------------------------------------------------
def apply_theme(theme):
    if theme == "dark":
        return """
        <style>
            body { background-color: #0e1117; color: #fafafa; }
            .main { background-color: #0e1117 !important; color: #fafafa !important; }
        </style>
        """
    else:
        return """
        <style>
            body { background-color: white; color: black; }
            .main { background-color: white !important; color: black !important; }
        </style>
        """

# -----------------------------------------------------------------
# 🔧 Backend configuration
# -----------------------------------------------------------------
BACKEND_URL = "http://localhost:8000"


# -----------------------------------------------------------------
# 🧠 DATA FETCHING HELPERS
# -----------------------------------------------------------------
def fetch_real_metrics(days=30, env_filter="All"):
    try:
        response = requests.get(f"{BACKEND_URL}/api/metrics?days={days}")
        if response.status_code == 200:
            data = response.json()
            metrics = data.get("metrics", [])

            if metrics:
                df = pd.DataFrame(metrics)
                df["Date"] = pd.to_datetime(df["Date"])

                if env_filter != "All":
                    df = df[df["Environment"] == env_filter]

                return df, data.get("summary", {})
    except:
        pass

    return generate_fallback_data(days, env_filter), {}


def fetch_real_vulnerabilities():
    try:
        response = requests.get(f"{BACKEND_URL}/api/vulnerabilities")
        if response.status_code == 200:
            return response.json()
    except:
        pass

    return generate_fallback_vulns()


def fetch_real_workflow_runs():
    try:
        response = requests.get(f"{BACKEND_URL}/api/workflow-runs")
        if response.status_code == 200:
            return response.json()
    except:
        pass

    return {"runs": []}


def generate_fallback_data(days, env_filter):
    dates = [datetime.today() - timedelta(days=i) for i in range(days)][::-1]
    data = []

    for date in dates:
        data.append({
            "Date": date,
            "Success Rate (%)": 85 + random.randint(-10, 10),
            "Build Time (s)": 60 + random.randint(-20, 20),
            "Vulnerabilities": random.randint(0, 12),
            "Environment": random.choice(["Development", "Staging", "Production"])
        })
    return pd.DataFrame(data)


def generate_fallback_vulns():
    packages = ["requests", "urllib3", "flask", "jinja2"]
    titles = [
        "Improper Input Validation",
        "Open Redirect Vulnerability",
        "Insecure Session Handling"
    ]

    return [
        {
            "id": f"CVE-2023-{random.randint(1000, 9999)}",
            "package": random.choice(packages),
            "severity": random.choice(["Critical", "High", "Medium", "Low"]),
            "title": random.choice(titles),
            "environment": random.choice(["Development", "Staging", "Production"])
        }
        for _ in range(random.randint(1, 6))
    ]

# -----------------------------------------------------------------
# 📌 SIDEBAR (Only allowed AFTER set_page_config)
# -----------------------------------------------------------------
st.sidebar.title("Reports")

report_files = (
    [f for f in os.listdir("../reports") if f.endswith(".json")]
    if os.path.exists("../reports") else []
)

for rf in report_files:
    with open(os.path.join("../reports", rf), "r") as fh:
        st.sidebar.download_button(
            label=f"Download {rf}",
            data=fh.read(),
            file_name=rf
        )

st.sidebar.title("Filters")

theme = st.sidebar.radio("Theme Mode", ["Light", "Dark"], index=0)
st.markdown(apply_theme(theme.lower()), unsafe_allow_html=True)

time_range = st.sidebar.slider("Time Range (Days)", 7, 90, 30)
env_filter = st.sidebar.selectbox("Environment", ["All", "Development", "Staging", "Production"])
severity_filter = st.sidebar.multiselect(
    "Severity Filter",
    ["Critical", "High", "Medium", "Low"],
    default=["Critical", "High"]
)
refresh = st.sidebar.button("🔄 Refresh Data")


# -----------------------------------------------------------------
# 📥 FETCH BACKEND DATA
# -----------------------------------------------------------------
df, summary = fetch_real_metrics(time_range, env_filter)
vulns = fetch_real_vulnerabilities()
workflow_runs = fetch_real_workflow_runs()

# -----------------------------------------------------------------
# 📊 METRICS CALCULATION
# -----------------------------------------------------------------
avg_success = summary.get("success_rate", 85)
avg_time = summary.get("avg_build_time", 60)
total_builds = summary.get("total_runs", len(df))
total_vulns = sum(df["Vulnerabilities"]) if "Vulnerabilities" in df else 0

severity_counts = {}
for v in vulns:
    severity_counts[v["severity"]] = severity_counts.get(v["severity"], 0) + 1

# Filter vulnerabilities
if severity_filter:
    vulns = [v for v in vulns if v["severity"] in severity_filter]

if env_filter != "All":
    vulns = [v for v in vulns if v.get("environment") == env_filter]


# -----------------------------------------------------------------
# 🎯 DASHBOARD HEADER
# -----------------------------------------------------------------
st.title("🛡️ DevSecOps Pulse")
st.markdown("Operational insights for your secure CI/CD pipeline.")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Overview Dashboard",
    "Pipeline Analytics",
    "Security Center",
    "Build History & Logs",
    "🚨 Critical Vulnerabilities"
])

# -----------------------------------------------------------------
# TAB 1: OVERVIEW DASHBOARD
# -----------------------------------------------------------------
with tab1:

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Build Success", f"{avg_success:.1f}%")
    col2.metric("Avg Build Time", f"{avg_time:.0f}s")
    col3.metric("Total Vulns", total_vulns)
    col4.metric("Total Runs", total_builds)

    health_status = (
        ("🟢 Excellent", avg_success >= 90),
        ("🟡 Good", avg_success >= 80),
        ("🔴 Needs Attention", avg_success < 80)
    )

    for status, cond in health_status:
        if cond:
            st.markdown(f"### {status}")
            break


# -----------------------------------------------------------------
# TAB 2: PIPELINE ANALYTICS
# -----------------------------------------------------------------
with tab2:
    st.subheader("Success Rate Trend")
    if not df.empty:
        fig = px.line(df, x="Date", y="Success Rate (%)")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No metrics available.")


# -----------------------------------------------------------------
# TAB 3: SECURITY CENTER
# -----------------------------------------------------------------
with tab3:
    st.subheader("Severity Distribution")

    if severity_counts:
        df_sev = pd.DataFrame({
            "Severity": list(severity_counts.keys()),
            "Count": list(severity_counts.values())
        })
        fig = px.pie(df_sev, values="Count", names="Severity")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No vulnerability data.")


# -----------------------------------------------------------------
# TAB 4: BUILD HISTORY
# -----------------------------------------------------------------
with tab4:
    st.subheader("Workflow Runs")
    st.json(workflow_runs)


# -----------------------------------------------------------------
# TAB 5: CRITICAL VULNERABILITIES
# -----------------------------------------------------------------
with tab5:
    st.header("🚨 Critical Vulnerabilities")
    crit = [v for v in vulns if v["severity"] == "Critical"]
    if crit:
        st.json(crit)
    else:
        st.success("No critical vulnerabilities detected.")


# -----------------------------------------------------------------
# REFRESH
# -----------------------------------------------------------------
if refresh:
    st.rerun()
