import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random

# ----------------------------
# 🎨 PAGE CONFIG & THEME MANAGEMENT
# ----------------------------
st.set_page_config(
    page_title="DevSecOps Pulse",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Theme Management
def apply_theme(theme):
    if theme == "dark":
        return """
        <style>
            .main { 
                background-color: #0e1117; 
                color: #fafafa;
                padding: 1.5rem; 
            }
            .stTabs [data-basewidth="100%"] { 
                background: #262730; 
                border-radius: 12px; 
                box-shadow: 0 2px 12px rgba(255,255,255,0.08); 
            }
            .stMetric { 
                background: #1e1e1e; 
                padding: 18px; 
                border-radius: 12px; 
                box-shadow: 0 2px 6px rgba(255,255,255,0.04); 
                border: 1px solid #444; 
            }
            h1, h2, h3 { color: #60a5fa; font-weight: 700; }
            .critical { color: #f87171; font-weight: 600; }
            .high { color: #fb923c; font-weight: 600; }
            .medium { color: #fbbf24; }
            .low { color: #9ca3af; }
            .alert-box {
                background: #7f1d1d;
                border-left: 4px solid #ef4444;
                padding: 12px;
                border-radius: 8px;
                margin: 10px 0;
                color: white;
            }
            .insight-box {
                background: #064e3b;
                border-left: 4px solid #10b981;
                padding: 12px;
                border-radius: 8px;
                margin: 10px 0;
                color: white;
            }
            .log-line {
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
                line-height: 1.5;
                color: #60a5fa;
            }
            .vulnerability-card {
                background: #1e1e1e;
                padding: 20px;
                border-radius: 12px;
                margin: 16px 0;
                border-left: 6px solid;
                box-shadow: 0 4px 12px rgba(255,255,255,0.1);
                transition: transform 0.2s ease;
            }
            .vulnerability-card:hover {
                transform: translateY(-2px);
            }
            .critical-card { border-left-color: #ef4444; background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%); }
            .high-card { border-left-color: #f97316; background: linear-gradient(135deg, #7c2d12 0%, #9a3412 100%); }
            .medium-card { border-left-color: #f59e0b; background: linear-gradient(135deg, #78350f 0%, #92400e 100%); }
            .low-card { border-left-color: #64748b; background: linear-gradient(135deg, #374151 0%, #4b5563 100%); }
            .priority-badge {
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 600;
                margin-left: 10px;
            }
            .immediate-priority { background: #ef4444; color: white; }
            .high-priority { background: #f97316; color: white; }
            .medium-priority { background: #f59e0b; color: black; }
        </style>
        """
    else:
        return """
        <style>
            .main { padding: 1.5rem; }
            .stTabs [data-basewidth="100%"] { 
                background: white; 
                border-radius: 12px; 
                box-shadow: 0 2px 12px rgba(0,0,0,0.08); 
            }
            .stMetric { 
                background: #f8fafc; 
                padding: 18px; 
                border-radius: 12px; 
                box-shadow: 0 2px 6px rgba(0,0,0,0.04); 
                border: 1px solid #e2e8f0; 
            }
            h1, h2, h3 { color: #1e3a8a; font-weight: 700; }
            .critical { color: #ef4444; font-weight: 600; }
            .high { color: #f97316; font-weight: 600; }
            .medium { color: #f59e0b; }
            .low { color: #64748b; }
            .alert-box {
                background: #fef2f2;
                border-left: 4px solid #ef4444;
                padding: 12px;
                border-radius: 8px;
                margin: 10px 0;
            }
            .insight-box {
                background: #f0fdf4;
                border-left: 4px solid #10b981;
                padding: 12px;
                border-radius: 8px;
                margin: 10px 0;
            }
            .log-line {
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
                line-height: 1.5;
                color: #1e3a8a;
            }
            .vulnerability-card {
                background: #f8fafc;
                padding: 20px;
                border-radius: 12px;
                margin: 16px 0;
                border-left: 6px solid;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                transition: transform 0.2s ease;
            }
            .vulnerability-card:hover {
                transform: translateY(-2px);
            }
            .critical-card { border-left-color: #ef4444; background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); }
            .high-card { border-left-color: #f97316; background: linear-gradient(135deg, #fff7ed 0%, #ffedd5 100%); }
            .medium-card { border-left-color: #f59e0b; background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%); }
            .low-card { border-left-color: #64748b; background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); }
            .priority-badge {
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 600;
                margin-left: 10px;
            }
            .immediate-priority { background: #ef4444; color: white; }
            .high-priority { background: #f97316; color: white; }
            .medium-priority { background: #f59e0b; color: black; }
        </style>
        """

# Theme selector in sidebar
st.sidebar.title("Filters")
theme = st.sidebar.radio("Theme Mode", ["Light", "Dark"], index=0)
st.markdown(apply_theme(theme.lower()), unsafe_allow_html=True)

# ----------------------------
# 🖥️ SIDEBAR FILTERS
# ----------------------------
time_range = st.sidebar.slider(
    "Time Range (Days)",
    min_value=7,
    max_value=90,
    value=30,
    help="Select how many days of data to display"
)
env_filter = st.sidebar.selectbox(
    "Environment",
    ["All", "Development", "Staging", "Production"],
    help="Filter by deployment environment"
)
severity_filter = st.sidebar.multiselect(
    "Severity Levels",
    ["Critical", "High", "Medium", "Low"],
    default=["Critical", "High"],
    help="Select which vulnerability severities to display"
)
refresh = st.sidebar.button("🔄 Refresh Data")

# ----------------------------
# 🧠 ENHANCED DATA GENERATION (Dynamic & Filter-Aware)
# ----------------------------
def generate_data(days, env="All"):
    env_success = {"Development": 95, "Staging": 88, "Production": 82}
    base_success = env_success.get(env, 90) if env != "All" else 90

    dates = [datetime.today() - timedelta(days=i) for i in range(days)][::-1]
    data = []
    for i, date in enumerate(dates):
        success = max(70, base_success + random.randint(-5, 3))
        build_time = max(50, 80 + random.randint(-20, 15))
        
        # Generate vulnerabilities based on time range and environment
        base_vulns = 25 - (i // 7)  # Decreases over time
        if env == "Production":
            base_vulns = max(5, base_vulns - 5)  # Production has fewer vulns
        elif env == "Staging":
            base_vulns = max(8, base_vulns - 3)
        
        vulns = max(0, base_vulns + random.randint(-3, 3))
        env_assigned = random.choice(["Development", "Staging", "Production"]) if env == "All" else env
        data.append({
            "Date": date,
            "Success Rate (%)": success,
            "Build Time (s)": build_time,
            "Vulnerabilities": vulns,
            "Environment": env_assigned
        })
    return pd.DataFrame(data)

def generate_vulns(time_range_days, severity_filter, env_filter):
    packages = ["requests", "urllib3", "flask", "jinja2", "django", "numpy", "pandas", "pyyaml"]
    titles = [
        "Improper Input Validation",
        "Open Redirect Vulnerability", 
        "Insecure Session Handling",
        "Template Injection Risk",
        "Information Disclosure",
        "SQL Injection Potential",
        "Path Traversal Risk",
        "Cross-Site Scripting (XSS)"
    ]
    
    # Adjust vulnerability count based on filters
    base_count = max(3, 15 - (time_range_days // 10))
    if env_filter == "Production":
        base_count = max(2, base_count - 3)
    elif env_filter == "Staging":
        base_count = max(3, base_count - 2)
    
    vulns = []
    for i in range(base_count):
        pkg = random.choice(packages)
        title = random.choice(titles)
        severity = random.choice(severity_filter) if severity_filter else "Low"
        cve = f"CVE-202{random.randint(3,5)}-{random.randint(1000,9999)}"
        vulns.append({
            "id": cve,
            "package": pkg,
            "severity": severity,
            "title": title,
            "environment": env_filter if env_filter != "All" else random.choice(["Development", "Staging", "Production"])
        })
    return vulns

# Generate data based on current filters
df = generate_data(time_range, env_filter if env_filter != "All" else "All")
vulns = generate_vulns(time_range, severity_filter, env_filter)

# Calculate dynamic metrics for alerts
df_filtered = df.copy()
if env_filter != "All":
    df_filtered = df_filtered[df_filtered["Environment"] == env_filter]

avg_success = df_filtered["Success Rate (%)"].mean()
avg_time = df_filtered["Build Time (s)"].mean()
total_vulns = sum(df_filtered["Vulnerabilities"])
total_builds = len(df_filtered)

# Count vulnerabilities by severity for dynamic alerts
severity_counts = {}
for v in vulns:
    severity_counts[v["severity"]] = severity_counts.get(v["severity"], 0) + 1

critical_vulns = severity_counts.get("Critical", 0)
high_vulns = severity_counts.get("High", 0)
medium_vulns = severity_counts.get("Medium", 0)
low_vulns = severity_counts.get("Low", 0)

# ----------------------------
# 🚨 TOP 3 VULNERABILITIES WITH REMEDIATION
# ----------------------------
def get_top_vulnerabilities_with_remediation(vulns_list):
    """Get top 3 vulnerabilities with remediation actions"""
    # Sort by severity (Critical > High > Medium > Low)
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    sorted_vulns = sorted(vulns_list, key=lambda x: severity_order.get(x["severity"], 0), reverse=True)
    
    top_3 = sorted_vulns[:3]
    
    # Add remediation actions based on vulnerability type
    for vuln in top_3:
        if "SQL Injection" in vuln["title"]:
            vuln["remediation"] = "Use parameterized queries and input validation"
            vuln["priority"] = "IMMEDIATE"
        elif "XSS" in vuln["title"]:
            vuln["remediation"] = "Implement output encoding and Content Security Policy"
            vuln["priority"] = "IMMEDIATE" 
        elif "Input Validation" in vuln["title"]:
            vuln["remediation"] = "Add strict input validation and sanitization"
            vuln["priority"] = "HIGH"
        elif "Session" in vuln["title"]:
            vuln["remediation"] = "Implement secure session management with proper timeout"
            vuln["priority"] = "HIGH"
        elif "Information Disclosure" in vuln["title"]:
            vuln["remediation"] = "Review error handling and remove sensitive data from responses"
            vuln["priority"] = "MEDIUM"
        elif "Path Traversal" in vuln["title"]:
            vuln["remediation"] = "Validate and sanitize file paths, use whitelisting"
            vuln["priority"] = "HIGH"
        else:
            vuln["remediation"] = "Update package to latest secure version"
            vuln["priority"] = "MEDIUM"
    
    return top_3

# Get top 3 vulnerabilities
top_vulnerabilities = get_top_vulnerabilities_with_remediation(vulns)

# ----------------------------
# 📊 DASHBOARD HEADER
# ----------------------------
st.title("🛡️ DevSecOps Pulse")
st.markdown("Operational insights for your secure CI/CD pipeline")

# ----------------------------
# 🔘 TABS (Added Tab 5 for Top Vulnerabilities)
# ----------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Overview Dashboard",
    "Pipeline Analytics", 
    "Security Center",
    "Build History & Logs",
    "🚨 Critical Vulnerabilities"  # New tab for top vulnerabilities
])

# ----------------------------
# TAB 1: OVERVIEW (Removed Top Vulnerabilities Section)
# ----------------------------
with tab1:
    # Existing metrics and health status (Top vulnerabilities removed)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Build Success", f"{avg_success:.1f}%", "↑ vs manual")
    col2.metric("Avg Build Time", f"{avg_time:.0f}s", "↓ 41% faster")
    col3.metric("Total Vulns", int(total_vulns), "auto-detected")
    col4.metric("Total Runs", total_builds, "automated")

    # Dynamic health status
    if avg_success >= 90 and total_vulns < 10:
        health = "Excellent"
        health_color = "🟢"
    elif avg_success >= 80:
        health = "Good" 
        health_color = "🟡"
    else:
        health = "Needs Attention"
        health_color = "🔴"
    
    st.markdown(f"### {health_color} Pipeline Health: {health}")

    # Last run info
    if not df_filtered.empty:
        last_run = df_filtered["Date"].max().strftime('%Y-%m-%d %H:%M:%S')
        st.markdown(f"**Last run:** {last_run}")

    # 🚨 DYNAMIC ALERTS & INSIGHTS (Now fully filter-aware)
    with st.expander("📋 Smart Alerts & Insights", expanded=True):
        alerts = []
        insights = []
        
        # Success rate alerts
        if avg_success < 75:
            alerts.append(f"🔴 CRITICAL: Build success rate critically low ({avg_success:.1f}%) - Immediate review required")
        elif avg_success < 85:
            alerts.append(f"🟡 WARNING: Build success rate below target ({avg_success:.1f}%) - Review test coverage")
        else:
            insights.append(f"✅ Build success rate is healthy at {avg_success:.1f}%")
        
        # Vulnerability alerts based on ACTUAL filtered data
        if critical_vulns > 0:
            alerts.append(f"🔴 CRITICAL: {critical_vulns} critical vulnerabilities detected - Patch immediately")
        if high_vulns > 2:
            alerts.append(f"🟠 HIGH: {high_vulns} high-severity vulnerabilities need attention")
        if medium_vulns > 5 and "Medium" in severity_filter:
            alerts.append(f"🟡 MEDIUM: {medium_vulns} medium-severity vulnerabilities - Schedule patching")
        if low_vulns > 8 and "Low" in severity_filter:
            alerts.append(f"🔵 LOW: {low_vulns} low-severity vulnerabilities - Monitor")
            
        if total_vulns == 0 and severity_filter:
            insights.append("✅ No vulnerabilities detected with current severity filters")
        elif total_vulns > 0:
            insights.append(f"📊 Vulnerability breakdown: {critical_vulns} Critical, {high_vulns} High, {medium_vulns} Medium, {low_vulns} Low")
        
        # Build time alerts
        if avg_time > 120:
            alerts.append(f"⏱️ SLOW: Build time {avg_time:.0f}s exceeds threshold - Optimize pipeline")
        elif avg_time < 60:
            insights.append(f"⚡ Fast build time: {avg_time:.0f}s - Good performance")
        
        # Environment-specific insights
        if env_filter != "All":
            insights.append(f"🌍 Filtering {env_filter} environment data")
        
        # Display alerts and insights
        for alert in alerts:
            st.markdown(f'<div class="alert-box">{alert}</div>', unsafe_allow_html=True)
        
        for insight in insights:
            st.markdown(f'<div class="insight-box">{insight}</div>', unsafe_allow_html=True)
            
        if not alerts and not insights:
            st.markdown('<div class="insight-box">✅ All systems operational - No issues detected</div>', unsafe_allow_html=True)

# ----------------------------
# TAB 2: ANALYTICS (Improved Charts)
# ----------------------------
with tab2:
    st.subheader("Success Rate Trend")
    fig1 = px.line(df, x="Date", y="Success Rate (%)", color="Environment", markers=True)
    fig1.update_traces(line_width=2)
    fig1.update_layout(
        title="Success Rate Over Time",
        xaxis_title="Date",
        yaxis_title="Success Rate (%)",
        legend_title="Environment"
    )
    st.plotly_chart(fig1, use_container_width=True)

    st.subheader("Build Time vs Vulnerability Detection")
    fig2 = go.Figure()
    fig2.add_trace(go.Scatter(x=df["Date"], y=df["Build Time (s)"], mode='lines+markers', name="Build Time", line=dict(color="#3b82f6"), marker=dict(size=6)))
    fig2.add_trace(go.Scatter(x=df["Date"], y=df["Vulnerabilities"], mode='lines+markers', name="Vulnerabilities", line=dict(color="#ef4444"), marker=dict(size=6), yaxis="y2"))
    fig2.update_layout(
        title="Build Performance vs Security Findings",
        xaxis_title="Date",
        yaxis=dict(title="Build Time (s)", showgrid=True),
        yaxis2=dict(title="Vulnerabilities", overlaying="y", side="right", showgrid=True),
        legend=dict(x=0.01, y=0.99),
        hovermode="x unified"
    )
    st.plotly_chart(fig2, use_container_width=True)

# ----------------------------
# TAB 3: SECURITY CENTER (Dynamic Vulnerability Display)
# ----------------------------
with tab3:
    st.subheader("Severity Distribution")
    if severity_counts:
        vuln_df = pd.DataFrame({
            "Severity": list(severity_counts.keys()),
            "Count": list(severity_counts.values())
        })
        fig3 = px.pie(vuln_df, values="Count", names="Severity",
                      color="Severity",
                      color_discrete_map={
                          "Critical": "#ef4444",
                          "High": "#f97316",
                          "Medium": "#f59e0b",
                          "Low": "#64748b"
                      },
                      hole=0.4)
        fig3.update_layout(title="Vulnerability Severity Breakdown")
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No vulnerabilities match current filters")

    st.subheader("Detected Vulnerabilities")
    if vulns:
        for v in vulns:
            color_map = {
                "Critical": "#fee2e2",
                "High": "#ffedd5",
                "Medium": "#fef3c7",
                "Low": "#f1f5f9"
            }
            border_map = {
                "Critical": "#ef4444",
                "High": "#f97316",
                "Medium": "#f59e0b",
                "Low": "#94a3b8"
            }
            st.markdown(f"""
            <div style="background: {color_map[v['severity']]}; padding: 12px; border-radius: 8px; margin: 8px 0; border-left: 4px solid {border_map[v['severity']]};">
                <strong class="{v['severity'].lower()}">{v['severity']}</strong><br>
                {v['title']}<br>
                <small>Package: {v['package']} • {v['id']} • Env: {v['environment']}</small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.warning("No vulnerabilities match current severity filters")

# ----------------------------
# TAB 4: BUILD HISTORY (Fully Dynamic Logs)
# ----------------------------
with tab4:
    st.subheader("Latest Build Output")

    # Generate dynamic log based on CURRENT filters and data
    if not df_filtered.empty:
        latest_build = df_filtered.iloc[-1]
        last_env = latest_build["Environment"]
        last_time = latest_build["Date"].strftime("%Y-%m-%dT%H:%M:%SZ")
        build_id = random.randint(140, 150)
        test_count = random.randint(30, 35)
        
        # Dynamic vulnerability count based on ACTUAL filtered vulnerabilities
        current_vuln_count = len(vulns)
        duration = random.randint(60, 90)
        
        # Determine build status based on metrics
        if latest_build["Success Rate (%)"] > 85 and current_vuln_count < 5:
            final_status = "SUCCESS"
            status_emoji = "🟢"
        else:
            final_status = "PARTIAL"
            status_emoji = "🟡"
    else:
        last_env = "Development"
        last_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        build_id = 142
        test_count = 32
        current_vuln_count = len(vulns)
        duration = 76
        final_status = "SUCCESS"
        status_emoji = "🟢"

    # Create fully dynamic log output
    log_lines = [
        f"[{last_time}] {status_emoji} Build #{build_id} started for {last_env}",
        f"[{last_time.replace('T', ' ').split('.')[0]}] 📦 Installing dependencies...",
        f"[{last_time.replace('T', ' ').split('.')[0]}] ✅ Tests passed ({test_count}/{test_count})",
        f"[{last_time.replace('T', ' ').split('.')[0]}] 🔍 Running Trivy scan...",
        f"[{last_time.replace('T', ' ').split('.')[0]}] ⚠️ {current_vuln_count} vulnerabilities detected ({', '.join(severity_filter) if severity_filter else 'none'})",
        f"[{last_time.replace('T', ' ').split('.')[0]}] 🚀 Deploying to {last_env} via Ansible playbook",
        f"[{last_time.replace('T', ' ').split('.')[0]}] {status_emoji} Build #{build_id} {final_status} ({duration}s)"
    ]

    # Display as styled code block
    log_html = "<br>".join(log_lines)
    st.markdown(f"""
    <div style="background: #f8fafc; padding: 16px; border-radius: 10px; border: 1px solid #e2e8f0; font-family: 'Courier New', monospace; font-size: 0.9em; line-height: 1.5;">
    {log_html}
    </div>
    """, unsafe_allow_html=True)

    # Build summary
    st.markdown(f"""
    **Build Summary:**
    - **Environment:** {last_env}
    - **Duration:** {duration}s
    - **Status:** {final_status}
    - **Vulnerabilities:** {current_vuln_count} ({', '.join(severity_filter) if severity_filter else 'none filtered'})
    - **Tests:** {test_count}/{test_count} passed
    """)

# ----------------------------
# TAB 5: 🚨 CRITICAL VULNERABILITIES (New Separate Tab)
# ----------------------------
# ----------------------------
# TAB 5: 🚨 CRITICAL VULNERABILITIES (New Separate Tab)
# ----------------------------
with tab5:
    st.header("🚨 Critical Vulnerabilities")
    st.markdown("### Priority wise Security Issues Requiring Immediate Attention")
    
    if top_vulnerabilities:
        # Summary metrics at the top
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Critical Vulnerabilities", critical_vulns, "Require immediate action")
        with col2:
            st.metric("High Severity", high_vulns, "Address within 48 hours")
        with col3:
            st.metric("Total Priority Issues", len(top_vulnerabilities), "Top 3 shown below")
        
        st.markdown("---")
        
        # Display top 3 vulnerabilities in collapsible panels
        for i, vuln in enumerate(top_vulnerabilities, 1):
            severity_class = f"{vuln['severity'].lower()}-card"
            priority_color = {
                "IMMEDIATE": "#ef4444",
                "HIGH": "#f97316", 
                "MEDIUM": "#f59e0b",
                "LOW": "#64748b"
            }[vuln["priority"]]
            
            priority_class = {
                "IMMEDIATE": "immediate-priority",
                "HIGH": "high-priority", 
                "MEDIUM": "medium-priority"
            }[vuln["priority"]]
            
            # Create collapsible expander for each vulnerability
            with st.expander(
                label=f"🚨 #{i} - {vuln['severity']} Severity: {vuln['title']}",
                expanded=False  # Start collapsed by default
            ):
                st.markdown(f"""
                <div class="vulnerability-card {severity_class}">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 16px;">
                        <div>
                            <h4 style="margin: 0 0 8px 0; display: flex; align-items: center;">
                                {vuln['severity']} Severity Vulnerability
                                <span class="priority-badge {priority_class}" style="margin-left: 12px;">{vuln['priority']} PRIORITY</span>
                            </h4>
                            <p style="margin: 0 0 12px 0; font-size: 1.1em; font-weight: 600; color: {priority_color};">
                                {vuln['title']}
                            </p>
                        </div>
                    </div>
                    
                    <div style="background: rgba(0,0,0,0.08); padding: 12px; border-radius: 8px; margin: 12px 0;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                            <div>
                                <strong>📦 Affected Package:</strong><br>
                                <code style="background: rgba(0,0,0,0.1); padding: 4px 8px; border-radius: 4px;">{vuln['package']}</code>
                            </div>
                            <div>
                                <strong>🆔 CVE ID:</strong><br>
                                <code style="background: rgba(0,0,0,0.1); padding: 4px 8px; border-radius: 4px;">{vuln['id']}</code>
                            </div>
                        </div>
                    </div>
                    
                    <div style="background: rgba(255,255,255,0.3); padding: 16px; border-radius: 8px; margin-top: 16px; border-left: 4px solid {priority_color};">
                        <h4 style="margin: 0 0 8px 0; color: {priority_color};">🛠️ Required Action</h4>
                        <p style="margin: 0; font-size: 1.05em; font-weight: 500;">{vuln['remediation']}</p>
                    </div>
                    
                    <div style="margin-top: 16px; font-size: 0.9em; color: #666;">
                        <strong>📝 Impact:</strong> This vulnerability could lead to security breaches if not addressed promptly.
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
    else:
        st.success("""
        ## ✅ No Critical Vulnerabilities Detected
        
        Your current security scan shows no critical or high-severity vulnerabilities 
        that require immediate attention. Continue monitoring with regular security scans.
        """)
        
        # Show celebration when no vulnerabilities
        st.balloons()
        st.markdown("""
        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #10b981 0%, #059669 100%); border-radius: 12px; color: white;">
            <h3>🎉 Excellent Security Posture!</h3>
            <p>Your proactive security measures are paying off. Keep up the good work!</p>
        </div>
        """, unsafe_allow_html=True) 

# ----------------------------
# 📥 DOWNLOAD & REFRESH
# ----------------------------
st.sidebar.markdown("---")
st.sidebar.subheader("Export")
if st.sidebar.button("Download Metrics (CSV)"):
    csv = df.to_csv(index=False)
    st.sidebar.download_button(
        label="Download Now",
        data=csv,
        file_name="pipeline_metrics.csv",
        mime="text/csv"
    )

if refresh:
    st.success("✅ Data refreshed with current filters!")
    st.rerun() 