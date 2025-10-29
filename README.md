<div align="center">

# 🚀 Automated CI/CD DevSecOps Demo Application  

### 🎓 MSc Project — *Design and Implementation of an Automated CI/CD Pipeline with Integrated DevSecOps Practices*  

---

</div>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-Express-green?logo=node.js" alt="Node.js">
  <img src="https://img.shields.io/badge/Docker-Enabled-blue?logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/Terraform-AWS-orange?logo=terraform" alt="Terraform">
  <img src="https://img.shields.io/badge/Security-DevSecOps-critical?logo=github" alt="Security">
</p>

---

## 🧠 Project Overview  

This repository contains a **lightweight Node.js + Express API**, designed as a **testbed** for implementing and evaluating secure automated pipelines within a DevSecOps framework.

The app provides a **simple microservice** simulating:
- Health monitoring  
- Task management  
- Greeting & version info endpoints  

It will serve as the foundation for integrating **CI/CD automation and security tools** (GitHub Actions, Terraform, SonarCloud, Trivy, etc.), aligning directly with the MSc research question:

> **“How can DevSecOps practices be effectively integrated into an automated CI/CD pipeline to enhance software delivery speed and security?”**

---

## 🧩 Tech Stack  

| Category | Technology | Purpose |
|-----------|-------------|----------|
| **Language** | Node.js (Express.js) | REST API Development |
| **Testing** | Jest + Supertest | Unit testing endpoints |
| **Containerization** | Docker | Build portable images |
| **Infrastructure** | Terraform + AWS (ECR, ECS, S3, IAM) | Infrastructure as Code |
| **CI/CD** | GitHub Actions | Build, test, deploy automation |
| **Security Tools** | SonarCloud, Trivy, OWASP Dependency Check | Static & Dependency Scanning |
| **Monitoring** | AWS CloudWatch | Logs & Metrics tracking |

---

## ⚙️ Setup Instructions  

### 🧾 1️⃣ Clone Repository  
```bash
git clone https://github.com/<your-username>/mmsc-devsecops-pipeline.git
cd mmsc-devsecops-pipeline/app



📦 2️⃣ Install Dependencies
>> npm install
▶️ 3️⃣ Run Application Locally
>> node src/index.js

<h3>Access Application:</h3>
👉 http://localhost:3000

<h3>Expected Output</h3>

{
  "status": "OK",
  "timestamp": "2025-10-28T22:00:00Z"
}


<h3>🧪 Running Tests</h3>
>> npm test

<h3>✅ Example Output:</h3>
PASS src/test/health.test.js
PASS src/test/tasks.test.js
PASS src/test/stats.test.js
Test Suites: 3 passed, 3 total
Tests:       10 passed, 10 total

-----------------------------------------------------------------

<h2>🐳 Docker Usage</h2>

<h3>🏗️ Build Docker Image</h3>
>> docker build -t devsecops-demo-api .

<h3>🚀 Run Docker Container</h3>
>> docker run -d -p 3000:3000 devsecops-demo-api

<h3>Verify:</h3>
>> curl http://localhost:3000/health


<h2> App File Structure </h2>
app/
│
├── src/
│   ├── routes/
│   │   ├── health.js
│   │   ├── greet.js
│   │   ├── tasks.js
│   │   ├── stats.js
│   │   └── version.js
│   └── index.js
│
├── src/test/
│   ├── health.test.js
│   ├── tasks.test.js
│   └── stats.test.js
│
├── Dockerfile
├── package.json
└── README.md


------------------------------------------------------

<h2>👨‍💻 Author</h2>

Name: Shahid Rasool
Programme: MSc Information Technology
University: University of the West of Scotland
Supervisor: Fath Ullah

<h3>📘 Project Title:</h3>
Design and Implementation of an Automated CI/CD Pipeline with Integrated DevSecOps Practices


<h2>🪪 License </h2>

This project is licensed under the MIT License.
You are free to use, modify, and share it for research and educational purposes.



<div align="center">

✨ “Integrating security early isn’t a delay — it’s acceleration done right.” ✨

</div>

