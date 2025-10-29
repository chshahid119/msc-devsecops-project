<div align="center">

# 🚀 Automated CI/CD DevSecOps Demo Application  

### 🎓 MSc Project — *Design and Implementation of an Automated CI/CD Pipeline with Integrated DevSecOps Practices*  

---

![Node.js](https://img.shields.io/badge/Node.js-Express-green?logo=node.js)
![Docker](https://img.shields.io/badge/Docker-Enabled-blue?logo=docker)
![Terraform](https://img.shields.io/badge/Terraform-AWS-orange?logo=terraform)
![Security](https://img.shields.io/badge/Security-DevSecOps-critical?logo=github)

</div>

---

## 🧠 Project Overview  

This repository contains a **lightweight Node.js + Express API**, designed as a **testbed** for implementing and evaluating secure automated pipelines within a DevSecOps framework.

The app simulates a real-world microservice providing:
- ✅ Health monitoring  
- ✅ Task management  
- ✅ Greeting & version info endpoints  

It forms the foundation for integrating **CI/CD automation and security tools** (GitHub Actions, Terraform, SonarCloud, Trivy, etc.), aligned with the MSc research question:

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

### 1️⃣ Clone Repository
```bash
git clone https://github.com/<your-username>/mmsc-devsecops-pipeline.git
cd mmsc-devsecops-pipeline/app



2️⃣ Install Dependencies
npm install

3️⃣ Run Application Locally
node src/index.js


Access Application:
👉 http://localhost:3000

Expected Output

{
  "status": "OK",
  "timestamp": "2025-10-28T22:00:00Z"
}

🧪 Running Tests
npm test


Example Output:

PASS src/test/health.test.js
PASS src/test/tasks.test.js
PASS src/test/stats.test.js
Test Suites: 3 passed, 3 total
Tests:       10 passed, 10 total

🐳 Docker Usage
🏗️ Build Docker Image
docker build -t devsecops-demo-api .

🚀 Run Docker Container
docker run -d -p 3000:3000 devsecops-demo-api


Verify:

curl http://localhost:3000/health

📁 Application Structure
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

👨‍💻 Author

Name: Shahid Rasool
Programme: MSc Information Technology
University: University of the West of Scotland
Supervisor: Fath Ullah

📘 Project Title:
Design and Implementation of an Automated CI/CD Pipeline with Integrated DevSecOps Practices

🪪 License

This project is licensed under the MIT License.
You are free to use, modify, and share it for research and educational purposes.


> ✨ “Integrating security early isn’t a delay — it’s acceleration done right.” ✨
