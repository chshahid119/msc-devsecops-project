FROM python:3.10-slim

USER root

# -----------------------------------------------------
# Install system tools
# -----------------------------------------------------
RUN apt-get update && apt-get install -y \
    curl wget git unzip gnupg ca-certificates docker.io \
    apt-transport-https tzdata vim jq \
    && rm -rf /var/lib/apt/lists/*

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:${PATH}"

# -----------------------------------------------------
# Python security tools
# -----------------------------------------------------
RUN pip install --upgrade pip && \
    pip install bandit pip-audit pytest checkov

# -----------------------------------------------------
# Install tfsec
# -----------------------------------------------------
RUN curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash \
    && chmod +x /usr/local/bin/tfsec

# -----------------------------------------------------
# Install Trivy
# -----------------------------------------------------
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh - \
    && mv ./bin/trivy /usr/local/bin/trivy \
    && chmod +x /usr/local/bin/trivy

# -----------------------------------------------------
# Install Gitleaks (auto-detect latest release)
# -----------------------------------------------------
RUN curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
    | grep browser_download_url \
    | grep linux-amd64 \
    | cut -d '"' -f 4 \
    | wget -i - -O /usr/local/bin/gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# -----------------------------------------------------
# Default command
# -----------------------------------------------------
CMD ["bash"]
