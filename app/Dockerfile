# Base Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy source and requirements
COPY src/ ./src/
COPY tests/ ./tests/
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python", "-m", "src.main"]
