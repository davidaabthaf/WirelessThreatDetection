# Use Python base image
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy backend files
COPY backend/ /app/backend/
COPY data/ /app/data/
COPY results/ /app/results/

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
RUN pip install gunicorn

# Copy frontend files
COPY frontend/ /app/frontend/

# Build frontend
WORKDIR /app/frontend
RUN npm install
RUN npm run build

# Go back to app directory
WORKDIR /app

# Expose port
EXPOSE 7860

# Start backend server
CMD ["python", "backend/api_server.py"]