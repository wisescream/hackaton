FROM python:3.10-slim

# Set work directory
WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose ports for Streamlit and Prometheus metrics
EXPOSE 8501
EXPOSE 8000

# Set Python path to ensure core and utils packages are visible
ENV PYTHONPATH=/app

# Run the Streamlit application
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
