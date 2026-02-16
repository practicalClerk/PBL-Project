# Use Python 3.10 slim image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY train_model.py .
COPY phishing_features.csv .

# Create directories
RUN mkdir -p templates static/css static/js

# Copy templates and static files
COPY templates/ templates/
COPY static/ static/

# Train the model (generates phishing_model.pkl and scaler.pkl)
RUN python train_model.py

# Expose port 5000
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:5000/api/health')"

# Run the application
CMD ["python", "app.py"]
