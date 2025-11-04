# Dockerfile.resource

FROM python:3.10-slim
WORKDIR /app

# Copy resource code
COPY src/resource.py .

# Copy certs directory (needed if you want SSL)
COPY certs/ certs/

# Install dependencies (Flask and Gunicorn)
RUN pip install --no-cache-dir flask gunicorn

# Expose resource service port
EXPOSE 8100

# Run resource API using Gunicorn with your preferred config:
CMD ["gunicorn", "-w", "2", "--threads", "4", "-k", "gthread", "-b", "0.0.0.0:8100", "resource:app"]
