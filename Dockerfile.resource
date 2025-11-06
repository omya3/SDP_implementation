FROM python:3.10-slim
WORKDIR /app
COPY src/resource.py .
RUN pip install --no-cache-dir flask gunicorn
EXPOSE 8100
CMD ["gunicorn", "-w", "2", "--threads", "4", "-k", "gthread", "-b", "0.0.0.0:8100", "resource:app"]
