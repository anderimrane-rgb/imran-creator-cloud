FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8090
CMD ["gunicorn", "--bind", "0.0.0.0:8090", "--workers", "2", "--threads", "4", "server:app"]
