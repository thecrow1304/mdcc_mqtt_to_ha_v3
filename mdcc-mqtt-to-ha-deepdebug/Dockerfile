
FROM python:3.11-slim
WORKDIR /app
COPY run.py .
RUN pip install --no-cache-dir paho-mqtt requests
CMD ["python3", "run.py"]
