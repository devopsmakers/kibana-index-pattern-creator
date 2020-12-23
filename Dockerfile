FROM python:3.8-alpine

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/main.py .
USER nobody
ENTRYPOINT ["python", "main.py"]
