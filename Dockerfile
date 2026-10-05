FROM python:3.12-alpine

WORKDIR /app
COPY rdiff.py /app/rdiff.py
RUN chmod +x /app/rdiff.py

ENTRYPOINT ["python3", "/app/rdiff.py"]
