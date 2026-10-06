FROM python:3.11-slim

WORKDIR /app
COPY rdiff/ /app/rdiff/

# 无第三方依赖；保持只读根文件系统友好
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "-m", "rdiff"]
