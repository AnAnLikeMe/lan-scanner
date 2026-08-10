FROM python:3.11-slim

# 安装 nmap (扫描必备)
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py .

# 安装 Flask
RUN pip install flask --no-cache-dir

# 创建数据卷目录
VOLUME /data

EXPOSE 5000

CMD ["python", "app.py"]