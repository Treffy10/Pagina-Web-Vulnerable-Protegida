FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./
RUN mkdir -p /app/uploads

# Genera un certificado autofirmado si no se monta uno propio en /app/certs
RUN chmod +x certs/generate_cert.sh

EXPOSE 5443

CMD ["sh", "-c", "test -f certs/cert.pem || bash certs/generate_cert.sh; python app.py"]
