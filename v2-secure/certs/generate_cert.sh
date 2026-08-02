#!/usr/bin/env bash
# ============================================================
# Genera un certificado TLS autofirmado (desarrollo/laboratorio)
# para levantar la app v2 en HTTPS.
#
# Uso:
#   bash certs/generate_cert.sh [dias_validez] [CN]
#
# Ejemplo:
#   bash certs/generate_cert.sh 825 localhost
#
# Para un entorno con dominio público real, sustituye estos
# archivos por un certificado emitido por Let's Encrypt (gratis):
#   sudo apt install certbot
#   sudo certbot certonly --standalone -d tu-dominio.com
#   cp /etc/letsencrypt/live/tu-dominio.com/fullchain.pem certs/cert.pem
#   cp /etc/letsencrypt/live/tu-dominio.com/privkey.pem   certs/key.pem
# ============================================================
set -euo pipefail

DAYS="${1:-825}"
CN="${2:-localhost}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CERT="$DIR/cert.pem"
KEY="$DIR/key.pem"

if command -v openssl >/dev/null 2>&1; then
    echo "[*] Generando certificado autofirmado (CN=$CN, validez=${DAYS} dias)..."
    openssl req -x509 -nodes \
        -newkey rsa:2048 \
        -keyout "$KEY" \
        -out "$CERT" \
        -days "$DAYS" \
        -subj "/C=CO/ST=Local/L=Local/O=Laboratorio-SecDevOps/OU=AppSegura-v2/CN=${CN}" \
        -addext "subjectAltName=DNS:${CN},DNS:localhost,IP:127.0.0.1"

    chmod 600 "$KEY"
    chmod 644 "$CERT"

    echo "[+] Certificado generado:"
    echo "    - $CERT"
    echo "    - $KEY"
    echo
    echo "[!] Es un certificado AUTOFIRMADO: el navegador mostrara una"
    echo "    advertencia de 'conexion no privada'. Es esperado en un"
    echo "    laboratorio local; acepta la excepcion para continuar."
    echo
    openssl x509 -in "$CERT" -noout -subject -issuer -dates
else
    echo "[ERROR] openssl no esta instalado. Instalalo con:"
    echo "  sudo apt-get install openssl   # Debian/Ubuntu"
    exit 1
fi
