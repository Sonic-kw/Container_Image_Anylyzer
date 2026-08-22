# Używamy stabilnego Pythona
FROM python:3.11-slim

# Instalacja zależności systemowych: curl do instalacji Trivy i Docker CLI
RUN apt-get update && apt-get install -y curl gnupg lsb-release && rm -rf /var/lib/apt/lists/*
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.45.1
RUN apt-get update && apt-get install -y docker.io && rm -rf /var/lib/apt/lists/*

# Katalog roboczy
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# Domyślnie kontener będzie czekał na polecenie (interaktywny)
CMD ["python", "scanner.py"]