FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PCAP_HOST=0.0.0.0 \
    PCAP_PORT=8080

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY pcap_insight.py ./

RUN useradd --create-home --uid 10001 pcapinsight
USER pcapinsight

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)" || exit 1

CMD ["python", "pcap_insight.py"]
