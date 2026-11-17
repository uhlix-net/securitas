# Securitas: read-only CVE report for Kubernetes clusters scanned by Trivy Operator.
# PDF export uses WeasyPrint (no browser in the image).
FROM python:3.12.16-slim-trixie

ARG VERSION=dev
LABEL org.opencontainers.image.title="securitas" \
      org.opencontainers.image.description="Read-only CVE report for Kubernetes clusters scanned by Trivy Operator, ranked by CISA KEV and EPSS, with PDF export" \
      org.opencontainers.image.source="https://github.com/uhlix-net/securitas" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HOME=/tmp XDG_CACHE_HOME=/tmp \
    SECURITAS_VERSION=${VERSION} SECURITAS_DATA_DIR=/data

# Pango and HarfBuzz for WeasyPrint; DejaVu fonts so PDFs render the same everywhere.
# apt-get upgrade picks up security fixes released after the base image was built.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt
COPY securitas ./securitas

RUN useradd --uid 10001 --user-group --no-create-home --home-dir /tmp securitas \
 && mkdir -p /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python", "-m", "securitas"]
