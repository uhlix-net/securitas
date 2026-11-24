# Securitas: CVE reports for Kubernetes (Trivy Operator), Linux (SSH) and Windows (WinRM) with scheduled scans,
# history, sign-in (local, LDAP, OpenID Connect) and roles. PDF export uses WeasyPrint (no browser in the image).
# Stage "agent": the Linux agent RPM (securitas-agent: compliance wrapper, Goss, setup command). Built on the build
# platform; the RPM itself is for x86_64 hosts (Goss is a static x86_64 binary). Securitas serves it at /agent/.
FROM --platform=$BUILDPLATFORM docker.io/library/rockylinux:9.3 AS agent
ARG VERSION=dev
ARG GOSS_VERSION=0.4.10
ARG GOSS_SHA256=26e365428946294bcec0c61d867bb3c8349f39feb3d0e6f59084e98632785cc7
RUN dnf -y install rpm-build && dnf clean all
WORKDIR /build
COPY agent/linux/ ./
COPY LICENSE ./
RUN curl -fsSL -o goss.tar.gz "https://github.com/goss-org/goss/releases/download/v${GOSS_VERSION}/goss_${GOSS_VERSION}_linux_x86_64.tar.gz" \
 && echo "${GOSS_SHA256}  goss.tar.gz" | sha256sum -c - \
 && tar -xzf goss.tar.gz goss && rm goss.tar.gz \
 && v=$(printf '%s' "$VERSION" | sed -E 's/^dev$/0.0.0~dev/; s/-/~/; s/[^A-Za-z0-9.~_+]//g') \
 && rpmbuild -bb --target x86_64 --define "_topdir /build/rpm" --define "_sourcedir /build" \
      --define "agent_version $v" --define "goss_version ${GOSS_VERSION}" --define "dist %{nil}" \
      --define "_binary_payload w9.gzdio" securitas-agent.spec \
 && mkdir /out && cp rpm/RPMS/x86_64/securitas-agent-*.rpm /out/

FROM python:3.12.16-slim-trixie

ARG VERSION=dev
LABEL org.opencontainers.image.title="securitas" \
      org.opencontainers.image.description="CVE reports for Kubernetes, Linux and Windows, ranked by CISA KEV and EPSS: scheduled scans, history, SSO/LDAP sign-in, roles, PDF export" \
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
COPY --from=agent /out/ ./agent/

RUN useradd --uid 10001 --user-group --no-create-home --home-dir /tmp securitas \
 && mkdir -p /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python", "-m", "securitas"]
