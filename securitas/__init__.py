"""Securitas: a read-only CVE report for Kubernetes clusters scanned by Trivy Operator."""
import os

__version__ = os.environ.get("SECURITAS_VERSION", "dev")
