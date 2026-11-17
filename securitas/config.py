"""Settings, read from SECURITAS_* environment variables."""
import os
from dataclasses import dataclass, field

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def _float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        raise SystemExit(f"{name} must be a number")


@dataclass
class Config:
    title: str = "Securitas"
    cluster_name: str = ""
    port: int = 8080
    refresh_seconds: int = 3600
    epss_min: float = 0.10
    namespaces: list = field(default_factory=list)
    kev_url: str = KEV_URL
    epss_url: str = EPSS_URL
    kev_max_age: int = 3300          # re-download KEV at most hourly
    epss_max_age: int = 12 * 3600    # EPSS is published daily
    data_dir: str = "/data"
    extra_dir: str = ""              # optional: extra platform JSON files (see README)
    paper: str = "letter"            # PDF page size: letter or A4
    api_url: str = ""                # optional: Kubernetes API URL, e.g. http://127.0.0.1:8001 (kubectl proxy)
    reports_file: str = ""           # optional: read reports from a file instead of the API (testing)

    @classmethod
    def from_env(cls):
        e = os.environ.get
        c = cls(
            title=e("SECURITAS_TITLE", "Securitas"),
            cluster_name=e("SECURITAS_CLUSTER_NAME", ""),
            port=int(e("SECURITAS_PORT", "8080")),
            refresh_seconds=max(60, int(_float("SECURITAS_REFRESH_SECONDS", 3600))),
            epss_min=_float("SECURITAS_EPSS_MIN", 0.10),
            namespaces=[n.strip() for n in e("SECURITAS_NAMESPACES", "").split(",") if n.strip()],
            kev_url=e("SECURITAS_KEV_URL", KEV_URL),
            epss_url=e("SECURITAS_EPSS_URL", EPSS_URL),
            data_dir=e("SECURITAS_DATA_DIR", "/data"),
            extra_dir=e("SECURITAS_EXTRA_DIR", ""),
            paper=e("SECURITAS_PAPER", "letter"),
            api_url=e("SECURITAS_API_URL", ""),
            reports_file=e("SECURITAS_REPORTS_FILE", ""),
        )
        if c.paper.lower() not in ("letter", "a4"):
            raise SystemExit("SECURITAS_PAPER must be letter or A4")
        return c
