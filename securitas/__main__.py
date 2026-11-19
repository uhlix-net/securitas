import logging
import signal
import sys

from .config import Config
from .server import serve


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for name in ("weasyprint", "weasyprint.progress", "fontTools", "paramiko", "pypsrp", "spnego", "httpx", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
    logging.getLogger("weasyprint").setLevel(logging.ERROR)   # CSS it does not support is ignored, not an error
    # Running as PID 1 in a container: exit promptly on SIGTERM instead of waiting to be killed.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    serve(Config.from_env())


if __name__ == "__main__":
    main()
