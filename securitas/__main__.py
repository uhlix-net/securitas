import logging
import signal
import sys

from .config import Config
from .server import serve


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for name in ("weasyprint", "weasyprint.progress", "fontTools"):
        logging.getLogger(name).setLevel(logging.WARNING)
    # Running as PID 1 in a container: exit promptly on SIGTERM instead of waiting to be killed.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    serve(Config.from_env())


if __name__ == "__main__":
    main()
