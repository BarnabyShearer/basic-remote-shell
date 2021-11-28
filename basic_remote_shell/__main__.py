"""Entrypoint."""
import argparse
import os
from urllib.parse import urlparse

from . import connect


def main() -> None:
    """Entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="URL to connect to")
    parser.add_argument(
        "-k", "--key", help="Filename of private key", default="~/.ssh/id_rsa"
    )
    args = parser.parse_args()
    url = urlparse(f"//{args.url}")
    connect(
        url.username or os.getlogin(),
        args.key,
        url.netloc.split(":")[0],
        url.port or 22,
    )


if __name__ == "__main__":
    main()
