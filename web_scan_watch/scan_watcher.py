#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
from pathlib import Path

from src.app import Application
from src.config import ExitCode

logger = logging.getLogger("scan_watcher")


def setup_logging(level: str = "INFO") -> None:
    log_level = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)
    logger.setLevel(log_level)


def parse_args() -> tuple[Path, str, bool, str]:
    import argparse

    parser = argparse.ArgumentParser(
        description="Web Application Scan Watcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0 - Success (scan completed or graceful shutdown)
  1 - Authorization failure
  2 - Configuration error
  3 - API error

Environment variables:
  {PREFIX}SF_TOKEN   - API authentication token (required)
  {PREFIX}SF_APP_URL - API base URL (required)

Example:
  %(prog)s config.yaml
  %(prog)s config.yaml --env-prefix=RUN1__
  RUN1__SF_TOKEN=xxx RUN1__SF_APP_URL=https://api.example.com %(prog)s config.yaml --env-prefix=RUN1__
        """,
    )

    parser.add_argument(
        "config",
        type=Path,
        help="Path to YAML/JSON configuration file",
    )
    parser.add_argument(
        "--env-prefix",
        default="",
        help="Environment variable prefix (e.g., RUN1__)",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Skip confirmation prompts for token warnings",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()
    return args.config, args.env_prefix, args.force, args.log_level


def main() -> int:
    try:
        config_path, env_prefix, force, log_level = parse_args()
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else ExitCode.CONFIG_ERROR

    setup_logging(log_level)
    logger.info(f"Loading configuration from {config_path}")

    app = Application()
    return app.run(config_path, env_prefix, force)


if __name__ == "__main__":
    sys.exit(main())
