from __future__ import annotations

import argparse
import json
import sys

import uvicorn

from .models import ContentInput, PipelineRequest
from .pipeline import UntrustedContentPipeline


def main() -> None:
    parser = argparse.ArgumentParser(prog="untrusted-content")
    subparsers = parser.add_subparsers(dest="command", required=True)

    server_parser = subparsers.add_parser("server", help="Run HTTP API server")
    server_parser.add_argument("--host", default="0.0.0.0")
    server_parser.add_argument("--port", type=int, default=8787)

    scan_text_parser = subparsers.add_parser("scan-text", help="Scan text from CLI")
    scan_text_parser.add_argument("content", help="Content to scan")
    scan_text_parser.add_argument("--source", default="cli")
    scan_text_parser.add_argument("--trust-level", choices=["untrusted", "semi-trusted", "trusted"], default="untrusted")

    scan_file_parser = subparsers.add_parser("scan-file", help="Scan file content")
    scan_file_parser.add_argument("path", help="Path to file")
    scan_file_parser.add_argument("--source", default="file")
    scan_file_parser.add_argument("--trust-level", choices=["untrusted", "semi-trusted", "trusted"], default="untrusted")

    args = parser.parse_args()

    if args.command == "server":
        uvicorn.run("untrusted_content_tool.api:app", host=args.host, port=args.port, reload=False)
        return

    pipeline = UntrustedContentPipeline()

    if args.command == "scan-text":
        request = PipelineRequest(
            input=ContentInput(content=args.content, source=args.source),
            pipeline={"trust_level": args.trust_level},
        )
        response = pipeline.process(request)
        print(json.dumps(response.model_dump(mode="json"), indent=2))
        return

    if args.command == "scan-file":
        path = args.path
        try:
            content = open(path, "r", encoding="utf-8").read()
        except OSError as exc:
            print(f"Failed to read {path}: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        request = PipelineRequest(
            input=ContentInput(content=content, source=args.source, url=path),
            pipeline={"trust_level": args.trust_level},
        )
        response = pipeline.process(request)
        print(json.dumps(response.model_dump(mode="json"), indent=2))
        return


if __name__ == "__main__":
    main()
