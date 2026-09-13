"""Deploy a built webshell to a target container via the orchestrator."""

import argparse
import base64
import json
import sys

import requests


def deploy(orchestrator_url: str, target: str, webshell_path: str, filename: str):
    with open(webshell_path, "rb") as f:
        content = f.read()

    payload = {
        "target": target,
        "file": base64.b64encode(content).decode(),
        "filename": filename,
    }

    resp = requests.post(f"{orchestrator_url}/deploy", json=payload, timeout=30)
    result = resp.json()

    if result.get("success"):
        print(f"Deployed to: {result['webshell_url']}")
        return result["webshell_url"]
    else:
        print(f"Deploy failed: {result.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy webshell to test target")
    parser.add_argument("--orchestrator", default="http://localhost:8090")
    parser.add_argument("--target", required=True, choices=["php", "aspx", "jsp", "go"])
    parser.add_argument("--file", required=True, help="Path to webshell file")
    parser.add_argument("--filename", required=True, help="Filename on target")
    args = parser.parse_args()

    deploy(args.orchestrator, args.target, args.file, args.filename)
