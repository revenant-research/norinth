import argparse
import ast
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("norinth_cli")

AI_PROVIDERS = {"openai", "anthropic", "langchain", "cohere", "google.generativeai", "bedrock"}

class AIScanner(ast.NodeVisitor):
    def __init__(self, filepath: Path) -> None:
        self.filepath = filepath
        self.providers: set[str] = set()
        self.models: set[str] = set()
        self.norinth_instrumented = False
        self.calls: list[dict[str, Any]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            base_module = alias.name.split(".")[0]
            if base_module in AI_PROVIDERS:
                self.providers.add(base_module)
            if base_module == "norinth_logger":
                self.norinth_instrumented = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            base_module = node.module.split(".")[0]
            if base_module in AI_PROVIDERS:
                self.providers.add(base_module)
            if base_module == "norinth_logger":
                self.norinth_instrumented = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # model=... kwargs
        model_name = None
        for keyword in node.keywords:
            if keyword.arg == "model":
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    model_name = keyword.value.value
                    self.models.add(model_name)
                elif isinstance(keyword.value, ast.Name):
                    # dynamic model arg; note it, can't resolve statically
                    model_name = f"<dynamic_from_var:{keyword.value.id}>"
                    self.models.add(model_name)
                    
        # match provider call by function name
        func_name = None
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in {"create", "invoke", "predict", "complete", "stream"}:
            self.calls.append({
                "line": node.lineno,
                "operation": func_name,
                "model_detected": model_name
            })
            
        self.generic_visit(node)

def scan_directory(directory: str) -> dict[str, Any]:
    root_path = Path(directory).resolve()
    manifest: dict[str, Any] = {
        "schema_version": "2026-01",
        "scanned_at": datetime.now(UTC).isoformat(),
        "root_directory": str(root_path),
        "total_files_scanned": 0,
        "providers_detected": set(),
        "models_detected": set(),
        "norinth_instrumentation_detected": False,
        "ai_files": []
    }

    ignore_dirs = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "build", "dist"}

    for root, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            if not file.endswith(".py"):
                continue
            
            filepath = Path(root) / file
            manifest["total_files_scanned"] += 1
            
            try:
                with open(filepath, encoding="utf-8") as f:
                    content = f.read()
                
                tree = ast.parse(content, filename=str(filepath))
                scanner = AIScanner(filepath)
                scanner.visit(tree)
                
                if scanner.providers or scanner.models or scanner.norinth_instrumented:
                    manifest["providers_detected"].update(scanner.providers)
                    manifest["models_detected"].update(scanner.models)
                    if scanner.norinth_instrumented:
                        manifest["norinth_instrumentation_detected"] = True
                        
                    rel_path = filepath.relative_to(root_path)
                    manifest["ai_files"].append({
                        "file": str(rel_path),
                        "providers": list(scanner.providers),
                        "models": list(scanner.models),
                        "instrumented": scanner.norinth_instrumented,
                        "operations": scanner.calls
                    })
            except Exception as e:
                logger.debug(f"Failed to scan {filepath}: {e}")

    # sets -> lists for json
    manifest["providers_detected"] = list(manifest["providers_detected"])
    manifest["models_detected"] = list(manifest["models_detected"])
    
    return manifest

# --- norinth CLI -------------------------------------------------------------------
#
#   norinth scan [DIR]            static inventory of AI providers/models in a codebase
#   norinth init                  write NORINTH_* settings and print the snippet
#   norinth doctor                prove the path: endpoint, key, first event
#   norinth gate check            exit 0 only if the release gate is approved (CI)
#   norinth attest keygen|sign    sign eval results so gates accept them as evidence

ENV_KEYS = ("NORINTH_ENDPOINT", "NORINTH_API_KEY", "NORINTH_PROJECT", "NORINTH_ENVIRONMENT", "NORINTH_SERVICE", "NORINTH_APPLICATION_NAME")


def _ok(msg: str) -> None:
    print(f"  \u2713 {msg}")


def _bad(msg: str) -> None:
    print(f"  \u2717 {msg}")


def _http(method: str, url: str, *, key: str | None = None, body: dict | None = None, timeout: float = 10.0) -> tuple[int, dict | str]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json", "User-Agent": "norinth-cli"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", "replace")
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, raw


def _settings(args: argparse.Namespace) -> dict[str, str]:
    values = {k: os.environ.get(k, "") for k in ENV_KEYS}
    for attr, env in (("endpoint", "NORINTH_ENDPOINT"), ("api_key", "NORINTH_API_KEY"), ("project", "NORINTH_PROJECT"), ("environment", "NORINTH_ENVIRONMENT"), ("service", "NORINTH_SERVICE")):
        if getattr(args, attr, None):
            values[env] = getattr(args, attr)
    # .env fills gaps, never overrides real env vars
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip("\"'")
                if k in values and not values[k]:
                    values[k] = v
    return values


def cmd_scan(args: argparse.Namespace) -> int:
    print(f"Scanning directory: {Path(args.directory).resolve()} for AI providers and models...")
    manifest = scan_directory(args.directory)
    print(f"Scanned {manifest['total_files_scanned']} Python files.")
    print(f"Found {len(manifest['ai_files'])} files interacting with AI systems.")
    print(f"Providers detected: {', '.join(manifest['providers_detected']) or 'None'}")
    print(f"Models statically identified: {', '.join(manifest['models_detected']) or 'None'}")
    out_path = Path(args.output)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest written to {out_path}")
    return 0


def _prompt(label: str, default: str = "", secret: bool = False) -> str:
    if not sys.stdin.isatty():
        return default
    suffix = f" [{default}]" if default and not secret else ""
    try:
        if secret:
            import getpass

            value = getpass.getpass(f"{label}: ")
        else:
            value = input(f"{label}{suffix}: ")
    except EOFError:
        return default
    return value.strip() or default


def cmd_init(args: argparse.Namespace) -> int:
    """write NORINTH_* settings to .env and print the setup snippet"""
    current = _settings(args)
    endpoint = current["NORINTH_ENDPOINT"] or _prompt("Norinth endpoint (e.g. https://norinth.internal)", "http://localhost:8001")
    api_key = current["NORINTH_API_KEY"] or _prompt("Ingestion key (nrk_...)", secret=True)
    project = current["NORINTH_PROJECT"] or _prompt("Project", Path.cwd().name)
    environment = current["NORINTH_ENVIRONMENT"] or _prompt("Environment", "prod")
    service = current["NORINTH_SERVICE"] or _prompt("Service name", Path.cwd().name)
    if not api_key:
        _bad("an ingestion key is required (create one under Identity & Integrations, or pass --api-key)")
        return 2

    manifest = scan_directory(args.directory)
    providers = sorted(manifest["providers_detected"])
    values = {
        "NORINTH_ENDPOINT": endpoint.rstrip("/"),
        "NORINTH_API_KEY": api_key,
        "NORINTH_PROJECT": project,
        "NORINTH_ENVIRONMENT": environment,
        "NORINTH_SERVICE": service,
    }
    env_path = Path(args.env_file)
    existing = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    kept = [line for line in existing if not any(line.startswith(f"{k}=") for k in values)]
    env_path.write_text("\n".join(kept + [f"{k}={v}" for k, v in values.items()]) + "\n", encoding="utf-8")
    try:
        os.chmod(env_path, 0o600)
    except OSError:
        pass
    _ok(f"wrote {env_path} ({', '.join(values)}) — keep it out of version control")
    if providers:
        _ok(f"detected {', '.join(providers)} in {manifest['total_files_scanned']} files; wrap each client to record its calls")
    else:
        print("  - no OpenAI/Anthropic clients detected statically; explicit events still work")
    print(
        "\nAdd at startup:\n\n"
        "    import norinth_logger as norinth\n"
        "    norinth.init()          # reads NORINTH_* from the environment\n\n"
        "Wrap each provider client so its model calls are recorded:\n\n"
        "    from openai import OpenAI\n"
        "    client = norinth.wrap(OpenAI())   # use the returned client\n\n"
        "Then run `norinth doctor` to confirm events arrive."
    )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """check endpoint reachability, key, and that an event is accepted"""
    s = _settings(args)
    endpoint, key = s["NORINTH_ENDPOINT"].rstrip("/"), s["NORINTH_API_KEY"]
    print(f"Norinth doctor — {endpoint or '(no endpoint)'}")
    failures = 0
    if not endpoint:
        _bad("NORINTH_ENDPOINT is not set (run `norinth init` or pass --endpoint)")
        return 2
    if not key:
        _bad("NORINTH_API_KEY is not set")
        return 2

    status, body = _http("GET", f"{endpoint}/health")
    if status == 200 and isinstance(body, dict) and body.get("ok"):
        _ok(f"platform reachable at {endpoint}/health")
    else:
        _bad(f"{endpoint}/health returned {status}: {str(body)[:120]}")
        print("    check DNS/TLS, the port, and whether a proxy or egress policy blocks this host")
        return 1

    event = {
        "type": "sdk.health",
        "schema_version": "2026-01",
        "trace_id": f"trc_doctor_{int(time.time())}",
        "span_id": f"spn_doctor_{int(time.time() * 1000) % 10_000_000}",
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "service": s["NORINTH_SERVICE"] or "norinth-doctor",
        "environment": s["NORINTH_ENVIRONMENT"] or "dev",
        "project": s["NORINTH_PROJECT"] or "doctor",
        "attributes": {"mode": "observe", "fail_open": True, "failed_sends": 0, "metadata": {"source": "norinth doctor"}},
    }
    status, body = _http("POST", f"{endpoint}/v1/events/batch", key=key, body={"events": [event]})
    if status == 200 and isinstance(body, dict) and body.get("accepted", 0) >= 1:
        _ok(f"ingestion key accepted; test event stored (platform now holds {body.get('total')} events)")
    elif status == 401:
        failures += 1
        _bad("ingestion key rejected (401): wrong key, revoked, or issued by a different organization")
    elif status == 403:
        failures += 1
        _bad(f"forbidden (403): {body.get('detail') if isinstance(body, dict) else body}")
    elif status == 200:
        failures += 1
        _bad("platform answered but stored nothing (duplicate trace/span?) — re-run")
    else:
        failures += 1
        _bad(f"POST /v1/events/batch returned {status}: {str(body)[:160]}")

    if failures == 0:
        print("\nAll good. Open the dashboard: the event appears under Monitoring; your service appears in Inventory once it sends a model call.")
        return 0
    return 1


def cmd_gate_check(args: argparse.Namespace) -> int:
    """exit 0 only when the gate for (deployment, version) is approved"""
    s = _settings(args)
    endpoint, key = s["NORINTH_ENDPOINT"].rstrip("/"), s["NORINTH_API_KEY"]
    if not endpoint or not key:
        _bad("NORINTH_ENDPOINT and NORINTH_API_KEY are required")
        return 3
    from urllib.parse import urlencode

    url = f"{endpoint}/v1/gates/check?" + urlencode({"deployment_id": args.deployment, "version": args.version})
    deadline = time.time() + max(0, args.wait)
    while True:
        status, body = _http("GET", url, key=key)
        if status == 200 and isinstance(body, dict):
            if body.get("approved"):
                _ok(f"gate {body['gate_id']} approved by {body.get('decided_by')} at {body.get('decided_at')}")
                return 0
            msg = f"gate {body.get('gate_id')} is {body.get('status')}"
            if body.get("blocking"):
                msg += f": {body['blocking']}"
            if time.time() < deadline:
                print(f"  … {msg}; waiting")
                time.sleep(min(15, max(1, args.poll)))
                continue
            _bad(msg)
            return 1
        if status == 404:
            _bad(f"no gate for deployment {args.deployment!r} version {args.version!r}: {body.get('detail') if isinstance(body, dict) else body}")
            return 2
        if status == 401:
            _bad("ingestion key rejected (401)")
            return 3
        _bad(f"{url} returned {status}: {str(body)[:160]}")
        return 3


def cmd_attest(args: argparse.Namespace) -> int:
    from . import attest as attest_module

    if args.attest_cmd == "keygen":
        return attest_module.main(["keygen"])
    if args.attest_cmd == "sign":
        key_pem = os.environ.get("NORINTH_ATTEST_KEY") or (Path(args.key_file).read_text(encoding="utf-8") if args.key_file else "")
        if not key_pem:
            _bad("provide the private key via NORINTH_ATTEST_KEY or --key-file")
            return 2
        source = Path(args.input).read_text(encoding="utf-8") if args.input and args.input != "-" else sys.stdin.read()
        event = json.loads(source)
        attest_module.sign_eval_result(event, private_key_pem=key_pem, key_id=args.key_id)
        json.dump(event, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    return 2


def _add_connection_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--endpoint", help="Norinth base URL (default: NORINTH_ENDPOINT)")
    parser.add_argument("--api-key", help="Ingestion key (default: NORINTH_API_KEY)")
    parser.add_argument("--project")
    parser.add_argument("--environment")
    parser.add_argument("--service")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="norinth", description="Norinth SDK command line")
    sub = parser.add_subparsers(dest="cmd")

    scan = sub.add_parser("scan", help="Static inventory of AI providers/models in a codebase")
    scan.add_argument("directory", nargs="?", default=".")
    scan.add_argument("--output", "-o", default="ai-manifest.json")
    scan.set_defaults(func=cmd_scan)

    init = sub.add_parser("init", help="Write NORINTH_* settings to .env and print the setup snippet")
    _add_connection_flags(init)
    init.add_argument("--directory", default=".", help="Project directory to scan for AI clients")
    init.add_argument("--env-file", default=".env")
    init.set_defaults(func=cmd_init)

    doctor = sub.add_parser("doctor", help="Check endpoint, key, and that an event is accepted")
    _add_connection_flags(doctor)
    doctor.set_defaults(func=cmd_doctor)

    gate = sub.add_parser("gate", help="Release gate commands for CI")
    gate_sub = gate.add_subparsers(dest="gate_cmd")
    check = gate_sub.add_parser("check", help="Exit 0 only if the gate for a deployment version is approved")
    _add_connection_flags(check)
    check.add_argument("--deployment", required=True, help="deployment_id as sent in deployment.event")
    check.add_argument("--version", required=True, help="version as sent in deployment.event")
    check.add_argument("--wait", type=int, default=0, help="seconds to keep polling for approval (default: no wait)")
    check.add_argument("--poll", type=int, default=10, help="poll interval in seconds")
    check.set_defaults(func=cmd_gate_check)

    attest = sub.add_parser("attest", help="Sign eval results (see norinth_logger.attest)")
    attest_sub = attest.add_subparsers(dest="attest_cmd")
    attest_sub.add_parser("keygen", help="Generate an Ed25519 key pair")
    sign = attest_sub.add_parser("sign", help="Sign an eval.result event JSON (stdin or --input)")
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--key-file", help="PEM private key (or set NORINTH_ATTEST_KEY)")
    sign.add_argument("--input", default="-", help="event JSON file, '-' for stdin")
    attest.set_defaults(func=cmd_attest)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # bare `norinth <dir>` is treated as `scan <dir>`
    if argv and argv[0] not in {"scan", "init", "doctor", "gate", "attest", "-h", "--help"} and not argv[0].startswith("-"):
        argv = ["scan", *argv]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
