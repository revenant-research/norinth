import argparse
import ast
import json
import logging
import os
from datetime import datetime, timezone
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
        # Check for model=... kwargs
        model_name = None
        for keyword in node.keywords:
            if keyword.arg == "model":
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    model_name = keyword.value.value
                    self.models.add(model_name)
                elif isinstance(keyword.value, ast.Name):
                    # It's a variable, harder to statically analyze but we note the dynamic nature
                    model_name = f"<dynamic_from_var:{keyword.value.id}>"
                    self.models.add(model_name)
                    
        # Rough check for function name to identify provider calls
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
        "scanned_at": datetime.now(timezone.utc).isoformat(),
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
                with open(filepath, "r", encoding="utf-8") as f:
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

    # Convert sets to lists for JSON serialization
    manifest["providers_detected"] = list(manifest["providers_detected"])
    manifest["models_detected"] = list(manifest["models_detected"])
    
    return manifest

def main() -> None:
    parser = argparse.ArgumentParser(description="Norinth Codebase Static Scanner")
    parser.add_argument("directory", nargs="?", default=".", help="Directory to scan (defaults to current)")
    parser.add_argument("--output", "-o", default="ai-manifest.json", help="Output JSON file path")
    
    args = parser.parse_args()
    
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

if __name__ == "__main__":
    main()
