#!/usr/bin/env python3
"""
Vouch Protocol - Monorepo Management Script

Alternative to Makefile for those who prefer Python.
Usage: python manage.py <command>
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parent.resolve()
PACKAGES = ROOT / "packages"


def run(cmd: str, cwd: Path | None = None, check: bool = True) -> int:
    """Run a shell command."""
    print(f"  → {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd or ROOT)
    if check and result.returncode != 0:
        print(f"  ✗ Command failed with code {result.returncode}")
    return result.returncode


def install_all():
    """Install all Python packages in editable mode."""
    print("📦 Installing Python packages in editable mode...")
    run("pip install -e ./packages/bridge[dev]")
    run("pip install -e ./packages/sdk-py[dev]")
    print("✅ All packages installed!")


def build_ts():
    """Build TypeScript SDK."""
    print("📦 Building TypeScript SDK...")
    run("npm install", cwd=PACKAGES / "sdk-ts")
    run("npm run build", cwd=PACKAGES / "sdk-ts")
    print("✅ TypeScript SDK built!")


def build_all():
    """Build all packages."""
    build_ts()
    print("📦 Building Python packages...")
    run("python -m build", cwd=PACKAGES / "bridge")
    run("python -m build", cwd=PACKAGES / "sdk-py")
    print("✅ All packages built!")


def clean():
    """Remove build artifacts."""
    print("🧹 Cleaning build artifacts...")
    
    patterns_to_remove = [
        "__pycache__",
        "*.egg-info",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
    ]
    
    for pattern in patterns_to_remove:
        for path in ROOT.rglob(pattern):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
                print(f"  Removed: {path.relative_to(ROOT)}")
    
    # Remove node_modules
    node_modules = PACKAGES / "sdk-ts" / "node_modules"
    if node_modules.exists():
        shutil.rmtree(node_modules, ignore_errors=True)
        print(f"  Removed: {node_modules.relative_to(ROOT)}")
    
    print("✅ Clean complete!")


def run_bridge():
    """Start the Vouch Bridge daemon."""
    print("🚀 Starting Vouch Bridge daemon...")
    run("python -m vouch_bridge.main")


def test():
    """Run all tests."""
    print("🧪 Running tests...")
    run("pytest tests/ -v", check=False)
    run("pytest tests/ -v", cwd=PACKAGES / "bridge", check=False)
    run("pytest tests/ -v", cwd=PACKAGES / "sdk-py", check=False)
    print("✅ Tests complete!")


def lint():
    """Run linters."""
    print("🔍 Running linters...")
    run("ruff check .")
    run("npm run lint", cwd=PACKAGES / "sdk-ts", check=False)
    print("✅ Lint complete!")


def dev_setup():
    """Full development environment setup."""
    clean()
    install_all()
    build_ts()
    print()
    print("🎉 Development environment ready!")
    print()
    print("Start the daemon:  vouch-bridge")
    print("Use the CLI:       vouch status")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="🔐 Vouch Protocol Monorepo Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  install-all    Install all Python packages in editable mode
  build-all      Build all packages (Python + TypeScript)
  build-ts       Build TypeScript SDK only
  clean          Remove build artifacts and __pycache__
  run-bridge     Start the Vouch Bridge daemon
  test           Run all tests
  lint           Run linters on all packages
  dev-setup      Full development environment setup (recommended)
"""
    )
    
    parser.add_argument(
        "command",
        choices=[
            "install-all", "build-all", "build-ts",
            "clean", "run-bridge", "test", "lint", "dev-setup"
        ],
        help="Command to run"
    )
    
    args = parser.parse_args()
    
    commands = {
        "install-all": install_all,
        "build-all": build_all,
        "build-ts": build_ts,
        "clean": clean,
        "run-bridge": run_bridge,
        "test": test,
        "lint": lint,
        "dev-setup": dev_setup,
    }
    
    commands[args.command]()


if __name__ == "__main__":
    main()
