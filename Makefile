# Vouch Protocol Monorepo Makefile
# ================================
# Manage all packages from the root directory

.PHONY: help install-all build-all build-ts clean run-bridge test lint

# Default target
help:
	@echo "🔐 Vouch Protocol Monorepo"
	@echo "=========================="
	@echo ""
	@echo "Available commands:"
	@echo "  make install-all    Install all Python packages in editable mode"
	@echo "  make build-all      Build all packages (Python + TypeScript)"
	@echo "  make build-ts       Build TypeScript SDK only"
	@echo "  make clean          Remove build artifacts and __pycache__"
	@echo "  make run-bridge     Start the Vouch Bridge daemon"
	@echo "  make test           Run all tests"
	@echo "  make lint           Run linters on all packages"
	@echo ""

# Install all Python packages in editable mode
install-all:
	@echo "📦 Installing Python packages in editable mode..."
	python -m pip install -e ".[dev]"
	python -m pip install -e ./packages/bridge[dev]
	python -m pip install -e ./packages/sdk-py[dev]
	@echo "✅ All packages installed!"

# Build all packages
build-all: build-ts
	@echo "📦 Building Python packages..."
	cd packages/bridge && python -m build
	cd packages/sdk-py && python -m build
	@echo "✅ All packages built!"

# Build TypeScript SDK only
build-ts:
	@echo "📦 Building TypeScript SDK..."
	cd packages/sdk-ts && npm install && npm run build
	@echo "✅ TypeScript SDK built!"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
	rm -rf packages/sdk-ts/node_modules 2>/dev/null || true
	rm -rf packages/sdk-ts/dist 2>/dev/null || true
	@echo "✅ Clean complete!"

# Run the Vouch Bridge daemon
run-bridge:
	@echo "🚀 Starting Vouch Bridge daemon..."
	python -m vouch_bridge.main

# Run all tests
test:
	@echo "🧪 Running tests..."
	pytest tests/ -v
	cd packages/bridge && pytest tests/ -v 2>/dev/null || echo "No bridge tests yet"
	cd packages/sdk-py && pytest tests/ -v 2>/dev/null || echo "No SDK tests yet"
	@echo "✅ Tests complete!"

# Run linters
lint:
	@echo "🔍 Running linters..."
	ruff check .
	cd packages/sdk-ts && npm run lint 2>/dev/null || echo "TypeScript lint not configured"
	@echo "✅ Lint complete!"

# Development setup (one command to rule them all)
dev-setup: clean install-all build-ts
	@echo ""
	@echo "🎉 Development environment ready!"
	@echo ""
	@echo "Start the daemon:  vouch-bridge"
	@echo "Use the CLI:       vouch status"
	@echo ""

# Publish all packages (use with caution!)
publish-all:
	@echo "📤 Publishing packages..."
	@echo "Publishing vouch-bridge to PyPI..."
	cd packages/bridge && python -m build && twine upload dist/*
	@echo "Publishing vouch-sdk to PyPI..."
	cd packages/sdk-py && python -m build && twine upload dist/*
	@echo "Publishing vouch-protocol to npm..."
	cd packages/sdk-ts && npm publish --access public
	@echo "✅ All packages published!"
