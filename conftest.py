import pathlib

import pytest

import tol_registry

EXAMPLE_REGISTRY = pathlib.Path(__file__).parent / "tests" / "fixtures" / "example_registry.json"


@pytest.fixture(autouse=True)
def example_registry(monkeypatch):
    """Tests use a fabricated registry (Stripe etc.); the shipped default holds no invented IP mappings."""
    monkeypatch.setattr(tol_registry, "REGISTRY_PATH", EXAMPLE_REGISTRY)
