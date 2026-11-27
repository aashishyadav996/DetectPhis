"""
PhishTrace AI application package.
"""


def __getattr__(name: str):
    """
    Lazy attribute resolver for WSGI servers attempting to import 'app:app'.
    Resolves the Flask instance from root app.py without namespace collisions.
    """
    if name in ("app", "application"):
        import importlib.util
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location("main_flask_app", root / "app.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return getattr(mod, name)
    raise AttributeError(f"module 'app' has no attribute '{name}'")
