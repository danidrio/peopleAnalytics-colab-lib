from . import utils

__all__ = [
    "utils",
    "GeminiClient"
]

def __getattr__(name):
    if name == "GeminiClient":
        from .gemini_client import GeminiClient

        return GeminiClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
