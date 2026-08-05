from __future__ import annotations

import os
from functools import lru_cache
from urllib.parse import urlparse

from dotenv import load_dotenv
from openai import AzureOpenAI

# Load .env from the project root; no-op if already set in the environment
load_dotenv()


def _base_url(endpoint: str) -> str:
    """Strip any path/query from the endpoint — SDK needs only scheme://host/."""
    parsed = urlparse(endpoint)
    return f"{parsed.scheme}://{parsed.netloc}/"


@lru_cache(maxsize=1)
def get_client() -> AzureOpenAI:
    """Returns a cached AzureOpenAI client. Reads credentials from env vars."""
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
    api_key = os.environ.get("AZURE_OPENAI_KEY", "").strip()
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2025-04-01-preview").strip()

    if not endpoint or not api_key:
        raise EnvironmentError(
            "Azure OpenAI credentials not configured. "
            "Set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_KEY environment variables."
        )

    return AzureOpenAI(
        azure_endpoint=_base_url(endpoint),
        api_key=api_key,
        api_version=api_version,
    )


def chat(system: str, user: str, deployment: str | None = None, max_tokens: int = 512) -> str:
    """Sends a single chat completion request and returns the response text."""
    model = deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    client = get_client()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_completion_tokens=max_tokens,
    )
    return response.choices[0].message.content or ""
