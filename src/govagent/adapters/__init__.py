"""Model adapters. Only the scripted adapter has no optional dependencies.

  scripted  offline replay (tests, CI, control-layer evals)
  claude    Anthropic Messages API          pip install ".[claude]"
  bedrock   Amazon Bedrock Converse API     pip install ".[bedrock]"
  adk       Google ADK LlmAgent integration pip install ".[adk]"   (see adapters/adk.py)
"""

from .scripted import ScriptedAdapter

__all__ = ["ScriptedAdapter"]
