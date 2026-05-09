from typing import Any, Optional
from pydantic import BaseModel
from fuzzyai.llm.providers.base import BaseLLMMessage

class GroqChatRequest(BaseModel):
    model: str
    messages: list[BaseLLMMessage]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None