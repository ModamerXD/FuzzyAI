import logging
import os
from typing import Any, Optional, Union

import aiohttp
import backoff
import requests

from fuzzyai.enums import LLMRole
from fuzzyai.llm.models import BaseLLMProviderResponse
from fuzzyai.llm.providers.base import (BaseLLMMessage, BaseLLMProvider, BaseLLMProviderException,
                                        BaseLLMProviderRateLimitException, llm_provider_fm)
from fuzzyai.llm.providers.enums import LLMProvider, LLMProviderExtraParams
from fuzzyai.llm.providers.groq.models import GroqChatRequest
from fuzzyai.llm.providers.shared.decorators import api_endpoint, sync_api_endpoint

logger = logging.getLogger(__name__)

class GroqProviderException(BaseLLMProviderException):
    pass

class GroqConfig:
    API_BASE_URL = "https://api.groq.com/openai/v1"
    CHAT_COMPLETIONS_ENDPOINT = "/chat/completions"
    API_KEY_ENV_VAR = "GROQ_API_KEY"

@llm_provider_fm.flavor(LLMProvider.GROQ)
class GroqProvider(BaseLLMProvider):
    def __init__(self, model: str, **extra: Any):
        super().__init__(model=model, **extra)

        if (api_key := os.environ.get(GroqConfig.API_KEY_ENV_VAR)) is None:
            raise BaseLLMProviderException(f"{GroqConfig.API_KEY_ENV_VAR} not in os.environ. Please add it to your .env file.")

        self._headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        self._session = aiohttp.ClientSession(headers=self._headers)
        self._base_url = GroqConfig.API_BASE_URL
        self._tokenizer = None
        self.tokens_handler = None

    @classmethod
    def get_supported_models(cls) -> Union[list[str], str]:
        return [
            "llama-3.1-8b-instant", 
            "llama-3.3-70b-versatile", 
            "llama3-8b-8192", 
            "llama3-70b-8192", 
            "mixtral-8x7b-32768", 
            "gemma2-9b-it"
        ]

    @api_endpoint(GroqConfig.CHAT_COMPLETIONS_ENDPOINT)
    async def generate(self, prompt: str, url: str, system_prompt: Optional[str] = None, **extra: Any) -> Optional[BaseLLMProviderResponse]:
        messages = [BaseLLMMessage(role=LLMRole.USER, content=prompt)]
        messages = self._prepare_messages(messages, system_prompt)
        return await self.chat(messages=messages, **extra) # type: ignore
    
    @backoff.on_exception(backoff.expo, BaseLLMProviderRateLimitException, max_time=60)
    @api_endpoint(GroqConfig.CHAT_COMPLETIONS_ENDPOINT)
    async def chat(self, messages: list[BaseLLMMessage], url: str, system_prompt: Optional[str] = None, **extra: Any) -> BaseLLMProviderResponse:
        messages = self._prepare_messages(messages, system_prompt)
        try:
            request = GroqChatRequest(model=self._model_name, messages=messages, **extra)
            async with self._session.post(url, json=request.model_dump()) as response:
                groq_response = await response.json()
                self._handle_error_response(groq_response)
                choice = groq_response["choices"][0]
                return BaseLLMProviderResponse(response=choice['message']['content'])
        except (BaseLLMProviderRateLimitException, GroqProviderException) as e:
            raise e
        except Exception as e:            
            logger.error(f'Error generating text from Groq: {e}')
            raise GroqProviderException('Cant generate text')
    
    @backoff.on_exception(backoff.expo, BaseLLMProviderRateLimitException, max_time=60)
    def sync_generate(self, prompt: str, **extra: Any) -> Optional[BaseLLMProviderResponse]:
        messages = [BaseLLMMessage(role=LLMRole.USER, content=prompt)]
        
        if extra.get(LLMProviderExtraParams.APPEND_LAST_RESPONSE) and (history := self.get_history()):
            messages.append(BaseLLMMessage(role=LLMRole.ASSISTANT, content=history[-1].response))
        
        chat_extra_params = {k:v for k, v in extra.items() if k not in [LLMProviderExtraParams.APPEND_LAST_RESPONSE]}
        return self.sync_chat(messages, **chat_extra_params)  # type: ignore

    @sync_api_endpoint(GroqConfig.CHAT_COMPLETIONS_ENDPOINT)
    def sync_chat(self, messages: list[BaseLLMMessage], url: str, 
                  system_prompt: Optional[str] = None, **extra: Any) -> Optional[BaseLLMProviderResponse]:
        messages = self._prepare_messages(messages, system_prompt)

        try:
            request = GroqChatRequest(model=self._model_name, messages=messages, **extra)
            with requests.post(url, json=request.model_dump(), headers=self._headers) as response:
                groq_response = response.json()
                self._handle_error_response(groq_response)                    
                return BaseLLMProviderResponse(response=groq_response["choices"][0]['message']['content'])
        except (BaseLLMProviderRateLimitException, GroqProviderException) as e:
            raise e
        except Exception as e:            
            logger.error(f'Error generating text from Groq: {e}')
            raise GroqProviderException('Cant generate text')
    
    async def close(self) -> None:
        await self._session.close()

    def _prepare_messages(self, messages: list[BaseLLMMessage], 
                          system_prompt: Optional[str] = None) -> list[BaseLLMMessage]:
        if system_prompt:
            return [BaseLLMMessage(role=LLMRole.SYSTEM, content=system_prompt)] + messages
        return messages
    
    @staticmethod
    def _handle_error_response(response_data: dict[str, Any]) -> None:
        if error := response_data.get("error"):
            if error.get("code") == "rate_limit_exceeded":
                raise BaseLLMProviderRateLimitException("Rate limit exceeded")
            raise GroqProviderException(f"Groq error: {error.get('message', 'Unknown error')}")