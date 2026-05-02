import os
from google import genai


class GeminiClient:
    DEFAULT_SECRET_NAME = "GEMINI_API_KEY"
    DEFAULT_MODEL = "gemini-2.5-flash"

    def __init__(self, api_key, model=DEFAULT_MODEL):
        if not api_key or not api_key.strip():
            raise ValueError("api_key no especificada")
        
        self.model = model
        os.environ[self.DEFAULT_SECRET_NAME] = api_key
        self.client = genai.Client()

    def generate(self, prompt, model=None):
        response = self.client.models.generate_content(
            model=model or self.model,
            contents=prompt
        )
        return response.text

    def close(self):
        self.client.close()