"""Settings availability response body."""

from pydantic import BaseModel


class SettingsResponse(BaseModel):
    database: bool
    docker: bool
    openai_api_key_present: bool
    toolchain: bool
