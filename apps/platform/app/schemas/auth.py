from __future__ import annotations

from pydantic import BaseModel, Field

from app.services.auth import MIN_PASSWORD_LENGTH


class LoginRequest(BaseModel):
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH)
