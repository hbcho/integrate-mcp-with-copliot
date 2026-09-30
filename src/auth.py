"""Authentication and authorization helpers for the activities API."""

from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import os
from time import time
from typing import Callable
from uuid import uuid4

import jwt
import pyotp
from fastapi import Depends, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pydantic import BaseModel, ValidationError


class Role(str, Enum):
    GUARDIAN = "guardian"
    TEACHER = "teacher"
    ADMIN = "admin"


class User(BaseModel):
    username: str
    password_hash: str
    role: Role
    institution_id: str
    mfa_secret: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str
    otp_code: str | None = None


class UserInfo(BaseModel):
    username: str
    role: Role
    institution_id: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserInfo


ACCESS_TOKEN_MINUTES = 20
REFRESH_TOKEN_DAYS = 7
TOKEN_ISSUER = "mergington-high-school-api"
password_hasher = PasswordHash.recommended()
bearer_scheme = HTTPBearer(auto_error=False)
_active_refresh_tokens: dict[str, UserInfo] = {}
_revoked_access_tokens: dict[str, int] = {}


def _auth_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "code": "UNAUTHORIZED",
            "message": "Authentication is required or the access token is invalid or expired.",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


def _configured_users() -> list[User]:
    raw_users = os.getenv("AUTH_USERS_JSON", "[]")
    try:
        users = [User.model_validate(item) for item in json.loads(raw_users)]
    except (json.JSONDecodeError, TypeError, ValidationError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AUTH_CONFIGURATION_ERROR", "message": "Authentication is not configured correctly."},
        ) from error

    if len({user.username for user in users}) != len(users):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AUTH_CONFIGURATION_ERROR", "message": "Authentication is not configured correctly."},
        )
    if any(user.role != Role.GUARDIAN and not user.mfa_secret for user in users):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AUTH_CONFIGURATION_ERROR", "message": "Authentication is not configured correctly."},
        )
    return users


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET_KEY", "")
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AUTH_CONFIGURATION_ERROR", "message": "Authentication is not configured correctly."},
        )
    return secret


def authenticate_user(username: str, password: str, otp_code: str | None = None) -> User | None:
    for user in _configured_users():
        if user.username == username:
            try:
                if not password_hasher.verify(password, user.password_hash):
                    return None
            except (TypeError, ValueError):
                return None
            if user.role != Role.GUARDIAN and (
                not otp_code or not pyotp.TOTP(user.mfa_secret).verify(otp_code, valid_window=1)
            ):
                return None
            return user
    return None


def create_access_token(user: User) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode(
        {
            "sub": user.username,
            "role": user.role.value,
            "institution_id": user.institution_id,
            "iss": TOKEN_ISSUER,
            "token_type": "access",
            "jti": str(uuid4()),
            "exp": expires_at,
        },
        _jwt_secret(),
        algorithm="HS256",
    )


def create_token_pair(user: User) -> tuple[str, str]:
    access_token = create_access_token(user)
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_DAYS)
    token_id = str(uuid4())
    refresh_token = jwt.encode(
        {
            "sub": user.username,
            "role": user.role.value,
            "institution_id": user.institution_id,
            "iss": TOKEN_ISSUER,
            "token_type": "refresh",
            "jti": token_id,
            "exp": expires_at,
        },
        _jwt_secret(),
        algorithm="HS256",
    )
    _active_refresh_tokens[token_id] = UserInfo(
        username=user.username,
        role=user.role,
        institution_id=user.institution_id,
    )
    return access_token, refresh_token


def rotate_refresh_token(refresh_token: str) -> tuple[str, str, UserInfo]:
    try:
        claims = jwt.decode(
            refresh_token,
            _jwt_secret(),
            algorithms=["HS256"],
            issuer=TOKEN_ISSUER,
            options={"require": ["exp", "sub", "role", "institution_id", "jti", "token_type"]},
        )
        token_id = claims["jti"]
        user = _active_refresh_tokens.get(token_id)
        if claims["token_type"] != "refresh" or user is None or user.username != claims["sub"]:
            raise _auth_error()
    except HTTPException:
        raise
    except (jwt.InvalidTokenError, KeyError, ValidationError, TypeError) as error:
        raise _auth_error() from error

    del _active_refresh_tokens[token_id]
    access_token, new_refresh_token = create_token_pair(
        User(
            username=user.username,
            password_hash="unused",
            role=user.role,
            institution_id=user.institution_id,
        )
    )
    return access_token, new_refresh_token, user


def revoke_refresh_token(refresh_token: str | None) -> None:
    if not refresh_token:
        return
    try:
        claims = jwt.decode(
            refresh_token,
            _jwt_secret(),
            algorithms=["HS256"],
            issuer=TOKEN_ISSUER,
            options={"require": ["exp", "jti", "token_type"]},
        )
        if claims["token_type"] == "refresh":
            _active_refresh_tokens.pop(claims["jti"], None)
    except (HTTPException, jwt.InvalidTokenError, KeyError, TypeError):
        return


def revoke_access_token(access_token: str) -> None:
    claims = jwt.decode(
        access_token,
        _jwt_secret(),
        algorithms=["HS256"],
        issuer=TOKEN_ISSUER,
        options={"require": ["exp", "jti", "token_type"]},
    )
    _revoked_access_tokens[claims["jti"]] = int(claims["exp"])


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> UserInfo:
    if credentials is None:
        raise _auth_error()

    try:
        claims = jwt.decode(
            credentials.credentials,
            _jwt_secret(),
            algorithms=["HS256"],
            issuer=TOKEN_ISSUER,
            options={"require": ["exp", "sub", "role", "institution_id", "jti", "token_type"]},
        )
        if claims["token_type"] != "access":
            raise _auth_error()
        now = int(time())
        for token_id, expires_at in list(_revoked_access_tokens.items()):
            if expires_at <= now:
                del _revoked_access_tokens[token_id]
        if claims["jti"] in _revoked_access_tokens:
            raise _auth_error()
        return UserInfo(
            username=claims["sub"],
            role=claims["role"],
            institution_id=claims["institution_id"],
        )
    except HTTPException:
        raise
    except (jwt.InvalidTokenError, KeyError, ValidationError, TypeError) as error:
        raise _auth_error() from error


def require_roles(*allowed_roles: Role) -> Callable:
    def check_role(user: UserInfo = Depends(get_current_user)) -> UserInfo:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "FORBIDDEN", "message": "Your role cannot perform this action."},
            )
        return user

    return check_role


def set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        "refresh_token",
        token,
        max_age=REFRESH_TOKEN_DAYS * 24 * 60 * 60,
        httponly=True,
        secure=os.getenv("AUTH_COOKIE_SECURE", "false").lower() == "true",
        samesite="strict",
        path="/auth",
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie("refresh_token", path="/auth", httponly=True, samesite="strict")
