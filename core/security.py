from fastapi.security import HTTPBearer
from typing import Optional
from datetime import datetime, timedelta
import bcrypt
from jose import jwt
from core.config import settings
from fastapi.requests import Request

reusable_oauth2 = HTTPBearer(scheme_name="Authorization")
PREFIX = "Bearer"


def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_access_token(claim: dict, expires_delta: Optional[timedelta] = None):
    to_encode = claim.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    jwt_token = jwt.encode(to_encode, settings.SECRET_KEY, settings.ALGORITHM)
    return jwt_token


def decode_access_token(token):
    payload = None
    try:
        auth_token = get_token(token)
        payload = jwt.decode(auth_token, settings.SECRET_KEY, settings.ALGORITHM)
    except Exception as e:
        print("Problem with token decode => ", str(e))
    return payload


def is_unauthorized_url(request: Request):
    allow_urls = [
        "/docs",
        "/openapi.json",
        "/auth/login",
        "/auth/register",
        "/auth/forgot-password",
        "/auth/verify-forgot-password-token",
        "/auth/refresh-token",
    ]
    current_url = request.url.path
    if current_url.startswith("/static"):
        return True

    if current_url in allow_urls:
        return True
    return False


def get_token(header):
    bearer, _, token = header.partition(" ")
    if bearer != PREFIX:
        raise ValueError("Invalid token")

    return token
