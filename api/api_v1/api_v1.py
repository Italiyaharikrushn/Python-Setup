from fastapi import APIRouter
from .endpoints import auth

route_v1 = APIRouter()
route_v1.include_router((auth.router), prefix='/auth', tags=['auth'])
