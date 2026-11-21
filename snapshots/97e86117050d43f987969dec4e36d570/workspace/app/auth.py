from fastapi import HTTPException
from .data import USERS

def actor(name):
    if name not in USERS:
        raise HTTPException(401, 'Unauthorized')
    return {'name': name, 'role': USERS[name]}
