from fastapi import HTTPException
from .data import TICKETS, COMMENTS

def read_comments(ticket_id, user):
    if ticket_id not in TICKETS:
        raise HTTPException(404, 'Not Found')
    return {'ticket_id': ticket_id, 'comments': list(COMMENTS.get(ticket_id, []))}
