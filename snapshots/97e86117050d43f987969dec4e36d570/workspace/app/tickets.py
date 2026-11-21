from fastapi import HTTPException
from .data import TICKETS

def read_ticket(ticket_id, user):
    item = TICKETS.get(ticket_id)
    if item is None:
        raise HTTPException(404, 'Not Found')
    return dict(item)

def create_ticket(title, user):
    if not isinstance(title, str) or not 1 <= len(title.strip()) <= 100:
        raise HTTPException(422, 'Invalid title')
    key = str(max(int(k) for k in TICKETS) + 1)
    TICKETS[key] = {'id': key, 'owner': user['name'], 'title': title.strip(), 'status': 'open'}
    return dict(TICKETS[key])

def change_status(ticket_id, status, user):
    item = TICKETS.get(ticket_id)
    if item is None:
        raise HTTPException(404, 'Not Found')
    if user['role'] not in ('manager', 'admin'):
        raise HTTPException(403, 'Forbidden')
    if status not in ('open', 'closed'):
        raise HTTPException(422, 'Invalid status')
    item['status'] = status
    return dict(item)
