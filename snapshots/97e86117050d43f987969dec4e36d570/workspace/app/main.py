from fastapi import FastAPI, Header, Body
from .auth import actor
from .tickets import read_ticket, create_ticket, change_status
from .comments import read_comments

app = FastAPI(title='TicketDesk')

@app.get('/health')
def health():
    return {'status': 'ok'}

@app.get('/tickets/{ticket_id}')
def ticket(ticket_id: str, x_test_user: str = Header(default=None)):
    return read_ticket(ticket_id, actor(x_test_user))

@app.get('/tickets/{ticket_id}/comments')
def comments(ticket_id: str, x_test_user: str = Header(default=None)):
    return read_comments(ticket_id, actor(x_test_user))

@app.post('/tickets')
def create(payload: dict = Body(...), x_test_user: str = Header(default=None)):
    return create_ticket(payload.get('title'), actor(x_test_user))

@app.patch('/tickets/{ticket_id}')
def update(ticket_id: str, payload: dict = Body(...), x_test_user: str = Header(default=None)):
    return change_status(ticket_id, payload.get('status'), actor(x_test_user))
