"""Synthetic corrected API: never use with real user data."""
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()
RECORDS = {
    'one': {'owner': 'alice', 'value': 'synthetic-A'},
    'two': {'owner': 'bob', 'value': 'synthetic-B'},
}


@app.get('/records/{record_id}')
def read_record(record_id: str, x_test_user: str | None = Header(default=None)):
    if x_test_user is None:
        raise HTTPException(status_code=401)
    record = RECORDS.get(record_id)
    if record is None:
        raise HTTPException(status_code=404)
    if x_test_user != record['owner']:
        raise HTTPException(status_code=403)
    return {'id': record_id, **record}
