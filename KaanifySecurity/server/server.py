import os, time
from typing import Optional, List, Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Form
from pydantic import BaseModel
from ..crypto.crypto_helpers import encrypt_bytes, decrypt_envelope, DEFAULT_ROUNDS, DEFAULT_MIX, DEFAULT_RATE

app = FastAPI(title="Kaanify Messenger (LAN demo)")

KEY_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")
os.makedirs(KEY_DIR, exist_ok=True)
KEY_PATH = os.path.abspath(os.path.join(KEY_DIR, "shared_key.bin"))
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "wb") as f:
        f.write(os.urandom(32))
with open(KEY_PATH, "rb") as f:
    SHARED_KEY = f.read()

MAILBOX: List[Dict] = []
CLIENTS: Dict[str, WebSocket] = {} 

class Envelope(BaseModel):
    from_user: str
    to_user: str
    nonce_hex: str
    rounds: int = DEFAULT_ROUNDS
    mix: str = DEFAULT_MIX
    rate: int = DEFAULT_RATE
    content_type: str = "application/octet-stream"
    filename: Optional[str] = None
    ciphertext_b64: str
    tag_hex: str
    sent_at: float

@app.post("/send")
async def send_message(env: Envelope):
    try:
        _, ok = decrypt_envelope(SHARED_KEY, env.dict())
    except Exception:
        ok = False
    item = env.dict() | {"ok": bool(ok)}
    MAILBOX.append(item)

    ws = CLIENTS.get(env.to_user)
    if ws:
        try:
            await ws.send_json(item)
        except Exception:
            pass
    return {"stored": True, "ok": bool(ok)}

@app.get("/inbox")
def inbox(user: str, limit: int = 50):
    out = [m for m in MAILBOX if m["to_user"] == user]
    return list(reversed(out[-limit:]))

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    user = websocket.query_params.get("user") or "anon"
    CLIENTS[user] = websocket
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if CLIENTS.get(user) is websocket:
            CLIENTS.pop(user, None)

@app.post("/encrypt_text_demo")
def encrypt_text_demo(text: str = Form(...), to_user: str = Form(...), from_user: str = Form("demo")):
    env = encrypt_bytes(SHARED_KEY, text.encode("utf-8"))
    env |= {
        "from_user": from_user,
        "to_user": to_user,
        "content_type": "text/plain; charset=utf-8",
        "filename": None,
        "sent_at": time.time(),
    }
    MAILBOX.append(env | {"ok": True})
    return env