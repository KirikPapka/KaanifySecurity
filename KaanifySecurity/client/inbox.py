import os, sys, json, time, asyncio, requests
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
from crypto.crypto_helpers import decrypt_envelope

try:
    import websockets  
except ImportError:
    websockets = None

def load_key():
    key_path = os.path.join(PROJECT_ROOT, "keys", "shared_key.bin")
    with open(key_path, "rb") as f:
        return f.read()

async def ws_listen(server: str, user: str, key: bytes):
    url = server.replace("http://", "ws://").replace("https://", "wss://") + f"/ws?user={user}"
    async with websockets.connect(url, ping_interval=20, ping_timeout=20) as ws:
        print(f"[ws] connected as {user}")
        while True:
            msg = await ws.recv()
            env = json.loads(msg)
            pt, ok = decrypt_envelope(key, env)
            kind = env.get("content_type","")
            if kind.startswith("text/"):
                print(f"[{env['from_user']} -> {env['to_user']}] ok={ok}: {pt.decode('utf-8','replace')}")
            else:
                print(f"[{env['from_user']} -> {env['to_user']}] ok={ok}: file {env.get('filename')} ({kind}), {len(pt)} bytes")
            await ws.send("ok")  

def poll_loop(server: str, user: str, key: bytes):
    seen = set()
    while True:
        resp = requests.get(f"{server}/inbox", params={"user": user}, timeout=10)
        for env in resp.json():
            uid = (env["nonce_hex"], env["from_user"], env["sent_at"])
            if uid in seen: 
                continue
            seen.add(uid)
            pt, ok = decrypt_envelope(key, env)
            kind = env.get("content_type","")
            if kind.startswith("text/"):
                print(f"[{env['from_user']} -> {env['to_user']}] ok={ok}: {pt.decode('utf-8','replace')}")
            else:
                print(f"[{env['from_user']} -> {env['to_user']}] ok={ok}: file {env.get('filename')} ({kind}), {len(pt)} bytes")
        time.sleep(2)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 inbox.py <server_base_url> <user>")
        sys.exit(1)
    server, user = sys.argv[1:3]
    key = load_key()
    if websockets is None:
        print("[inbox] websockets not installed; polling...")
        poll_loop(server, user, key)
    else:
        asyncio.run(ws_listen(server, user, key))

if __name__ == "__main__":
    main()