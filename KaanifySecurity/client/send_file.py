import os, sys, time, mimetypes, requests
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
from crypto.crypto_helpers import encrypt_bytes

def main():
    if len(sys.argv) < 5:
        print("Usage: python3 send_file.py <server_base_url> <from_user> <to_user> <path_to_file>")
        sys.exit(1)

    server, from_user, to_user, path = sys.argv[1:5]

    key_path = os.path.join(PROJECT_ROOT, "keys", "shared_key.bin")
    with open(key_path, "rb") as f:
        key = f.read()

    with open(path, "rb") as f:
        data = f.read()

    env = encrypt_bytes(key, data)
    content_type = mimetypes.guess_type(path)[0] or "application/octet-stream"

    payload = {
        "from_user": from_user,
        "to_user": to_user,
        "nonce_hex": env["nonce_hex"],
        "rounds": env["rounds"],
        "mix": env["mix"],
        "rate": env["rate"],
        "content_type": content_type,
        "filename": os.path.basename(path),
        "ciphertext_b64": env["ciphertext_b64"],
        "tag_hex": env["tag_hex"],
        "sent_at": time.time(),
    }
    r = requests.post(f"{server}/send", json=payload, timeout=30)
    print(r.json())

if __name__ == "__main__":
    main()