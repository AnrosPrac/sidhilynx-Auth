from fastapi import Request, HTTPException
import time

from auth_utils import decode_access_token
from security.client_crypto import derive_client_id, verify_signature


async def client_bound_auth(request: Request):
    # 1️⃣ Get Authorization header
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth.split(" ", 1)[1]

    # 2️⃣ Decode JWT
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    token_client_id = payload.get("cid")
    if not token_client_id:
        raise HTTPException(status_code=401, detail="Unbound token")

    # 3️⃣ Get crypto headers
    pub = request.headers.get("X-Client-Public-Key")
    sig = request.headers.get("X-Client-Signature")
    ts = request.headers.get("X-Client-Timestamp")

    if not all([pub, sig, ts]):
        raise HTTPException(status_code=401, detail="Missing client proof")

    # 4️⃣ Timestamp check
    now = time.time()
    if abs(now - float(ts)) > 60:
        raise HTTPException(status_code=401, detail="Stale request")

    # 5️⃣ Verify signature
    message = f"{ts}:{request.url.path}".encode()

    if not verify_signature(
        public_key_hex=pub,
        message=message,
        signature_hex=sig
    ):
        raise HTTPException(status_code=401, detail="Invalid client signature")

    # 6️⃣ Derive client_id and compare
    derived_client_id = derive_client_id(bytes.fromhex(pub))

    if derived_client_id != token_client_id:
        raise HTTPException(status_code=401, detail="Client mismatch")

    # 7️⃣ Attach auth info to request
    request.state.user_id = payload["sub"]
    request.state.client_id = token_client_id
