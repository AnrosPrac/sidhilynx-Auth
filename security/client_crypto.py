import hashlib
from nacl.signing import VerifyKey 
from nacl.exceptions import BadSignatureError


def derive_client_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def verify_signature(
    public_key_hex: str,
    message: bytes,
    signature_hex: str
) -> bool:
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(message, bytes.fromhex(signature_hex))
        return True
    except BadSignatureError:
        return False
