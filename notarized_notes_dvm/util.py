import time
from typing import Optional

from electrum_aionostr.key import PublicKey

def now(): return int(time.time())

def is_hex_str(maybe_hex_str: str, bytes_length: Optional[int] = None) -> bool:
    try:
        length_input = len(bytes.fromhex(maybe_hex_str))
    except Exception:
        return False
    if bytes_length is not None:
        return length_input == bytes_length
    return True

def verify_signature(leaf_h, upvoter_pubkey, upvoter_signature) -> bool:
    pk = PublicKey(b'\x02' + upvoter_pubkey)
    return pk.verify_signed_message_hash(leaf_h, upvoter_signature)
