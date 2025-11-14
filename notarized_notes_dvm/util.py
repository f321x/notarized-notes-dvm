import time
from typing import Optional
from hashlib import sha256

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

def round_up_division(a: int, b:int) -> int:
    return int(a // b) + (a % b > 0)

def int_to_bytes(x: int) -> bytes:
    assert type(x) == int
    return x.to_bytes(8, 'big')

def bytes_to_int(x: bytes) -> int:
    # we use 8 bytes.
    # this is enough for 21_000_000_00000000_000 millisats
    assert type(x) == bytes
    assert len(x) == 8
    return int.from_bytes(x, 'big')

def node_hash(left_h, left_v:int, right_h, right_v:int) -> bytes:
    return sha256(b"Node:" + left_h + int_to_bytes(left_v) + right_h + int_to_bytes(right_v)).digest()

def leaf_hash(event_id: bytes, value_msats:int, nonce:bytes, pubkey:bytes) -> bytes:
    return sha256(b"Leaf:" + event_id + int_to_bytes(value_msats) + nonce + (pubkey if pubkey else bytes(32))).digest()

def verify_signature(leaf_h, upvoter_pubkey, upvoter_signature) -> bool:
    pk = PublicKey(b'\x02' + upvoter_pubkey)
    return pk.verify_signed_message_hash(leaf_h, upvoter_signature)
