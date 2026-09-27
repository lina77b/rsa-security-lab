import hashlib
import os

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    h_len = hash_func().digest_size
    output = bytearray()
    counter = 0
    while len(output) < length:
        c_bytes = counter.to_bytes(4, byteorder='big')
        output.extend(hash_func(seed + c_bytes).digest())
        counter += 1
    return bytes(output[:length])

def oaep_pad(message: bytes, k: int, label: bytes = b"") -> bytes:
    hash_func = hashlib.sha256
    h_len = hash_func().digest_size
    max_msg_len = k - 2 * h_len - 2
    
    if len(message) > max_msg_len:
        raise ValueError("Message too long for OAEP padding.")

    l_hash = hash_func(label).digest()
    ps = b'\x00' * (max_msg_len - len(message))
    db = l_hash + ps + b'\x01' + message
    
    seed = os.urandom(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    
    seed_mask = mgf1(masked_db, h_len, hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    
    return b'\x00' + masked_seed + masked_db

def oaep_unpad(padded_msg: bytes, k: int, label: bytes = b"") -> bytes:
    hash_func = hashlib.sha256
    h_len = hash_func().digest_size
    
    if len(padded_msg) != k or padded_msg[0] != 0:
        raise ValueError("Decryption/Unpadding error (Length or leading byte).")

    masked_seed = padded_msg[1:h_len + 1]
    masked_db = padded_msg[h_len + 1:]

    seed_mask = mgf1(masked_db, h_len, hash_func)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    l_hash = hash_func(label).digest()
    if db[:h_len] != l_hash:
        raise ValueError("Decryption/Unpadding error (Hash mismatch).")

    idx = h_len
    while idx < len(db) and db[idx] == 0:
        idx += 1

    if idx >= len(db) or db[idx] != 1:
        raise ValueError("Decryption/Unpadding error (Invalid separator).")

    return db[idx + 1:]