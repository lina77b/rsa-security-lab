import hashlib
from math_utils import generate_prime, mod_inverse, mod_pow, extended_gcd

def generate_keypair(bits: int = 2048):
    e = 65537
    
    # Loop until we find p and q such that e and phi(n) are coprime
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        
        gcd, _, _ = extended_gcd(e, phi)
        if gcd == 1:
            break

    d = mod_inverse(e, phi)
    
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def encrypt_raw(message_int: int, public_key: tuple) -> int:
    e, n = public_key
    if message_int >= n:
        raise ValueError("Message integer must be smaller than modulus n.")
    return mod_pow(message_int, e, n)

def decrypt_raw(ciphertext_int: int, private_key: tuple) -> int:
    d, n = private_key
    return mod_pow(ciphertext_int, d, n)

def sign_message(message: bytes, private_key: tuple) -> int:
    d, n = private_key
    # Hash the message using SHA-256 and convert to an integer
    msg_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
    # The signature is the hash raised to the power of d modulo n
    return mod_pow(msg_hash, d, n)

def verify_signature(message: bytes, signature: int, public_key: tuple) -> bool:
    e, n = public_key
    # Calculate the expected hash of the original message
    expected_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
    # Decrypt the signature using the public key to retrieve the hash
    decrypted_hash = mod_pow(signature, e, n)
    # The signature is valid if the hashes match
    return expected_hash == decrypted_hash