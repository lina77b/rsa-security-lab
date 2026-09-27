import secrets

def mod_pow(base: int, exp: int, mod: int) -> int:
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result

def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a: int, m: int) -> int:
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % m

def miller_rabin(n: int, k: int = 40) -> bool:
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        composite = True
        for _ in range(s - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False

    return True

def generate_prime(bits: int) -> int:
    while True:
        # Ensures the number is exactly 'bits' long and is odd
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(p):
            return p