from rsa_core import generate_keypair, encrypt_raw, decrypt_raw
from math_utils import mod_pow

def run_malleability_attack():
    print("\n======================================================================")
    print("MALLEABILITY ATTACK DEMO — textbook RSA with NO padding")
    print("======================================================================")
    
    print("\n[*] Generating a 1024-bit RSA keypair for the victim...")
    public_key, private_key = generate_keypair(bits=1024)
    
    # Unpack the tuple into standard variables
    e, n = public_key
    
    # Use the unpacked variables 'e' and 'n' instead of public_key.e
    print(f"    Public key : (e={e}, n={str(n)[:40]}...)")

    original_amount = 500
    print(f"[*] Original transaction amount: {original_amount}")
    
    ciphertext = encrypt_raw(original_amount, public_key)
    print("    Victim encrypts the amount and sends the ciphertext.")

    print("\n[*] Attacker intercepts the ciphertext and modifies it (multiplier = 2)...")
    multiplier = 2
    multiplier_encrypted = mod_pow(multiplier, e, n)
    manipulated_ciphertext = (ciphertext * multiplier_encrypted) % n

    print("\n[*] Receiver gets the modified ciphertext and decrypts it...")
    decrypted_amount = decrypt_raw(manipulated_ciphertext, private_key)
    print(f"    Amount after decryption of manipulated ciphertext: {decrypted_amount}")

    assert decrypted_amount == original_amount * multiplier
    print("\n[+] Result: Malleability attack successful! This proves why raw RSA is insecure without padding.")