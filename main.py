from rsa_core import generate_keypair, encrypt_raw, decrypt_raw, sign_message, verify_signature
from oaep import oaep_pad, oaep_unpad
from attack_demo import run_malleability_attack

def main():
    print("Generating 2048-bit RSA keypair...")
    public_key, private_key = generate_keypair(bits=2048)
    e, n = public_key
    k = (n.bit_length() + 7) // 8

    # 1. Encryption & Decryption with OAEP 
    message = b"Secret message using custom RSA with OAEP!"
    print(f"\n[ENCRYPTION] Original Message: {message.decode('utf-8')}")

    # OAEP Padding
    padded_msg = oaep_pad(message, k)
    msg_int = int.from_bytes(padded_msg, byteorder='big')

    # Encryption
    ciphertext_int = encrypt_raw(msg_int, public_key)
    print("[ENCRYPTION] Message encrypted successfully using OAEP + RSA.")

    # Decryption
    decrypted_int = decrypt_raw(ciphertext_int, private_key)
    decrypted_bytes = decrypted_int.to_bytes(k, byteorder='big')

    # OAEP Unpadding
    recovered_msg = oaep_unpad(decrypted_bytes, k)
    print(f"[DECRYPTION] Recovered Message: {recovered_msg.decode('utf-8')}")
    
    assert message == recovered_msg

    #2 Digital Signature
    print("\n[SIGNATURE] --- Testing Digital Signature ---")
    doc_to_sign = b"Contract agreement document."
    print(f"[SIGNATURE] Document to sign: {doc_to_sign.decode('utf-8')}")
    
    signature = sign_message(doc_to_sign, private_key)
    print("[SIGNATURE] Document signed successfully with the private key.")
    
    is_valid = verify_signature(doc_to_sign, signature, public_key)
    print(f"[SIGNATURE] Is the signature valid? {is_valid}")
    assert is_valid is True

    # 3 Vulnerability Demonstration 
    run_malleability_attack()

if __name__ == "__main__":
    main()