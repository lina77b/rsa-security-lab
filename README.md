# RSA Cryptography and Security Padding (Practical Work)

## Overview
This repository contains a self-made practical work (Travail Pratique) designed for the Information Security module. The project provides a complete, from-scratch implementation of the RSA cryptosystem to demonstrate its core mathematical mechanics and the critical security protocols required for real-world application. 

It fulfills the strict requirements of coding the RSA algorithm without relying on external cryptographic math libraries, featuring complete key generation, encryption, decryption, and digital signatures. It also highlights the difference between textbook RSA (highly vulnerable to manipulation) and secure RSA implementations using Optimal Asymmetric Encryption Padding (OAEP).

## Project Architecture
The codebase is modular and separated into specific cryptographic concerns:

* **math_utils.py**: Handles the fundamental arithmetic without external crypto libraries. It includes functions for modular exponentiation, the Extended Euclidean Algorithm, modular inverse calculations, and prime number generation using the Miller-Rabin primality test.
* **rsa_core.py**: Implements the textbook RSA mechanics. It handles 2048-bit keypair generation, the mathematical operations for raw encryption and decryption, as well as digital signing and verification using SHA-256 hashing.
* **oaep.py**: Implements the Optimal Asymmetric Encryption Padding (OAEP) scheme along with the required Mask Generation Function (MGF1). This module injects randomness into the plaintext before encryption, securing it against deterministic analysis.
* **attack_demo.py**: Contains a proof-of-concept malleability attack. It demonstrates how an attacker can manipulate raw RSA ciphertext in transit to predictably alter the decrypted message, proving the absolute necessity of secure padding schemes.
* **main.py**: The primary execution script that connects all modules. It runs a full encryption and decryption lifecycle using RSA-OAEP, processes a digital signature creation and verification, and triggers the malleability attack demonstration.

## Execution
To run the project execute the main script from your terminal:

python main.py# rsa-security-lab
