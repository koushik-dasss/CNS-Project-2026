# Project 6  
# Secure Message Encryption and Decryption using Triple DES (3DES)

## Overview

This project implements a complete Secure Message Encryption and Decryption system using the Triple DES (3DES / TDEA) symmetric encryption algorithm in Python. The implementation demonstrates secure plaintext encryption, ciphertext generation, decryption, performance benchmarking, AES comparison, and security validation using the PyCryptodome cryptographic library.

The project is divided into three modular Python programs:

- `3DES_core.py`
- `3DESvsAES.py`
- `3DES_SecurityTesting.py`

Each file demonstrates a different aspect of Triple DES encryption including:
- secure encryption and decryption,
- performance analysis,
- AES comparison,
- wrong-key testing,
- IV randomness validation,
- edge-case security testing.

---

# Problem Statement

In today’s digital age, secure communication is a critical requirement across all domains including banking, healthcare, and personal messaging. With increasing threats such as data breaches, message tampering, and unauthorized access, strong encryption mechanisms are essential for protecting sensitive information.

Although the original Data Encryption Standard (DES) was widely used historically, its security limitations led to the development of stronger algorithms. Triple DES (3DES) improves DES security by applying the DES encryption process three times using multiple keys.

This project designs and implements a secure message encryption and decryption system using Triple DES to ensure:
- confidentiality,
- secure communication,
- protection against brute-force attacks,
- secure ciphertext generation.

---

# Objectives

1. To understand the working principles of the Triple DES encryption algorithm and its advantages over DES.

2. To develop a secure system that accepts plaintext input and encrypts it using Triple DES.

3. To implement a decryption module that correctly recovers the original plaintext using the correct secret key.

4. To ensure data confidentiality and integrity through secure key handling and CBC mode encryption.

5. To evaluate system performance in terms of:
   - encryption speed,
   - decryption accuracy,
   - computational efficiency,
   - security strength.

6. To compare Triple DES with AES and analyze their practical differences in modern cryptographic systems.

---

# Project Structure

```text
Project_6_TripleDES/
│
├── 3DES_core.py
├── 3DESvsAES.py
├── 3DES_SecurityTesting.py
├── README.md

