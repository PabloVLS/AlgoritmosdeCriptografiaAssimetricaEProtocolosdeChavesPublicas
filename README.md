# RSA (Manual Implementation in Python)

This repository contains a complete educational implementation of the RSA lifecycle without using ready-made cryptography libraries.

## Main Files

- `rsa.py` : RSA implementation (prime generation using Miller–Rabin, key generation, encryption and decryption with message chunking).
- `demo.py`: usage example that generates keys, encrypts, and decrypts a message.

## Mathematical Foundations (Summary)

### Modular Arithmetic
- Operations are performed modulo `n`: values that differ by integer multiples of `n` are considered equivalent.
- Notation: `a ≡ b (mod n)` means `n | (a - b)`.

### Prime Numbers and Euler's Totient
- RSA uses two large primes `p` and `q` and defines `n = p * q`.
- The Euler totient of `n` when `n = p*q` (with distinct primes `p` and `q`) is `phi(n) = (p - 1)*(q - 1)`.
- `phi(n)` is the number of integers smaller than `n` that are coprime with `n`.

### Keys and Exponents
- A public exponent `e` is chosen such that `1 < e < phi(n)` and `gcd(e, phi(n)) = 1`.
- The private exponent `d` is the multiplicative inverse of `e` modulo `phi(n)`, meaning `d*e ≡ 1 (mod phi(n))`.
- `d` is found using the extended Euclidean algorithm.

### Encryption and Decryption
- Message `m` is encoded as an integer smaller than `n`.
- Encryption: `c = m^e mod n`.
- Decryption: `m = c^d mod n`.
- Security is based on the difficulty of factoring `n` into `p` and `q` to recover `phi(n)` and `d`.

## Message Conversion

- Messages (UTF-8 strings) are converted to bytes and divided into blocks with maximum size `k = floor((bitlen(n)-1)/8)` bytes.
- Each block of bytes is transformed into an integer using `int.from_bytes(...)` before encryption.
- During decryption, blocks are reconstructed with `to_bytes(k, 'big')` and decoded back to UTF-8.

> Note: This implementation uses simple chunking without a secure padding scheme (PKCS#). For real production use, proper padding and protections must be applied.

## How to Run the Demonstration

In Windows PowerShell, inside the project folder, run:

```powershell
python demo.py
