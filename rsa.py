"""
Módulo RSA implementado sem bibliotecas de criptografia prontas.
Contém:
- geração de primos (Miller-Rabin)
- geração de chaves (n, e, d)
- funções de cifrar/decifrar mensagens (chunking de bytes)
- funções utilitárias (egcd, modinv)

Uso principal: import rsa; rsa.generate_keys(bits)
"""

import secrets
import random
import math

# --- utilitários ---

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = egcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (g, x, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('Inverse does not exist')
    else:
        return x % m

# --- primalidade: Miller-Rabin ---

def is_prime(n, k=20):
    """Teste de primalidade probabilístico Miller-Rabin."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # escreva n-1 como d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # 2 <= a <= n-2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def generate_prime(bits):
    """Gera um primo de tamanho `bits` usando Miller-Rabin."""
    if bits < 16:
        raise ValueError('bits must be >= 16')
    while True:
        # Gera um ímpar com bit alto setado
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

# --- RSA ---

def generate_keys(bits=1024, e=65537):
    """Gera par de chaves RSA (n, e, d).
    Retorna dicionário: {'n':n, 'e':e, 'd':d}
    Use bits para o tamanho total de n (aprox n tem bits de magnitude)
    """
    if bits < 64:
        raise ValueError('Use bits >= 64 for reasonable security')

    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            try:
                d = modinv(e, phi)
                return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}
            except ValueError:
                # modinv falhou, gerar novamente
                continue

# --- conversão e cifragem ---

def _max_chunk_bytes(n):
    # tamanho máximo em bytes para que m < n
    return (n.bit_length() - 1) // 8


def encode_message_to_ints(message: str, n: int):
    """Converte string para lista de inteiros (cada inteiro < n), usando chunking de bytes.
    Retorna (chunks, chunk_size) onde chunks é lista de ints e chunk_size é tamanho fixo em bytes.
    """
    data = message.encode('utf-8')
    k = _max_chunk_bytes(n)
    if k <= 0:
        raise ValueError('Modulus too small to encode any data')

    chunks = [data[i:i + k] for i in range(0, len(data), k)]
    ints = [int.from_bytes(chunk, byteorder='big') for chunk in chunks]
    last_chunk_len = len(chunks[-1]) if chunks else 0
    return ints, k, len(data), last_chunk_len


def decode_ints_to_message(ints, chunk_size, orig_len, last_chunk_len):
    parts = []
    if not ints:
        return ''
    # all but last chunk use full chunk_size; last chunk uses last_chunk_len
    for i, val in enumerate(ints):
        if i == len(ints) - 1:
            length = last_chunk_len
        else:
            length = chunk_size
        parts.append(val.to_bytes(length, byteorder='big'))
    data = b''.join(parts)
    data = data[:orig_len]
    return data.decode('utf-8', errors='strict')


def encrypt_int(m: int, e: int, n: int):
    return pow(m, e, n)


def decrypt_int(c: int, d: int, n: int):
    return pow(c, d, n)


def encrypt_message(message: str, e: int, n: int):
    ints, chunk_size, orig_len, last_chunk_len = encode_message_to_ints(message, n)
    ciphertext = [encrypt_int(m, e, n) for m in ints]
    return ciphertext, chunk_size, orig_len, last_chunk_len


def decrypt_message(ciphertext, d: int, n: int, chunk_size, orig_len, last_chunk_len):
    ints = [decrypt_int(c, d, n) for c in ciphertext]
    # convert back to message
    return decode_ints_to_message(ints, chunk_size, orig_len, last_chunk_len)

# --- helpers para salvar/carregar chaves (simples) ---

def keypair_to_dict(kp):
    return {'n': kp['n'], 'e': kp['e'], 'd': kp['d'], 'p': kp.get('p'), 'q': kp.get('q')}


if __name__ == '__main__':
    print('Módulo RSA. Importe e use generate_keys/encrypt_message/decrypt_message.')
