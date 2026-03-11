"""
Demonstração rápida do uso do módulo `rsa.py`.
Gera chaves (bits reduzidos para demo), cifra e decifra uma mensagem.
"""
from rsa import generate_keys, encrypt_message, decrypt_message


def hex_ciphertext(ciphertext):
    return ' '.join([hex(c) for c in ciphertext])


def main():
    print('Gerando chaves RSA (demo, 512 bits)...')
    kp = generate_keys(bits=512)  # 512 para a demo ser rápida; use >= 2048 para produção
    n = kp['n']
    e = kp['e']
    d = kp['d']

    print('\nChaves geradas:')
    print('n (modulus) bits:', n.bit_length())
    print('e (public exp):', e)
    print('d (private exp): (oculto, mostrado truncado)')
    print(str(d)[:60] + '...')

    message = 'Olá, este é um teste de RSA implementado manualmente.'
    print('\nMensagem original:')
    print(message)

    ciphertext, chunk_size, orig_len, last_chunk_len = encrypt_message(message, e, n)
    print('\nCifrado (hex por bloco):')
    print(hex_ciphertext(ciphertext))

    decrypted = decrypt_message(ciphertext, d, n, chunk_size, orig_len, last_chunk_len)
    print('\nMensagem decifrada:')
    print(decrypted)

    print('\nConfere igualdade:', decrypted == message)

if __name__ == '__main__':
    main()
