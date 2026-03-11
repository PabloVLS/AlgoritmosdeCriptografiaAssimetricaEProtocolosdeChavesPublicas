# RSA (implementação manual em Python)

Este repositório contém uma implementação didática completa do ciclo de vida do RSA sem o uso de bibliotecas de criptografia prontas.

Arquivos principais:
- `rsa.py` : implementação do RSA (geração de primos com Miller-Rabin, geração de chaves, cifragem e decifragem com chunking de mensagens).
- `demo.py`: exemplo de uso que gera chaves, cifra e decifra uma mensagem.

## Fundamentos matemáticos (resumo)

**Aritmética Modular**
- Operações são feitas modulo `n`: valores "diferem" por múltiplos inteiros de `n` são considerados equivalentes.
- Notação: `a ≡ b (mod n)` significa `n | (a-b)`.

**Números Primos e Totiente de Euler**
- RSA usa dois primos grandes `p` e `q` e define `n = p * q`.
- O totiente de Euler de `n` quando `n = p*q` (p e q primos distintos) é `phi(n) = (p-1)*(q-1)`.
- `phi(n)` é o número de inteiros menores que `n` e coprimos com `n`.

**Chaves e expoentes**
- Escolhe-se um expoente público `e` tal que `1 < e < phi(n)` e `gcd(e, phi(n)) = 1`.
- O expoente privado `d` é o inverso multiplicativo de `e` modulo `phi(n)`, ou seja `d*e ≡ 1 (mod phi(n))`.
- `d` é encontrado via algoritmo de Euclides estendido.

**Cifrar e Decifrar**
- Mensagem m codificada como inteiro menor que `n`.
- Cifrado: `c = m^e mod n`.
- Decifrado: `m = c^d mod n`.
- A segurança baseia-se na dificuldade do problema de fatoração de `n` em `p` e `q` para recuperar `phi(n)` e `d`.

## Conversão de mensagens

- Mensagens (strings UTF-8) são convertidas em bytes e divididas em blocos de tamanho máximo `k = floor((bitlen(n)-1)/8)` bytes.
- Cada bloco de bytes é transformado em um inteiro com `int.from_bytes(...)` antes da cifragem.
- Ao decifrar, reconstrói-se os blocos com `to_bytes(k, 'big')` e decodifica-se para UTF-8.

> Observação: Esta implementação usa chunking simples sem esquema de padding seguro (PKCS#) — para uso real em produção, deve-se aplicar padding e proteções adequadas.

## Como executar a demonstração

No Windows PowerShell, dentro da pasta do projeto, execute:

```powershell
python demo.py
```

`demo.py` gera chaves (512 bits para ser rápido na demo), cifra uma mensagem e mostra que a decifragem recupera o texto original.

Para testar com tamanhos maiores, altere o parâmetro `bits` em `demo.py`. Use `bits=2048` para chaves mais seguras (leva mais tempo para gerar).

## Interface Web local (opcional)

Há uma interface web simples que roda um pequeno servidor HTTP e permite gerar chaves, cifrar e decifrar via browser.

Para executar:

```powershell
python server.py
# abra no navegador: http://localhost:8000/ui.html
```

Essa UI usa os mesmos métodos do `rsa.py` e é apenas para demonstração local. Não exponha em produção.

## Sobre o vídeo demonstrativo

Você deve gravar um vídeo de até 5 minutos que mostre:
- Execução de `demo.py` ou fluxo equivalente.
- Impressão das chaves (N, e e, opcionalmente, d parcial/truncado).
- Cifrar uma mensagem e em seguida decifrá-la com a chave privada.

Sugestão de comandos para gravação:
- Abra o PowerShell no diretório do projeto
- Rode `python demo.py`
- Mostre saída e comente brevemente cada etapa

## Licença e avisos

Implementação educacional. Não use em produção sem adaptações de segurança (padding, geração de KDFs, proteção contra ataques laterais, etc.).
