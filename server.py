"""
Pequeno servidor HTTP para demo do RSA.
Fornece endpoints JSON:
- POST /api/generate  -> {'n':..., 'e':..., 'd':...}
- POST /api/encrypt   -> {'ciphertext': [hex,...], 'chunk_size':..., 'orig_len':..., 'last_chunk_len':...}
- POST /api/decrypt   -> {'message': '...'}

Serve também arquivos estáticos (incluindo `ui.html`).

Uso:
python server.py
Abra http://localhost:8000/ui.html
"""

from http.server import SimpleHTTPRequestHandler, HTTPServer
import json
import urllib.parse
import threading
import sys

from rsa import generate_keys, encrypt_message, decrypt_message

HOST = '127.0.0.1'
PORT = 8000

# armazena chaves geradas na memória para a sessão do servidor
_server_keys = None

class RSARequestHandler(SimpleHTTPRequestHandler):
    def _set_json_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def do_OPTIONS(self):
        # suporte a CORS para desenvolvimento local
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        # quando a raiz for solicitada, servir a UI diretamente
        path = urllib.parse.urlparse(self.path).path
        if path == '/' or path == '':
            self.path = '/ui.html'
        return super().do_GET()

    def do_POST(self):
        global _server_keys
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length > 0 else b''
        try:
            data = json.loads(raw.decode('utf-8')) if raw else {}
        except Exception:
            data = {}

        path = urllib.parse.urlparse(self.path).path

        if path == '/api/generate':
            bits = int(data.get('bits', 1024))
            # gerar chaves
            kp = generate_keys(bits=bits)
            _server_keys = kp
            resp = {
                'n': str(kp['n']),
                'e': str(kp['e']),
                'd': str(kp['d'])
            }
            self._set_json_headers(200)
            self.wfile.write(json.dumps(resp).encode('utf-8'))
            return

        if path == '/api/encrypt':
            message = data.get('message', '')
            # permitir fornecer e,n como override
            if 'n' in data and 'e' in data:
                n = int(data['n'])
                e = int(data['e'])
                ciphertext, chunk_size, orig_len, last_chunk_len = encrypt_message(message, e, n)
            else:
                if not _server_keys:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({'error': 'No server keypair generated'}).encode('utf-8'))
                    return
                ciphertext, chunk_size, orig_len, last_chunk_len = encrypt_message(message, int(_server_keys['e']), int(_server_keys['n']))
            # enviar como hex
            c_hex = [hex(c) for c in ciphertext]
            resp = {'ciphertext': c_hex, 'chunk_size': chunk_size, 'orig_len': orig_len, 'last_chunk_len': last_chunk_len}
            self._set_json_headers(200)
            self.wfile.write(json.dumps(resp).encode('utf-8'))
            return

        if path == '/api/decrypt':
            # requer chaves no servidor
            if not _server_keys:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({'error': 'No server keypair generated'}).encode('utf-8'))
                return
            c_hex = data.get('ciphertext', [])
            chunk_size = int(data.get('chunk_size', 0))
            orig_len = int(data.get('orig_len', 0))
            last_chunk_len = int(data.get('last_chunk_len', 0))
            # converter
            try:
                ciphertext = [int(x, 16) for x in c_hex]
                message = decrypt_message(ciphertext, int(_server_keys['d']), int(_server_keys['n']), chunk_size, orig_len, last_chunk_len)
                resp = {'message': message}
                self._set_json_headers(200)
                self.wfile.write(json.dumps(resp).encode('utf-8'))
            except Exception as e:
                self._set_json_headers(500)
                self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))
            return

        # rota não encontrada
        self._set_json_headers(404)
        self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))


def run(server_class=HTTPServer, handler_class=RSARequestHandler):
    server_address = (HOST, PORT)
    httpd = server_class(server_address, handler_class)
    print(f"Serving HTTP on http://{HOST}:{PORT} (press Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down server')
        httpd.server_close()


if __name__ == '__main__':
    run()
