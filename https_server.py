import http.server
import ssl

HOST = "0.0.0.0"
PORT = 8443

CERT_FILE = "pki/server/server-cert.pem"
KEY_FILE = "pki/server/server-private.pem"

server_address = (HOST, PORT)

httpd = http.server.HTTPServer(
    server_address,
    http.server.SimpleHTTPRequestHandler
)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile=CERT_FILE,
    keyfile=KEY_FILE
)

httpd.socket = context.wrap_socket(
    httpd.socket,
    server_side=True
)

print(f"HTTPS server running on https://localhost:{PORT}")

httpd.serve_forever()
