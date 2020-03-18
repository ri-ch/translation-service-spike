import tornado.ioloop
import tornado.web

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key():
    print("Loading private key")
    with open("test_rsa", "rb") as key_file:
        private_key_bytes = key_file.read()
        return serialization.load_pem_private_key(private_key_bytes, None, default_backend())

def load_public_key():
    print("Loading public key")
    with open("test_rsa.pub", "rb") as key_file:
        public_key_bytes = key_file.read()
        return serialization.load_pem_public_key(public_key_bytes, default_backend())

def sign_message(message, private_key):
    print("Signing message")
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256
    )

def verify_message(message, signature, public_key):
    print("Verifying message")
    public_key.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256
    )

def log_message_details(request):
    print(request.headers)
    print(request.body)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello, world")

class Sign(tornado.web.RequestHandler):
    private_key = load_private_key()

    def post(self):
        log_message_details(request)
        signature = sign_message(request.body, private_key)
        self.write(signature)

class Verify(tornado.web.RequestHandler):
    public_key = load_public_key()

    def post(self):
        log_message_details(request)
        verify_message(request.body, request.headers['signature'], public_key)
        self.write("Signature verified successfully")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/sign", Sign),
        (r"/verify", Verify)

    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
