from adb import adb_protocol

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

class FakeSHA1:
    oid = "1.3.14.3.2.26"  # SHA-1 OID

    def __init__(self, data: (bytes, bytearray)) -> None:
        self.reset()
        self._data = data

    def reset(self) -> None:
        self._data = b""

    def update(self, data: (bytes, bytearray)) -> None:
        self._data += data

    def digest(self) -> (bytes, bytearray):
        return self._data

class PycryptodomeSigner(adb_protocol.AuthSigner):
    def __init__(self, rsa_key_path=None):
        super(PycryptodomeSigner, self).__init__()

        if rsa_key_path:
            with open(rsa_key_path + '.pub', 'rb') as rsa_pub_file:
                self.public_key = rsa_pub_file.read()

            with open(rsa_key_path, 'rb') as rsa_priv_file:
                self.rsa_key = RSA.import_key(rsa_priv_file.read())

    def Sign(self, data):
        h = FakeSHA1(data)
        return PKCS1_v1_5.new(self.rsa_key).sign(h)

    def GetPublicKey(self):
        return self.public_key