
from Oracle import Oracle
from Crypto.Cipher import AES

class AESOracle(Oracle):

    def __init__(self, key):
        self.key = key

    def decrypt_block(self, crafted_block, target_block):
        suite = AES.new(self.key, AES.MODE_CBC, crafted_block)
        plain_text = suite.decrypt(target_block)
        return self.validate_padding(plain_text)

