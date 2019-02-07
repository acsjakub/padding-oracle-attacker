
from Oracle import Oracle
from Crypto.Cipher import DES

class DESOracle(Oracle):

    def __init__(self, key):
        self.key = key

    def decrypt_block(self, crafted_block, target_block):
        suite = DES.new(self.key, DES.MODE_CBC, crafted_block)
        plain_text = suite.decrypt(target_block)
        return self.validate_padding(plain_text)