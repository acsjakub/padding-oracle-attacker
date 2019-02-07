import attacker_module
import AESOracle
import DESOracle
import Logger
import binascii
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random

def test_AES_decryption(key_length, log_level):
    encryption_key = bytes(Random.get_random_bytes(key_length))
    encryption_iv = bytes(Random.get_random_bytes(AES.block_size))
    plain_text = bytes(Random.get_random_bytes(48))

    # init parameters for attacker
    logger = Logger.Logger(log_level)
    oracle = AESOracle.AESOracle(encryption_key)

    # we first need AES encryption procedure to obtain the ciphertext to decrypt
    # - testing purposes
    encryptor = AES.new(encryption_key, AES.MODE_CBC, encryption_iv)
    cipher_text = encryption_iv + encryptor.encrypt(plain_text)

    # we tell attacker to decrypt encrypted data using oracle
    attacker = attacker_module.OracleAttacker(oracle, logger)
    result = attacker.attack_oracle(cipher_text)

    # here, we want to check if attacker successfully decrypted the plaintext

    print('Cipher text(hex):\n{}'.format(binascii.hexlify(bytearray(cipher_text))))
    print('Plain text(hex):\n{}'.format(binascii.hexlify(bytearray(plain_text))))
    print('Attacker output(hex):\n{}'.format(binascii.hexlify((result))))

    test_result = result == bytearray(plain_text)
    print('\nTest succesful: {}\n'.format(test_result))
    return test_result

def test_DES_decryption(log_level):
    encryption_key = bytes(Random.get_random_bytes(8))
    encryption_iv = bytes(Random.get_random_bytes(8))
    plain_text = bytes(Random.get_random_bytes(48))
    logger = Logger.Logger(log_level)
    oracle = DESOracle.DESOracle(encryption_key)
    encryptor = DES.new(encryption_key, DES.MODE_CBC, encryption_iv)
    cipher_text = encryption_iv + encryptor.encrypt(plain_text)


    attacker = attacker_module.OracleAttacker(oracle, logger)
    result = attacker.attack_oracle(cipher_text, 8)

    # here, we want to check if attacker successfully decrypted the plaintext

    print('Cipher text(hex):\n{}'.format(binascii.hexlify(bytearray(cipher_text))))
    print('Plain text(hex):\n{}'.format(binascii.hexlify(bytearray(plain_text))))
    print('Attacker output(hex):\n{}'.format(binascii.hexlify((result))))

    test_result = result == bytearray(plain_text)
    print('\nTest succesful: {}\n'.format(test_result))
    return test_result

def test_AES_encryption(key_length, log_level):
    encryption_key = bytes(Random.get_random_bytes(key_length))
    plain_text = bytes(Random.get_random_bytes(48))

    # init parameters for attacker
    logger = Logger.Logger(log_level)
    oracle = AESOracle.AESOracle(encryption_key)

    attacker = attacker_module.OracleAttacker(oracle, logger)
    iv, cipher_text = attacker.encrypt_plaintext(plain_text)

    # need to make sure AES decryptor uses iv produced by attacker
    decryptor = AES.new(encryption_key, AES.MODE_CBC, iv)
    result = decryptor.decrypt(cipher_text)

    test_result = result == plain_text

    # here, we want to check if the ciphertext produced by attacker successfully
    # decrypts to original plaintext using the AES decryption procedure

    print('Plain text(hex):\n{}'.format(binascii.hexlify(bytearray(plain_text))))
    print('Attacker output(hex):\n{}'.format(binascii.hexlify(cipher_text)))
    print('Decrypted attacker output(hex):\n{}'.format(binascii.hexlify(result)))

    print('\nTest successful: {}\n'.format(test_result))
    return test_result


def test_AES_128():
    test_AES_decryption(16, Logger.Logger.WARNING_LEVEL)
    test_AES_encryption(16, Logger.Logger.WARNING_LEVEL)

def test_AES_192():

    test_AES_decryption(24, Logger.Logger.WARNING_LEVEL)
    test_AES_encryption(24, Logger.Logger.WARNING_LEVEL)

def test_AES_256():

    test_AES_decryption(32, Logger.Logger.WARNING_LEVEL)
    test_AES_encryption(32, Logger.Logger.WARNING_LEVEL)

def test_DES():

    test_DES_decryption(Logger.Logger.WARNING_LEVEL)

test_AES_128()
test_AES_192()
test_AES_256()
test_DES()
