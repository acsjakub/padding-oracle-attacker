
class Oracle:

    def __init__(self):
        pass

    def decrypt(self, message):
        pass

    def validate_padding(self, plain_text_block):
        pad_length = int(plain_text_block[-1])
        if (pad_length == 0 or pad_length > len(plain_text_block)):
            return False

        for i in range(pad_length):
            if plain_text_block[-i - 1] != pad_length:
                return False
        return True

