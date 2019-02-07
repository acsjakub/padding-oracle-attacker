
class bcolors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE  = '\033[94m'
    ENDC = '\033[0m'

class Logger:

    ERROR_LEVEL = 1
    WARNING_LEVEL = 2
    INFO_LEVEL = 3
    DEBUG_LEVEL = 4
    OWNER_NAME = ''

    def __init__(self, verbosity_level):
        self.level = verbosity_level

    def set_owner_name(self, owner_name):
        self.OWNER_NAME = owner_name

    def error(self, message):
        if (self.level >= self.ERROR_LEVEL):
            print(bcolors.RED + '[{}-ERROR]: {}'.format(self.OWNER_NAME, message) + bcolors.ENDC)

    def warn(self, message):
        if (self.level >= self.WARNING_LEVEL):
            print(bcolors.YELLOW + '[{}-WARNING]: {}'.format(self.OWNER_NAME, message) + bcolors.ENDC)

    def info(self, message):
        if (self.level >= self.INFO_LEVEL):
            print(bcolors.GREEN + '[{}-INFO]: {}'.format(self.OWNER_NAME, message) + bcolors.ENDC)

    def debug(self, message):
        if (self.level >= self.DEBUG_LEVEL):
            print(bcolors.BLUE + '[{}-DEBUG]: {}'.format(self.OWNER_NAME, message) + bcolors.ENDC)
