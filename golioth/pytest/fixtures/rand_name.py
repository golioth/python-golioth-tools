import random
import string

NAME_PREFIX = 'pytest-'

def get_random_name():
    return NAME_PREFIX + ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(16))
