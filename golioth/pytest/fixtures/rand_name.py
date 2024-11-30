import random
import string

NAME_PREFIX = 'pytest'

def get_random_name(prefix: str | None = None):
    random_string = ''.join(random.choice(string.ascii_lowercase + string.digits)
                            for _ in range(16))

    return f'{prefix or NAME_PREFIX}-{random_string}'
