import hashlib as hl
import json

# __all__ = ['hash_string_256', 'hash_block']


def hash_string_256(string):
    """ Create a SHA256 hash for a given input string.

        Arguments:
            :string: The string which should be hashed.
    """
    return hl.sha256(string).hexdigest()


def hash_block(block):
    """ Hashes a block and returns a string representation of it.

        Process:
            1.  Copy our block object into a variable (formatted with __dict__).
            2.  Convert the data into JSON (with dict keys sorted for a consistent hash) with proper encoding.
            3.  Hash the converted data using SHA256 and return the result.

        Arguments:
            :block: The block that should be hashed.

        Notes:
            *   JSON can't convert entire objects, so we import our block through the __dict__ method.
            *   Each hash function should create its own unique .copy() of the block, or else they'll all reference the
                same shared variable and produce an incorrect hash. """
    hashable_block = block.__dict__.copy()
    hashable_block['transactions'] = [
        tx.to_ordered_dict() for tx in hashable_block['transactions']
    ]
    return hash_string_256(json.dumps(hashable_block, sort_keys=True).encode())
