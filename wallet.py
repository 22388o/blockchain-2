from Crypto.PublicKey import RSA            # For generating a key pair.
from Crypto.Signature import PKCS1_v1_5     # Generate a random string of characters for a signature
from Crypto.Hash import SHA256              # Our SHA256 hashing function.
import Crypto.Random                        # Our random number generator.
import binascii                             # TODO: Figure out what this does.


class Wallet:
    """ Creates, loads and holds private and public keys. Manages transaction
    signing and verification. """

    def __init__(self, node_id):
        self.private_key = None     # To not auto generate on wallet creation
        self.public_key = None
        self.node_id = node_id

    def create_keys(self):
        """ Create a new pair of private and public keys. """
        private_key, public_key = self.generate_keys()
        self.private_key = private_key
        self.public_key = public_key

    def save_keys(self):
        """ Saves the keys to a file (wallet.txt). """
        # Check to make sure public_key and private_key are defined before saving.
        if self.public_key is not None and self.private_key is not None:
            try:
                # Use .format to inject our node_id into the name of the text file.
                with open('wallet-{}.txt'.format(self.node_id), mode='w') as f:
                    f.write(self.public_key)        # Write our public_key variable.
                    f.write('\n')
                    f.write(self.private_key)       # Need to engineer a more secure way of storing this!
                return True
            except (IOError, IndexError):
                print('Saving wallet failed...')
                return False

    def load_keys(self):
        """ Loads the keys from the wallet.txt file into memory. """
        try:
            # Use .format to inject our node_id into the name of the text file.
            with open('wallet-{}.txt'.format(self.node_id), mode='r') as f:
                keys = f.readlines()                # Read lines from text file.
                public_key = keys[0][:-1]           # Use [:-1] to strip out newline (\n) characters.
                private_key = keys[1]               # Need to engineer a more secure way of storing this!
                self.public_key = public_key        # Set our public_key variable.
                self.private_key = private_key      # Set our private_key variable.
            return True
        except (IOError, IndexError):
            print('Loading wallet failed...')
            return False

    def generate_keys(self):
        """ Generate a new pair of private and public key. """

        # We are specifying 1024 bits for generating our RSA key.
        private_key = RSA.generate(1024, Crypto.Random.new().read)
        public_key = private_key.publickey()        # publickey() is a unique method of private_key.
        # TODO: Unpack all this and write out the steps.
        return (
            binascii                                        # lookup what this does
            .hexlify(private_key.exportKey(format='DER'))   # returns a hexadecimal version of binary data
            .decode('ascii'),                               # converts back to ascii
            binascii
            .hexlify(public_key.exportKey(format='DER'))
            .decode('ascii')
        )

    def sign_transaction(self, sender, recipient, amount):
        """ Sign a transaction and return the signature.

            Arguments:
                :sender: The sender of the transaction.
                :recipient: The recipient of the transaction.
                :amount: The amount of the transaction.
        """
        # TODO: Need to unpack this. We are doing something with RSA and our private key.
        signer = PKCS1_v1_5.new(RSA.importKey(
            binascii.unhexlify(self.private_key)))
        # Create a hash of our transaction using the sender, recipient, and amount data.
        h = SHA256.new((str(sender) + str(recipient) +
                        str(amount)).encode('utf8'))
        signature = signer.sign(h)                          # Signature = singer key + hash of transaction.
        return binascii.hexlify(signature).decode('ascii')  # Hexlify the signature, then convert to ascii.

    # NOTE ABOUT defining depth of access with @classmethod and @staticmethod
    @staticmethod
    def verify_transaction(transaction):
        """ Verify the signature of a transaction.

            Arguments:
                :transaction: The transaction that should be verified.
        """
        public_key = RSA.importKey(binascii.unhexlify(transaction.sender))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA256.new((str(transaction.sender) + str(transaction.recipient) +
                        str(transaction.amount)).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(transaction.signature))
