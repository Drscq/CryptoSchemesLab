import concurrent.futures
import secrets
from sympy import isprime, primerange, mod_inverse

class ElGamalEncryption:
    def __init__(self, bit_length=512):
        self.p, self.g = self.generate_prime_and_generator(bit_length)

    @staticmethod
    def generate_prime_and_generator(bit_length):
        # Generate a safe prime for enhanced security
        p = 4
        while not (isprime(p) and isprime((p - 1) // 2)):
            p = secrets.randbits(bit_length) | (1 << bit_length) | 1
        g = 2  # Starting point for finding a suitable generator
        # Ensure g is a generator of a large subgroup
        while pow(g, 2, p) == 1 or pow(g, (p - 1) // 2, p) == 1:
            g += 1
        return p, g

    def generate_keys(self):
        private_key = secrets.randbelow(self.p - 2) + 2
        public_key = pow(self.g, private_key, self.p)
        return private_key, public_key

    def encrypt(self, public_key, message):
        r = secrets.randbelow(self.p - 2) + 2
        c1 = pow(self.g, r, self.p)
        c2 = (message * pow(public_key, r, self.p)) % self.p
        return c1, c2

    def randomize_ciphertext(self, public_key, ciphertext):
        c1, c2 = ciphertext
        s = secrets.randbelow(self.p - 2) + 2
        new_c1 = (c1 * pow(self.g, s, self.p)) % self.p
        new_c2 = (c2 * pow(public_key, s, self.p)) % self.p
        return new_c1, new_c2

    def decrypt(self, private_key, ciphertext):
        c1, c2 = ciphertext
        s = pow(c1, private_key, self.p)
        m = (c2 * mod_inverse(s, self.p)) % self.p
        return m

    @staticmethod
    def binary_to_int(binary_data):
        return int.from_bytes(binary_data, 'big')

    @staticmethod
    def int_to_binary(integer, length):
        return integer.to_bytes(length, 'big')

    def encrypt_binary(self, public_key, binary_data, chunk_size=64):
        # Split the binary data into chunks
        chunks = [binary_data[i:i+chunk_size] for i in range(0, len(binary_data), chunk_size)]
        
        # Function to encrypt a single chunk
        def encrypt_chunk(chunk):
            chunk_int = self.binary_to_int(chunk)
            return self.encrypt(public_key, chunk_int)

        # Use ThreadPoolExecutor to encrypt chunks in parallel
        with concurrent.futures.ThreadPoolExecutor() as executor:
            encrypted_chunks = list(executor.map(encrypt_chunk, chunks))
        
        return encrypted_chunks

    def decrypt_binary(self, private_key, encrypted_chunks):
        # Function to decrypt a single chunk
        def decrypt_chunk(chunk):
            decrypted_chunk_int = self.decrypt(private_key, chunk)
            decrypted_chunk_length = (self.p.bit_length() + 7) // 8
            return self.int_to_binary(decrypted_chunk_int, decrypted_chunk_length).lstrip(b'\x00')

        # Use ThreadPoolExecutor to decrypt chunks in parallel
        with concurrent.futures.ThreadPoolExecutor() as executor:
            decrypted_chunks = list(executor.map(decrypt_chunk, encrypted_chunks))
        
        # Combine the decrypted chunks back into binary data
        decrypted_data = b''.join(decrypted_chunks)
        
        return decrypted_data
