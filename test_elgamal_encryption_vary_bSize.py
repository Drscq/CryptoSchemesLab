import unittest
from elgamal_encryption import ElGamalEncryption
from tqdm import tqdm
import time

class TestElGamalEncryption(unittest.TestCase):

    def setUp(self):
        """Setup an ElGamalEncryption instance with a 512-bit prime for testing."""
        self.elgamal = ElGamalEncryption(512)

    # Existing tests unchanged...

    def test_binary_input_size_effect(self):
        """Test the effect of binary input size on running time."""
        private_key, public_key = self.elgamal.generate_keys()
        sizes = [1024 * 2 ** i for i in range(11)]  # 1KB to 1MB, doubling each step
        times = []

        for size in tqdm(sizes, desc="Testing sizes from 1KB to 1MB"):
            binary_message = b'a' * size  # Generate dummy binary data of the specified size
            start_time = time.time()
            encrypted_chunks = self.elgamal.encrypt_binary(public_key, binary_message)
            decrypted_binary = self.elgamal.decrypt_binary(private_key, encrypted_chunks)
            end_time = time.time()
            self.assertEqual(binary_message, decrypted_binary)
            times.append(end_time - start_time)

        # Optionally, print or log the times for each size to observe the pattern
        for size, elapsed in zip(sizes, times):
            print(f"Size: {size / 1024} KB, Time: {elapsed} seconds")

if __name__ == '__main__':
    unittest.main()
