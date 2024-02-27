import unittest
from elgamal_encryption import ElGamalEncryption  # Adjust the import statement based on your actual file name

class TestElGamalEncryption(unittest.TestCase):

    def setUp(self):
        """Setup an ElGamalEncryption instance with a 512-bit prime for testing."""
        self.elgamal = ElGamalEncryption(512)

    def test_prime_and_generator(self):
        """Test if the generated prime and generator are valid."""
        p, g = self.elgamal.p, self.elgamal.g
        self.assertTrue(p > 0)
        self.assertTrue(g > 0)

    def test_key_generation(self):
        """Test if the generated keys are valid."""
        private_key, public_key = self.elgamal.generate_keys()
        self.assertTrue(0 < private_key < self.elgamal.p)
        self.assertTrue(0 < public_key < self.elgamal.p)

    def test_encryption_decryption(self):
        """Test encryption and decryption of a message."""
        private_key, public_key = self.elgamal.generate_keys()
        message = 12345  # Example message
        encrypted_message = self.elgamal.encrypt(public_key, message)
        decrypted_message = self.elgamal.decrypt(private_key, encrypted_message)
        self.assertEqual(message, decrypted_message)

    def test_binary_encryption_decryption(self):
        """Test binary data encryption and decryption."""
        private_key, public_key = self.elgamal.generate_keys()
        binary_message = b'Hello, World!'
        encrypted_chunks = self.elgamal.encrypt_binary(public_key, binary_message)
        decrypted_binary = self.elgamal.decrypt_binary(private_key, encrypted_chunks)
        self.assertEqual(binary_message, decrypted_binary)

    def test_ciphertext_randomization(self):
        """Test if ciphertext randomization maintains the ability to decrypt to the original message."""
        private_key, public_key = self.elgamal.generate_keys()
        message = 12345  # Example message
        encrypted_message = self.elgamal.encrypt(public_key, message)
        randomized_ciphertext = self.elgamal.randomize_ciphertext(public_key, encrypted_message)
        decrypted_message_after_randomization = self.elgamal.decrypt(private_key, randomized_ciphertext)
        self.assertEqual(message, decrypted_message_after_randomization)

    def test_binary_ciphertext_randomization(self):
        """Test binary ciphertext randomization and decryption."""
        private_key, public_key = self.elgamal.generate_keys()
        binary_message = b'Hello, ElGamal!'
        encrypted_chunks = self.elgamal.encrypt_binary(public_key, binary_message)
        randomized_chunks = self.elgamal.randomize_binary(public_key, encrypted_chunks)
        decrypted_binary_after_randomization = self.elgamal.decrypt_binary(private_key, randomized_chunks)
        self.assertEqual(binary_message, decrypted_binary_after_randomization)

if __name__ == '__main__':
    unittest.main()
