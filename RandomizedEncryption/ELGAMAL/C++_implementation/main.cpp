#include "ElGamalEncryption.h"
#include <iostream>
#include <gmpxx.h>

int main() {
    // Initialize the encryption system
    ElGamalEncryption elGamal(512); // Use a 512-bit prime by default

    // Generate keys
    mpz_class privateKey, publicKey;
    elGamal.generateKeys(privateKey, publicKey);
    std::cout << "Private Key: " << privateKey << std::endl;
    std::cout << "Public Key: " << publicKey << std::endl;

    // Encrypt a message
    mpz_class message(12345678); // Example message
    std::cout << "Original Message: " << message << std::endl;
    mpz_class c1, c2;
    elGamal.encrypt(publicKey, message, c1, c2);
    std::cout << "Encrypted Message: " << c1 << ", " << c2 << std::endl;

    // Randomize the encrypted message
    mpz_class randomizedC1, randomizedC2;
    elGamal.randomizeCiphertext(publicKey, c1, c2, randomizedC1, randomizedC2);
    std::cout << "Randomized Encrypted Message: " << randomizedC1 << ", " << randomizedC2 << std::endl;

    // Decrypt the randomized message
    mpz_class decryptedRandomizedMessage = elGamal.decrypt(privateKey, randomizedC1, randomizedC2);
    std::cout << "Decrypted Randomized Message: " << decryptedRandomizedMessage << std::endl;

    return 0;
}
