#include "ElGamal.h"
#include <iostream>
#include <string>

int main() {
    // Example parameters (For real applications, use secure, large primes and random x)
    long long p = 686477; // A large prime number (for demo purposes)
    long long g = 2;
    long long x = 34029; // Private key, should be randomly chosen

    // Initialize ElGamal with the given parameters
    ElGamal elGamal(p, g, x);

    // Example message
    std::string originalMessage = "Hello, ElGamal!";
    std::vector<unsigned char> message(originalMessage.begin(), originalMessage.end());

    // Encrypt the message
    long long k = 123456789; // Randomly chosen for each encryption, for demo using a fixed value
    auto encryptedMessage = elGamal.encrypt(message, k);

    // Decrypt the message
    auto decryptedMessage = elGamal.decrypt(encryptedMessage);

    // Convert decrypted message back to string
    std::string decryptedString(decryptedMessage.begin(), decryptedMessage.end());

    // Display results
    std::cout << "Original Message: " << originalMessage << std::endl;
    std::cout << "Decrypted Message: " << decryptedString << std::endl;

    // Check if decryption was successful
    if (originalMessage == decryptedString) {
        std::cout << "Success: The decrypted message matches the original." << std::endl;
    } else {
        std::cout << "Error: The decrypted message does not match the original." << std::endl;
    }

    return 0;
}
