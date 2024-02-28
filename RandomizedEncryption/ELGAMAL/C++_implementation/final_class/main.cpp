#include "ElGamal.h"
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <chrono>

// Function to generate a random message of a given size
std::vector<unsigned char> generateRandomMessage(size_t size) {
    std::vector<unsigned char> message(size);
    for (size_t i = 0; i < size; ++i) {
        message[i] = static_cast<unsigned char>(rand() % 256);
    }
    return message;
}

// Function to test the ElGamal encryption, decryption, and randomization with timing
void testElGamalWithMessageSize(ElGamal& elGamal, size_t messageSize) {
    std::cout << "Testing with message size: " << messageSize << " bytes." << std::endl;

    // Generate a random message of the specified size
    auto message = generateRandomMessage(messageSize);

    // Measure encryption time
    auto start = std::chrono::high_resolution_clock::now();
    long long k = rand(); // Use a new random value for each encryption
    auto encryptedMessage = elGamal.encrypt(message, k);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> encryptionTime = end - start;
    std::cout << "Encryption time: " << encryptionTime.count() << " ms." << std::endl;

    // Measure randomization time
    start = std::chrono::high_resolution_clock::now();
    long long k_random = rand(); // Use a new random value for randomization
    auto randomizedCiphertext = elGamal.randomizeCiphertext(encryptedMessage, k_random);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> randomizationTime = end - start;
    std::cout << "Randomization time: " << randomizationTime.count() << " ms." << std::endl;

    // Measure decryption time
    start = std::chrono::high_resolution_clock::now();
    auto decryptedMessage = elGamal.decrypt(randomizedCiphertext);
    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> decryptionTime = end - start;
    std::cout << "Decryption time: " << decryptionTime.count() << " ms." << std::endl;

    // Verify the decrypted message matches the original
    bool success = (message == decryptedMessage);
    std::cout << (success ? "Success" : "Failure") << ": The decrypted message "
              << (success ? "matches" : "does not match") << " the original." << std::endl;
}

int main() {
    srand(static_cast<unsigned>(time(nullptr))); // Seed the random number generator

    // Example parameters (use secure, large primes and random x for real applications)
    long long p = 686477; // A large prime number (for demo purposes)
    long long g = 2;
    long long x = 34029; // Private key, should be randomly chosen

    // Initialize ElGamal with the given parameters
    ElGamal elGamal(p, g, x);

    // Test message sizes from 1KB to 1MB
    for (size_t size = 1024; size <= 1024 * 1024; size *= 2) {
        testElGamalWithMessageSize(elGamal, size);
    }

    return 0;
}