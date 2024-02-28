// ElGamalMT.cpp
#include "ElGamalMT.h"
#include <cmath>
#include <future>
#include <vector>
#include <thread>
ElGamal::ElGamal(long long p, long long g, long long x) {
    publicKey.p = p;
    publicKey.g = g;
    privateKey.x = x;
    publicKey.h = modPow(publicKey.g, privateKey.x, publicKey.p);
}

ElGamal::PublicKey ElGamal::getPublicKey() const {
    return publicKey;
}

// Example modification for the encrypt method
ElGamal::Ciphertext ElGamal::encrypt(const std::vector<unsigned char>& message, long long k) const {
    Ciphertext ct;
    ct.resize(message.size()); // Preallocate space for all chunks

    const size_t numThreads = std::thread::hardware_concurrency(); // Or set a fixed limit
    const size_t batchSize = (message.size() + numThreads - 1) / numThreads;

    std::vector<std::future<void>> futures;

    for (size_t t = 0; t < numThreads; ++t) {
        futures.push_back(std::async(std::launch::async, [this, &ct, t, k, &message, batchSize]() {
            const size_t startIdx = t * batchSize;
            const size_t endIdx = std::min(startIdx + batchSize, message.size());
            for (size_t i = startIdx; i < endIdx; ++i) {
                long long m_long = static_cast<long long>(message[i]);
                ct[i].c1 = modPow(publicKey.g, k, publicKey.p);
                ct[i].c2 = (m_long * modPow(publicKey.h, k, publicKey.p)) % publicKey.p;
            }
        }));
    }

    for (auto& future : futures) {
        future.get(); // Ensure all futures have completed
    }

    return ct;
}



std::vector<unsigned char> ElGamal::decrypt(const Ciphertext& ct) const {
    std::vector<unsigned char> decryptedMessage(ct.size());
    const size_t numThreads = std::thread::hardware_concurrency();
    const size_t batchSize = (ct.size() + numThreads - 1) / numThreads;

    std::vector<std::future<void>> futures;

    for (size_t t = 0; t < numThreads; ++t) {
        futures.push_back(std::async(std::launch::async, [this, &decryptedMessage, &ct, t, batchSize]() {
            const size_t startIdx = t * batchSize;
            const size_t endIdx = std::min(startIdx + batchSize, ct.size());
            for (size_t i = startIdx; i < endIdx; ++i) {
                long long s = modPow(ct[i].c1, privateKey.x, publicKey.p);
                long long m = (ct[i].c2 * modInverse(s, publicKey.p)) % publicKey.p;
                decryptedMessage[i] = static_cast<unsigned char>(m);
            }
        }));
    }

    for (auto& future : futures) {
        future.get(); // Ensure all futures have completed
    }

    return decryptedMessage;
}


ElGamal::Ciphertext ElGamal::randomizeCiphertext(const Ciphertext& ct, long long k) const {
    Ciphertext newCt(ct.size());
    const size_t numThreads = std::thread::hardware_concurrency();
    const size_t batchSize = (ct.size() + numThreads - 1) / numThreads;

    std::vector<std::future<void>> futures;

    for (size_t t = 0; t < numThreads; ++t) {
        futures.push_back(std::async(std::launch::async, [this, &newCt, &ct, t, k, batchSize]() {
            const size_t startIdx = t * batchSize;
            const size_t endIdx = std::min(startIdx + batchSize, ct.size());
            for (size_t i = startIdx; i < endIdx; ++i) {
                newCt[i].c1 = (ct[i].c1 * modPow(publicKey.g, k, publicKey.p)) % publicKey.p;
                newCt[i].c2 = (ct[i].c2 * modPow(publicKey.h, k, publicKey.p)) % publicKey.p;
            }
        }));
    }

    for (auto& future : futures) {
        future.get(); // Ensure all futures have completed
    }

    return newCt;
}



long long ElGamal::modPow(long long base, long long exponent, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % mod;
        exponent >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

long long ElGamal::modInverse(long long a, long long mod) {
    long long mod0 = mod, t, q;
    long long x0 = 0, x1 = 1;
    if (mod == 1)
      return 0;
    while (a > 1) {
        q = a / mod;
        t = mod;
        mod = a % mod, a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0)
       x1 += mod0;
    return x1;
}
