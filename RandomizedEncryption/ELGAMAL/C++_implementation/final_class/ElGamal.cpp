// ElGamal.cpp
#include <cmath>
#include "ElGamal.h"
ElGamal::ElGamal(long long p, long long g, long long x) {
    publicKey.p = p;
    publicKey.g = g;
    privateKey.x = x;
    publicKey.h = modPow(publicKey.g, privateKey.x, publicKey.p);
}

ElGamal::PublicKey ElGamal::getPublicKey() const {
    return publicKey;
}

ElGamal::Ciphertext ElGamal::encrypt(const std::vector<unsigned char>& message, long long k) const {
    Ciphertext ct;
    for (auto m : message) {
        long long m_long = static_cast<long long>(m);
        CiphertextChunk chunk;
        chunk.c1 = modPow(publicKey.g, k, publicKey.p);
        chunk.c2 = (m_long * modPow(publicKey.h, k, publicKey.p)) % publicKey.p;
        ct.push_back(chunk);
    }
    return ct;
}

std::vector<unsigned char> ElGamal::decrypt(const Ciphertext& ct) const {
    std::vector<unsigned char> decryptedMessage;
    for (const auto& chunk : ct) {
        long long s = modPow(chunk.c1, privateKey.x, publicKey.p);
        long long m = (chunk.c2 * modInverse(s, publicKey.p)) % publicKey.p;
        decryptedMessage.push_back(static_cast<unsigned char>(m));
    }
    return decryptedMessage;
}

ElGamal::Ciphertext ElGamal::randomizeCiphertext(const Ciphertext& ct, long long k) const {
    Ciphertext newCt;
    for (const auto& chunk : ct) {
        CiphertextChunk newChunk;
        newChunk.c1 = (chunk.c1 * modPow(publicKey.g, k, publicKey.p)) % publicKey.p;
        newChunk.c2 = (chunk.c2 * modPow(publicKey.h, k, publicKey.p)) % publicKey.p;
        newCt.push_back(newChunk);
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