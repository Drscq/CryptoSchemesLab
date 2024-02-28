// ElGamal.h
#ifndef ELGAMALMT_H
#define ELGAMALMT_H

#include <vector>

class ElGamal {
public:
    struct PublicKey {
        long long p, g, h;
    };

    struct PrivateKey {
        long long x;
    };

    struct CiphertextChunk {
        long long c1, c2;
    };

    using Ciphertext = std::vector<CiphertextChunk>;

    ElGamal(long long p, long long g, long long x);

    PublicKey getPublicKey() const;

    Ciphertext encrypt(const std::vector<unsigned char>& message, long long k) const;

    std::vector<unsigned char> decrypt(const Ciphertext& ct) const;

    Ciphertext randomizeCiphertext(const Ciphertext& ct, long long k) const;

private:
    static long long modPow(long long base, long long exponent, long long mod);

    static long long modInverse(long long a, long long mod);

    PublicKey publicKey;
    PrivateKey privateKey;
};

#endif // ELGAMAL_H
