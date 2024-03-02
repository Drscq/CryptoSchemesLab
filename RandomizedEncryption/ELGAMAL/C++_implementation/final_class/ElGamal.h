// ElGamal.h
#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <vector>
#include <openssl/bn.h>
class ElGamal {
public:
    struct PublicKey {
        BIGNUM *p; // Prime number
        BIGNUM *g; // Generator
        BIGNUM *h; // Public key g^x mod p
    };

    struct PrivateKey {
        BIGNUM *x; // Private Key
    };

    struct CiphertextChunk {
        BIGNUM *c1; // g^k mod p
        BIGNUM *c2; // h^k * m mod p
    };

    using Ciphertext = std::vector<CiphertextChunk>;

    ElGamal();
    ~ElGamal();

    // Key generation
    void generateKeys(int bits);

    PublicKey getPublicKey() const;

    Ciphertext encrypt(const std::vector<unsigned char>& message, BIGNUM *k) const;

    std::vector<unsigned char> decrypt(const Ciphertext& ct) const;

    Ciphertext randomizeCiphertext(const Ciphertext& ct, BIGNUM *k) const;

private:
    static long long modPow(long long base, long long exponent, long long mod);

    static long long modInverse(long long a, long long mod);

    PublicKey publicKey;
    PrivateKey privateKey;
};

#endif // ELGAMAL_H
