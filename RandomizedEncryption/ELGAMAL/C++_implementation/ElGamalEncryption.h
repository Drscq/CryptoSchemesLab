#ifndef ELGAMALENCRYPTION_H
#define ELGAMALENCRYPTION_H

#include <gmpxx.h>

class ElGamalEncryption {
private:
    mpz_class p, g;
    static mpz_class generateRandomBigInt(const mpz_class& min, const mpz_class& max);
    static mpz_class generatePrime(const int bit_length);
    static mpz_class modInverse(const mpz_class& a, const mpz_class& m);

public:
    ElGamalEncryption(int bit_length = 512);
    void generateKeys(mpz_class& privateKey, mpz_class& publicKey);
    void encrypt(const mpz_class& publicKey, const mpz_class& message, mpz_class& c1, mpz_class& c2);
    void randomizeCiphertext(const mpz_class& publicKey, const mpz_class& c1, const mpz_class& c2, mpz_class& newC1, mpz_class& newC2);
    mpz_class decrypt(const mpz_class& privateKey, const mpz_class& c1, const mpz_class& c2);
};

#endif // ELGAMALENCRYPTION_H
