#include "ElGamalEncryption.h"
#include <gmp.h>
#include <gmpxx.h>
#include <cstdlib>
#include <ctime>

ElGamalEncryption::ElGamalEncryption(int bit_length) {
    p = generatePrime(bit_length);
    g = 2; // Simple choice; in real applications, choose wisely.
}

mpz_class ElGamalEncryption::generateRandomBigInt(const mpz_class& min, const mpz_class& max) {
    mpz_class result;
    gmp_randclass rr(gmp_randinit_default);
    rr.seed(time(NULL));
    mpz_class range = max - min + 1;
    mpz_class randomNumber;
    do {
        randomNumber = rr.get_z_range(range) + min;
    } while (randomNumber < min || randomNumber > max);
    return randomNumber;
}

mpz_class ElGamalEncryption::generatePrime(const int bit_length) {
    mpz_class prime;
    gmp_randclass r(gmp_randinit_default);
    r.seed(time(NULL));
    do {
        mpz_urandomb(prime.get_mpz_t(), r.get_gmp_randstate_t(), bit_length);
        mpz_setbit(prime.get_mpz_t(), bit_length - 1);
        mpz_setbit(prime.get_mpz_t(), 0);
    } while (!mpz_probab_prime_p(prime.get_mpz_t(), 25));
    return prime;
}

mpz_class ElGamalEncryption::modInverse(const mpz_class& a, const mpz_class& m) {
    mpz_class inv;
    mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
    return inv;
}

void ElGamalEncryption::generateKeys(mpz_class& privateKey, mpz_class& publicKey) {
    privateKey = generateRandomBigInt(2, p - 2);
    mpz_powm(publicKey.get_mpz_t(), g.get_mpz_t(), privateKey.get_mpz_t(), p.get_mpz_t());
}

void ElGamalEncryption::encrypt(const mpz_class& publicKey, const mpz_class& message, mpz_class& c1, mpz_class& c2) {
    mpz_class r = generateRandomBigInt(2, p - 2);
    mpz_powm(c1.get_mpz_t(), g.get_mpz_t(), r.get_mpz_t(), p.get_mpz_t());
    mpz_class gm;
    mpz_powm(gm.get_mpz_t(), publicKey.get_mpz_t(), r.get_mpz_t(), p.get_mpz_t());
    c2 = (message * gm) % p;
}

void ElGamalEncryption::randomizeCiphertext(const mpz_class& publicKey, const mpz_class& c1, const mpz_class& c2, mpz_class& newC1, mpz_class& newC2) {
    mpz_class s = generateRandomBigInt(2, p - 2);
    mpz_class gs;
    mpz_powm(gs.get_mpz_t(), g.get_mpz_t(), s.get_mpz_t(), p.get_mpz_t());
    newC1 = (c1 * gs) % p;
    mpz_class ps;
    mpz_powm(ps.get_mpz_t(), publicKey.get_mpz_t(), s.get_mpz_t(), p.get_mpz_t());
    newC2 = (c2 * ps) % p;
}

mpz_class ElGamalEncryption::decrypt(const mpz_class& privateKey, const mpz_class& c1, const mpz_class& c2) {
    mpz_class s;
    mpz_powm(s.get_mpz_t(), c1.get_mpz_t(), privateKey.get_mpz_t(), p.get_mpz_t());
    mpz_class m = (c2 * modInverse(s, p)) % p;
    return m;
}
