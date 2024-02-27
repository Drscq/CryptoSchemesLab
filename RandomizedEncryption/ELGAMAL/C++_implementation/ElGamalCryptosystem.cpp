#include <iostream>
#include <cstdlib>
#include <ctime>
#include <cmath>

class ElGamal {
public:
    struct PublicKey {
        long long p, g, h; // p: prime number, g: primitive root modulo p, h = g^x mod p
    };

    struct PrivateKey {
        long long x; // x: secret key
    };

    struct Ciphertext {
        long long c1, c2; // c1 = g^k mod p, c2 = m*h^k mod p
    };

private:
    PublicKey publicKey;
    PrivateKey privateKey;

public:
    ElGamal(long long p, long long g, long long x) {
        publicKey.p = p;
        publicKey.g = g;
        privateKey.x = x;
        publicKey.h = modPow(publicKey.g, privateKey.x, publicKey.p);
    }

    PublicKey getPublicKey() const {
        return publicKey;
    }

    Ciphertext encrypt(long long m, long long k) const {
        Ciphertext ct;
        ct.c1 = modPow(publicKey.g, k, publicKey.p);
        ct.c2 = (m * modPow(publicKey.h, k, publicKey.p)) % publicKey.p;
        return ct;
    }

    long long decrypt(const Ciphertext& ct) const {
        long long s = modPow(ct.c1, privateKey.x, publicKey.p);
        long long m = (ct.c2 * modInverse(s, publicKey.p)) % publicKey.p;
        return m;
    }

    Ciphertext randomizeCiphertext(const Ciphertext& ct, long long k) const {
        Ciphertext newCt;
        newCt.c1 = (ct.c1 * modPow(publicKey.g, k, publicKey.p)) % publicKey.p;
        newCt.c2 = (ct.c2 * modPow(publicKey.h, k, publicKey.p)) % publicKey.p;
        return newCt;
    }

private:
    static long long modPow(long long base, long long exponent, long long mod) {
        long long result = 1;
        base = base % mod;
        while (exponent > 0) {
            if (exponent % 2 == 1)
                result = (result * base) % mod;
            exponent = exponent >> 1;
            base = (base * base) % mod;
        }
        return result;
    }

    static long long modInverse(long long a, long long m) {
        long long m0 = m, t, q;
        long long x0 = 0, x1 = 1;
        if (m == 1)
          return 0;
        while (a > 1) {
            q = a / m;
            t = m;
            m = a % m, a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0)
           x1 += m0;
        return x1;
    }
};

int main() {
    // Example usage:
    // p = 23 (prime), g = 5 (primitive root), x = 6 (private key)
    ElGamal elGamal(23, 5, 6);
    ElGamal::PublicKey pubKey = elGamal.getPublicKey();
    std::cout << "Public Key: (p=" << pubKey.p << ", g=" << pubKey.g << ", h=" << pubKey.h << ")\n";

    // Encrypting message m = 10 with random k = 15
    auto ct = elGamal.encrypt(10, 15);
    std::cout << "Ciphertext: (c1=" << ct.c1 << ", c2=" << ct.c2 << ")\n";

    // Decrypting the message
    auto decryptedMessage = elGamal.decrypt(ct);
    std::cout << "Decrypted message: " << decryptedMessage << "\n";

    // Randomizing the ciphertext
    auto newCt = elGamal.randomizeCiphertext(ct, 3); // Random k = 3 for randomization
    std::cout << "Randomized Ciphertext: (c1=" << newCt.c1 << ", c2=" << newCt.c2 << ")\n";

    // Decrypting the randomized ciphertext
    auto decryptedRandomizedMessage = elGamal.decrypt(newCt);
    std::cout << "Decrypted randomized message: " << decryptedRandomizedMessage << "\n";

    return 0;
}
