#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cmath>

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

    Ciphertext encrypt(const std::vector<unsigned char>& message, long long k) const {
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

    std::vector<unsigned char> decrypt(const Ciphertext& ct) const {
        std::vector<unsigned char> decryptedMessage;
        for (const auto& chunk : ct) {
            long long s = modPow(chunk.c1, privateKey.x, publicKey.p);
            long long m = (chunk.c2 * modInverse(s, publicKey.p)) % publicKey.p;
            decryptedMessage.push_back(static_cast<unsigned char>(m));
        }
        return decryptedMessage;
    }

    Ciphertext randomizeCiphertext(const Ciphertext& ct, long long k) const {
        Ciphertext newCt;
        for (const auto& chunk : ct) {
            CiphertextChunk newChunk;
            newChunk.c1 = (chunk.c1 * modPow(publicKey.g, k, publicKey.p)) % publicKey.p;
            newChunk.c2 = (chunk.c2 * modPow(publicKey.h, k, publicKey.p)) % publicKey.p;
            newCt.push_back(newChunk);
        }
        return newCt;
    }

private:
    static long long modPow(long long base, long long exponent, long long mod) {
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

    static long long modInverse(long long a, long long mod) {
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
};

// Note: The main function would remain largely the same, with adjustments
// to handle binary data conversion to and from std::vector<unsigned char> for messages.


int main() {
    // Demonstration with a simple binary message
    std::vector<unsigned char> message = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    ElGamal elGamal(123, 5, 6); // Example usage with small prime for demonstration
    auto ct = elGamal.encrypt(message, 1234);
    std::cout << "Encrypted message: ";
    for (const auto& chunk : ct) {
        std::cout << "(" << chunk.c1 << ", " << chunk.c2 << ") ";
    }
    std::cout << "\n";
    auto randomCt = elGamal.randomizeCiphertext(ct, 5678);
    std::cout << "\nRandomized ciphertext: ";
    for (const auto& chunk : randomCt) {
        std::cout << "(" << chunk.c1 << ", " << chunk.c2 << ") ";
    }
    std::cout << "\n";
    auto decryptedMessage = elGamal.decrypt(randomCt);

    std::cout << "Decrypted message: ";
    for (char c : decryptedMessage) {
        std::cout << c;
    }
    std::cout << "\n";

    return 0;
}
