# CryptoSchemesLab
CryptoSchemesLab: Dive into the world of encryption with a focus on randomizable schemes. A collaborative platform for cryptographers to explore, implement, and refine secure algorithms. Join us to contribute and learn about innovative cryptographic methods.

Sure, below is how you can document the usage of CMake with the appropriate preprocessor macro in your `README.md` file:


# ElGamal Encryption System

This project implements the ElGamal encryption system in C++, allowing users to encrypt and decrypt messages using the ElGamal algorithm. Additionally, it supports multiple versions of the ElGamal class, including a multi-threaded implementation for improved performance.

## Building with CMake

To build the project, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/your_username/ElGamal.git
   ```

2. Navigate to the project directory:
   ```bash
   cd ElGamal
   ```

3. Create a build directory:
   ```bash
   mkdir build
   cd build
   ```

4. Run CMake to generate build files. Use the `-DELGAMAL_MT=ON` flag to enable the multi-threaded version of ElGamal, or omit the flag to use the regular version:
   ```bash
   cmake -DELGAMAL_MT=ON ..
   ```

5. Build the project using make:
   ```bash
   make
   ```

6. The executable will be generated in the build directory. Run the executable to use the ElGamal encryption system:
   ```bash
   ./ElGamal
   ```

## Usage

Once the project is built, you can use the ElGamal encryption system as follows:

- Specify the parameters in your `main.cpp` file, such as the prime number, generator, and private key.
- Include either `ElGamal.h` or `ElGamalMT.h` in your `main.cpp` file, depending on whether you want to use the regular or multi-threaded version of ElGamal.
- Compile your code using CMake, ensuring to specify the appropriate preprocessor macro (`-DELGAMAL_MT=ON` for multi-threaded version, or omit for regular version).
- Run the executable to encrypt and decrypt messages using ElGamal encryption.

