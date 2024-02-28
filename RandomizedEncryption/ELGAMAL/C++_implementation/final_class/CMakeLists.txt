cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(ElGamalDemo VERSION 1.0)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(ElGamalDemo main.cpp ElGamal.cpp)
