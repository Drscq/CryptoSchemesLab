cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(ElGamal VERSION 1.0)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find the Threads package
find_package(Threads REQUIRED)

# Add the executable
if(DEFINED ELGAMAL_MT)
    add_executable(ElGamal main.cpp ElGamalMT.cpp)  # Compile with ElGamalMT.cpp
else()
    add_executable(ElGamal main.cpp ElGamal.cpp)  # Compile with ElGamal.cpp
endif()

# Link the executable to the Threads library
target_link_libraries(ElGamal PRIVATE Threads::Threads)
