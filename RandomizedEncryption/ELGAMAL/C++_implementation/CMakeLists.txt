cmake_minimum_required(VERSION 3.10) # Specify the minimum version for CMake

project(ElGamalEncryptionProject) # Define the project name

# Set the C++ standard to use
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable
add_executable(ElGamalEncryption main.cpp ElGamalEncryption.cpp)

# Find and link GMP and GMPXX libraries
find_package(GMP REQUIRED)
find_library(GMPXX_LIBRARIES NAMES gmpxx)
find_library(GMP_LIBRARIES NAMES gmp)

target_include_directories(ElGamalEncryption PRIVATE ${GMP_INCLUDE_DIR})
target_link_libraries(ElGamalEncryption ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
