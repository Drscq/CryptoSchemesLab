# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build

# Include any dependencies generated for this target.
include CMakeFiles/ElGamal.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/ElGamal.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/ElGamal.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ElGamal.dir/flags.make

CMakeFiles/ElGamal.dir/main.cpp.o: CMakeFiles/ElGamal.dir/flags.make
CMakeFiles/ElGamal.dir/main.cpp.o: ../main.cpp
CMakeFiles/ElGamal.dir/main.cpp.o: CMakeFiles/ElGamal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/ElGamal.dir/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/ElGamal.dir/main.cpp.o -MF CMakeFiles/ElGamal.dir/main.cpp.o.d -o CMakeFiles/ElGamal.dir/main.cpp.o -c /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/main.cpp

CMakeFiles/ElGamal.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ElGamal.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/main.cpp > CMakeFiles/ElGamal.dir/main.cpp.i

CMakeFiles/ElGamal.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ElGamal.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/main.cpp -o CMakeFiles/ElGamal.dir/main.cpp.s

CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o: CMakeFiles/ElGamal.dir/flags.make
CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o: ../ElGamalMT.cpp
CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o: CMakeFiles/ElGamal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o -MF CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o.d -o CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o -c /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/ElGamalMT.cpp

CMakeFiles/ElGamal.dir/ElGamalMT.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ElGamal.dir/ElGamalMT.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/ElGamalMT.cpp > CMakeFiles/ElGamal.dir/ElGamalMT.cpp.i

CMakeFiles/ElGamal.dir/ElGamalMT.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ElGamal.dir/ElGamalMT.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/ElGamalMT.cpp -o CMakeFiles/ElGamal.dir/ElGamalMT.cpp.s

# Object files for target ElGamal
ElGamal_OBJECTS = \
"CMakeFiles/ElGamal.dir/main.cpp.o" \
"CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o"

# External object files for target ElGamal
ElGamal_EXTERNAL_OBJECTS =

ElGamal: CMakeFiles/ElGamal.dir/main.cpp.o
ElGamal: CMakeFiles/ElGamal.dir/ElGamalMT.cpp.o
ElGamal: CMakeFiles/ElGamal.dir/build.make
ElGamal: CMakeFiles/ElGamal.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable ElGamal"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ElGamal.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ElGamal.dir/build: ElGamal
.PHONY : CMakeFiles/ElGamal.dir/build

CMakeFiles/ElGamal.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ElGamal.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ElGamal.dir/clean

CMakeFiles/ElGamal.dir/depend:
	cd /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build/CMakeFiles/ElGamal.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ElGamal.dir/depend

