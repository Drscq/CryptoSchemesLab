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
include CMakeFiles/ElGamalDemo.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/ElGamalDemo.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/ElGamalDemo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ElGamalDemo.dir/flags.make

CMakeFiles/ElGamalDemo.dir/main.cpp.o: CMakeFiles/ElGamalDemo.dir/flags.make
CMakeFiles/ElGamalDemo.dir/main.cpp.o: ../main.cpp
CMakeFiles/ElGamalDemo.dir/main.cpp.o: CMakeFiles/ElGamalDemo.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/ElGamalDemo.dir/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/ElGamalDemo.dir/main.cpp.o -MF CMakeFiles/ElGamalDemo.dir/main.cpp.o.d -o CMakeFiles/ElGamalDemo.dir/main.cpp.o -c /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/main.cpp

CMakeFiles/ElGamalDemo.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ElGamalDemo.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/main.cpp > CMakeFiles/ElGamalDemo.dir/main.cpp.i

CMakeFiles/ElGamalDemo.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ElGamalDemo.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/main.cpp -o CMakeFiles/ElGamalDemo.dir/main.cpp.s

CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o: CMakeFiles/ElGamalDemo.dir/flags.make
CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o: ../ElGamal.cpp
CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o: CMakeFiles/ElGamalDemo.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o -MF CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o.d -o CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o -c /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/ElGamal.cpp

CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/ElGamal.cpp > CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.i

CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/ElGamal.cpp -o CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.s

# Object files for target ElGamalDemo
ElGamalDemo_OBJECTS = \
"CMakeFiles/ElGamalDemo.dir/main.cpp.o" \
"CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o"

# External object files for target ElGamalDemo
ElGamalDemo_EXTERNAL_OBJECTS =

ElGamalDemo: CMakeFiles/ElGamalDemo.dir/main.cpp.o
ElGamalDemo: CMakeFiles/ElGamalDemo.dir/ElGamal.cpp.o
ElGamalDemo: CMakeFiles/ElGamalDemo.dir/build.make
ElGamalDemo: CMakeFiles/ElGamalDemo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable ElGamalDemo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ElGamalDemo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ElGamalDemo.dir/build: ElGamalDemo
.PHONY : CMakeFiles/ElGamalDemo.dir/build

CMakeFiles/ElGamalDemo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ElGamalDemo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ElGamalDemo.dir/clean

CMakeFiles/ElGamalDemo.dir/depend:
	cd /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build /home/changqi/ORAM/CryptoSchemesLab/RandomizedEncryption/ELGAMAL/C++_implementation/final_class/build/CMakeFiles/ElGamalDemo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ElGamalDemo.dir/depend

