# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
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
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/li/mPSI

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/li/mPSI

# Include any dependencies generated for this target.
include libOPRF/CMakeFiles/libOPRF.dir/depend.make

# Include the progress variables for this target.
include libOPRF/CMakeFiles/libOPRF.dir/progress.make

# Include the compile flags for this target's objects.
include libOPRF/CMakeFiles/libOPRF.dir/flags.make

libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o: libOPRF/CMakeFiles/libOPRF.dir/flags.make
libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o: libOPRF/Hashing/BitPosition.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o -c /home/li/mPSI/libOPRF/Hashing/BitPosition.cpp

libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.i"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libOPRF/Hashing/BitPosition.cpp > CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.i

libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.s"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libOPRF/Hashing/BitPosition.cpp -o CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.s

libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o.requires:

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o.requires

libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o.provides: libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o.requires
	$(MAKE) -f libOPRF/CMakeFiles/libOPRF.dir/build.make libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o.provides.build
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o.provides

libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o.provides.build: libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o


libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o: libOPRF/CMakeFiles/libOPRF.dir/flags.make
libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o: libOPRF/Hashing/CuckooHasher1.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o -c /home/li/mPSI/libOPRF/Hashing/CuckooHasher1.cpp

libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.i"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libOPRF/Hashing/CuckooHasher1.cpp > CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.i

libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.s"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libOPRF/Hashing/CuckooHasher1.cpp -o CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.s

libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o.requires:

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o.requires

libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o.provides: libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o.requires
	$(MAKE) -f libOPRF/CMakeFiles/libOPRF.dir/build.make libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o.provides.build
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o.provides

libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o.provides.build: libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o


libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o: libOPRF/CMakeFiles/libOPRF.dir/flags.make
libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o: libOPRF/Hashing/SimpleHasher1.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o -c /home/li/mPSI/libOPRF/Hashing/SimpleHasher1.cpp

libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.i"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libOPRF/Hashing/SimpleHasher1.cpp > CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.i

libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.s"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libOPRF/Hashing/SimpleHasher1.cpp -o CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.s

libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o.requires:

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o.requires

libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o.provides: libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o.requires
	$(MAKE) -f libOPRF/CMakeFiles/libOPRF.dir/build.make libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o.provides.build
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o.provides

libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o.provides.build: libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o


libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o: libOPRF/CMakeFiles/libOPRF.dir/flags.make
libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o: libOPRF/Hashing/polyFFT.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o -c /home/li/mPSI/libOPRF/Hashing/polyFFT.cpp

libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.i"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libOPRF/Hashing/polyFFT.cpp > CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.i

libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.s"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libOPRF/Hashing/polyFFT.cpp -o CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.s

libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o.requires:

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o.requires

libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o.provides: libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o.requires
	$(MAKE) -f libOPRF/CMakeFiles/libOPRF.dir/build.make libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o.provides.build
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o.provides

libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o.provides.build: libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o


libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o: libOPRF/CMakeFiles/libOPRF.dir/flags.make
libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o: libOPRF/OPPRF/OPPRFReceiver.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o -c /home/li/mPSI/libOPRF/OPPRF/OPPRFReceiver.cpp

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.i"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libOPRF/OPPRF/OPPRFReceiver.cpp > CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.i

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.s"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libOPRF/OPPRF/OPPRFReceiver.cpp -o CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.s

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o.requires:

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o.requires

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o.provides: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o.requires
	$(MAKE) -f libOPRF/CMakeFiles/libOPRF.dir/build.make libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o.provides.build
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o.provides

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o.provides.build: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o


libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o: libOPRF/CMakeFiles/libOPRF.dir/flags.make
libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o: libOPRF/OPPRF/OPPRFSender.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o -c /home/li/mPSI/libOPRF/OPPRF/OPPRFSender.cpp

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.i"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libOPRF/OPPRF/OPPRFSender.cpp > CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.i

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.s"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libOPRF/OPPRF/OPPRFSender.cpp -o CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.s

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o.requires:

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o.requires

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o.provides: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o.requires
	$(MAKE) -f libOPRF/CMakeFiles/libOPRF.dir/build.make libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o.provides.build
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o.provides

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o.provides.build: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o


libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o: libOPRF/CMakeFiles/libOPRF.dir/flags.make
libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o: libOPRF/OPPRF/binSet.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o -c /home/li/mPSI/libOPRF/OPPRF/binSet.cpp

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.i"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libOPRF/OPPRF/binSet.cpp > CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.i

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.s"
	cd /home/li/mPSI/libOPRF && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libOPRF/OPPRF/binSet.cpp -o CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.s

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o.requires:

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o.requires

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o.provides: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o.requires
	$(MAKE) -f libOPRF/CMakeFiles/libOPRF.dir/build.make libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o.provides.build
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o.provides

libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o.provides.build: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o


# Object files for target libOPRF
libOPRF_OBJECTS = \
"CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o" \
"CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o" \
"CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o" \
"CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o" \
"CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o" \
"CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o" \
"CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o"

# External object files for target libOPRF
libOPRF_EXTERNAL_OBJECTS =

lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o
lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o
lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o
lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o
lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o
lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o
lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o
lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/build.make
lib/liblibOPRF.a: libOPRF/CMakeFiles/libOPRF.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Linking CXX static library ../lib/liblibOPRF.a"
	cd /home/li/mPSI/libOPRF && $(CMAKE_COMMAND) -P CMakeFiles/libOPRF.dir/cmake_clean_target.cmake
	cd /home/li/mPSI/libOPRF && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/libOPRF.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libOPRF/CMakeFiles/libOPRF.dir/build: lib/liblibOPRF.a

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/build

libOPRF/CMakeFiles/libOPRF.dir/requires: libOPRF/CMakeFiles/libOPRF.dir/Hashing/BitPosition.cpp.o.requires
libOPRF/CMakeFiles/libOPRF.dir/requires: libOPRF/CMakeFiles/libOPRF.dir/Hashing/CuckooHasher1.cpp.o.requires
libOPRF/CMakeFiles/libOPRF.dir/requires: libOPRF/CMakeFiles/libOPRF.dir/Hashing/SimpleHasher1.cpp.o.requires
libOPRF/CMakeFiles/libOPRF.dir/requires: libOPRF/CMakeFiles/libOPRF.dir/Hashing/polyFFT.cpp.o.requires
libOPRF/CMakeFiles/libOPRF.dir/requires: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFReceiver.cpp.o.requires
libOPRF/CMakeFiles/libOPRF.dir/requires: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/OPPRFSender.cpp.o.requires
libOPRF/CMakeFiles/libOPRF.dir/requires: libOPRF/CMakeFiles/libOPRF.dir/OPPRF/binSet.cpp.o.requires

.PHONY : libOPRF/CMakeFiles/libOPRF.dir/requires

libOPRF/CMakeFiles/libOPRF.dir/clean:
	cd /home/li/mPSI/libOPRF && $(CMAKE_COMMAND) -P CMakeFiles/libOPRF.dir/cmake_clean.cmake
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/clean

libOPRF/CMakeFiles/libOPRF.dir/depend:
	cd /home/li/mPSI && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/li/mPSI /home/li/mPSI/libOPRF /home/li/mPSI /home/li/mPSI/libOPRF /home/li/mPSI/libOPRF/CMakeFiles/libOPRF.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libOPRF/CMakeFiles/libOPRF.dir/depend

