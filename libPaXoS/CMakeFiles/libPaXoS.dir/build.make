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
include libPaXoS/CMakeFiles/libPaXoS.dir/depend.make

# Include the progress variables for this target.
include libPaXoS/CMakeFiles/libPaXoS.dir/progress.make

# Include the compile flags for this target's objects.
include libPaXoS/CMakeFiles/libPaXoS.dir/flags.make

libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o: libPaXoS/CMakeFiles/libPaXoS.dir/flags.make
libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o: libPaXoS/ObliviousDictionary.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o"
	cd /home/li/mPSI/libPaXoS && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o -c /home/li/mPSI/libPaXoS/ObliviousDictionary.cpp

libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.i"
	cd /home/li/mPSI/libPaXoS && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libPaXoS/ObliviousDictionary.cpp > CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.i

libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.s"
	cd /home/li/mPSI/libPaXoS && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libPaXoS/ObliviousDictionary.cpp -o CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.s

libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o.requires:

.PHONY : libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o.requires

libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o.provides: libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o.requires
	$(MAKE) -f libPaXoS/CMakeFiles/libPaXoS.dir/build.make libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o.provides.build
.PHONY : libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o.provides

libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o.provides.build: libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o


libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o: libPaXoS/CMakeFiles/libPaXoS.dir/flags.make
libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o: libPaXoS/gf2e_mat_solve.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o"
	cd /home/li/mPSI/libPaXoS && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o -c /home/li/mPSI/libPaXoS/gf2e_mat_solve.cpp

libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.i"
	cd /home/li/mPSI/libPaXoS && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/li/mPSI/libPaXoS/gf2e_mat_solve.cpp > CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.i

libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.s"
	cd /home/li/mPSI/libPaXoS && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/li/mPSI/libPaXoS/gf2e_mat_solve.cpp -o CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.s

libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o.requires:

.PHONY : libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o.requires

libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o.provides: libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o.requires
	$(MAKE) -f libPaXoS/CMakeFiles/libPaXoS.dir/build.make libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o.provides.build
.PHONY : libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o.provides

libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o.provides.build: libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o


# Object files for target libPaXoS
libPaXoS_OBJECTS = \
"CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o" \
"CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o"

# External object files for target libPaXoS
libPaXoS_EXTERNAL_OBJECTS =

lib/liblibPaXoS.a: libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o
lib/liblibPaXoS.a: libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o
lib/liblibPaXoS.a: libPaXoS/CMakeFiles/libPaXoS.dir/build.make
lib/liblibPaXoS.a: libPaXoS/CMakeFiles/libPaXoS.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/li/mPSI/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX static library ../lib/liblibPaXoS.a"
	cd /home/li/mPSI/libPaXoS && $(CMAKE_COMMAND) -P CMakeFiles/libPaXoS.dir/cmake_clean_target.cmake
	cd /home/li/mPSI/libPaXoS && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/libPaXoS.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libPaXoS/CMakeFiles/libPaXoS.dir/build: lib/liblibPaXoS.a

.PHONY : libPaXoS/CMakeFiles/libPaXoS.dir/build

libPaXoS/CMakeFiles/libPaXoS.dir/requires: libPaXoS/CMakeFiles/libPaXoS.dir/ObliviousDictionary.cpp.o.requires
libPaXoS/CMakeFiles/libPaXoS.dir/requires: libPaXoS/CMakeFiles/libPaXoS.dir/gf2e_mat_solve.cpp.o.requires

.PHONY : libPaXoS/CMakeFiles/libPaXoS.dir/requires

libPaXoS/CMakeFiles/libPaXoS.dir/clean:
	cd /home/li/mPSI/libPaXoS && $(CMAKE_COMMAND) -P CMakeFiles/libPaXoS.dir/cmake_clean.cmake
.PHONY : libPaXoS/CMakeFiles/libPaXoS.dir/clean

libPaXoS/CMakeFiles/libPaXoS.dir/depend:
	cd /home/li/mPSI && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/li/mPSI /home/li/mPSI/libPaXoS /home/li/mPSI /home/li/mPSI/libPaXoS /home/li/mPSI/libPaXoS/CMakeFiles/libPaXoS.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libPaXoS/CMakeFiles/libPaXoS.dir/depend

