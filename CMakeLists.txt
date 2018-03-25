cmake_minimum_required(VERSION 3.9)
project(RC4)

set(CMAKE_CXX_STANDARD 17)

add_executable(RC4 main.cpp RC4.hpp RC4.cpp)