cmake_minimum_required(VERSION 3.9)
project(RC4)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -pedantic-errors")

add_executable(RC4 main.cpp RC4.hpp RC4.cpp)