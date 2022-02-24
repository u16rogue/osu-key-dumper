cmake_minimum_required(VERSION 3.18)

set(CMAKE_CXX_STANDARD 20)

project(osu-key-dumper VERSION 0.1.0)

add_executable(${PROJECT_NAME} main.cpp helper.cpp helper.hpp)