cmake_minimum_required(VERSION 3.20)
project(ping LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

add_executable(ping
  src/main.cpp
)
