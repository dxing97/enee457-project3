cmake_minimum_required(VERSION 3.12)
project(enee457-project3 C)

set(CMAKE_C_STANDARD 99)

include_directories(/usr/local/Cellar/openssl/1.0.2p/include)
include_directories(/usr/local/ssl/include)

add_executable(GenTable GenTable.c)
target_link_libraries(GenTable crypto)

add_executable(Crack Crack.c Crack.c project3.h)
target_link_libraries(Crack crypto)