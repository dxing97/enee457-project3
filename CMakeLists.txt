cmake_minimum_required(VERSION 2.8)
project(enee457-project3 C)

set(CMAKE_C_STANDARD 99)

#option(USE_RAINBOW_CHAINS "use rainbow chains instead of normal chains" ON)
#option(USE_MSB_REDUCTION "use most significant bits instead of least significat bits when using truncation as reduction function" OFF)
#option(IGNORE_DUPLICATES "don't search and avoid duplicate tails in the chain table" ON)

include_directories(/usr/local/Cellar/openssl/1.0.2p/include)
include_directories(/usr/local/ssl/include)

configure_file( ${CMAKE_SOURCE_DIR}/config.h.in ${CMAKE_BINARY_DIR}/config.h)



##if(OPT_USE_RAINBOW_CHAINS)
#    set(USE_RAINBOW_CHAINS ON)
##endif()
#
##if(OPT_USE_MSB_REDUCTION)
#    set(USE_MSB_REDUCTION OFF)
##endif()
#
##if(OPT_IGNORE_DUPLICATES)
#    set(IGNORE_DUPLICATES ON)
##endif()



set(STATIC_LIBS project3.h config.h)
set(LIBS crypto)

add_executable(GenTable GenTable.c project3.h ${STATIC_LIBS})
target_link_libraries(GenTable ${LIBS})

add_executable(Crack Crack.c project3.h ${STATIC_LIBS})
target_link_libraries(Crack ${LIBS})

add_executable(test tests.c project3.h ${STATIC_LIBS})
target_link_libraries(test ${LIBS})

add_executable(bruteforce bruteforce.c project3.h ${STATIC_LIBS})
target_link_libraries(bruteforce ${LIBS})