cmake_minimum_required(VERSION 3.22)

set(this DESwithCBCC)

project(${this} C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

enable_testing()

add_subdirectory(googletest)

set(headers
    headers/decryptCiphertext.h
    headers/desRounds.h 
    headers/encryptPlaintext.h 
    headers/subkeyGenerator.h 
    headers/main.h
    headers/fileFunctions.h
    headers/errorHandling.h
)

set(sources
    src/main.c
    src/decryptCiphertext.c
    src/desRounds.c 
    src/encryptPlaintext.c 
    src/subkeyGenerator.c 
    src/fileFunctions.c
    src/errorHandling.c
)

set(testHeaders
    headers/decryptCiphertext.h
    headers/desRounds.h 
    headers/encryptPlaintext.h 
    headers/subkeyGenerator.h 
    headers/main.h
    headers/fileFunctions.h
    headers/errorHandling.h
    tests/mockMain.h
)

set(testSources
    src/decryptCiphertext.c
    src/desRounds.c 
    src/encryptPlaintext.c 
    src/subkeyGenerator.c 
    src/fileFunctions.c
    src/errorHandling.c
    tests/mockMain.c
)

add_library(${this} STATIC ${testSources} ${testHeaders})

add_subdirectory(tests)

add_executable(DESwithCBCC_Debug ${sources})