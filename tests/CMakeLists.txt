cmake_minimum_required(VERSION 3.22)

set(this encryptionProgramTests)

set(sources
    subkeyGeneratorTests.cpp
    desRoundsTests.cpp
    encryptPlainTest.cpp
    decryptCiphertextTests.cpp
    fileFunctionsTests.cpp
    errorHandlingTests.cpp
    mainTests.cpp
)

add_executable(${this} ${sources})
target_link_libraries(${this} PUBLIC
    gtest_main
    DESwithCBCC
)


add_test(
    NAME: ${this}
    COMMAND: ${this}
)