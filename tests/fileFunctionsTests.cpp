#include <gtest/gtest.h>
extern "C"
{
    #include "../headers/fileFunctions.h"
    #include "../headers/errorHandling.h"
}


TEST(fileFunctionTests, openFileTestsTests)
{
    char badFilePath[40] = "./fakeDirectory/fakefile.txt";
    FILE *filePointer = NULL;

    EXPECT_EQ(openFileToBeRead(badFilePath, &filePointer), openErrorReadFile);
    EXPECT_EQ(openFileToBeWritten(badFilePath, &filePointer), openErrorWriteFile);
}


TEST(fileFunctionTests, checkSizeOfFileTests)
{
    FILE *filePointer = NULL;
    char filePath[50] = "../../tests/mockFiles/encryptionTest.txt";
    openFileToBeRead(filePath, &filePointer);
    EXPECT_EQ(checkSizeOfFile(filePointer), 13);
    closeFile(filePointer);

    EXPECT_EQ(checkSizeOfFile(NULL), -1);
}


TEST(fileFunctionTests, calculateSizeOfLastBlockTest)
{
    size_t expectedSizeOfLastBlock = 5;
    size_t sizeOfFile = 13;

    EXPECT_EQ(calculateSizeOfLastBlock(sizeOfFile), expectedSizeOfLastBlock);
}


TEST(fileFunctionTests, calculateNoOfBlocksNeeded)
{
    size_t expectedNoOfBlocksNeeded = 2;
    size_t sizeOfFile = 13;

    EXPECT_EQ(calculateNoOfBlocksNeeded(sizeOfFile), expectedNoOfBlocksNeeded);
}