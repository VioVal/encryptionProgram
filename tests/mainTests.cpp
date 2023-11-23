#include <gtest/gtest.h>
extern "C"
{
    #include "mockMain.h"
    #include "../headers/encryptPlaintext.h"
    #include "../headers/decryptCiphertext.h"
}


TEST(mainTests, checkNumberOfArgumentsTests)
{
    EXPECT_DEATH(checkNumberOfArguments(40), "");
    EXPECT_DEATH(checkNumberOfArguments(2), "");
}


TEST(mainTests, checkEncryptOrDecryptTests)
{
    char arrayOfTestString[6][14] = {"", "hfeuiaohweu", "-e", "--encrypt", "-d", "--decrypt"};
    EXPECT_DEATH(checkEncryptOrDecrypt(arrayOfTestString[0]), "");
    EXPECT_DEATH(checkEncryptOrDecrypt(arrayOfTestString[1]), "");
    EXPECT_EQ(checkEncryptOrDecrypt(arrayOfTestString[2]), encrypt);
    EXPECT_EQ(checkEncryptOrDecrypt(arrayOfTestString[3]), encrypt);
    EXPECT_EQ(checkEncryptOrDecrypt(arrayOfTestString[4]), decrypt);
    EXPECT_EQ(checkEncryptOrDecrypt(arrayOfTestString[5]), decrypt);
}


TEST(mainTests, checkKeyTests)
{
    char arrayOfTestKeys[][30] = {"", "zzzzzzzzzzzzzzzz", "1abcf43acbd367923", "0000000074fa5bd2",
        "ffffffff74fa5bd2", "e6fa4cb200000000", "e6fa4cb2ffffffff"};

    EXPECT_DEATH(checkKey(arrayOfTestKeys[0]), "");
    EXPECT_DEATH(checkKey(arrayOfTestKeys[1]), "");
    EXPECT_DEATH(checkKey(arrayOfTestKeys[2]), "");
    EXPECT_DEATH(checkKey(arrayOfTestKeys[3]), "");
    EXPECT_DEATH(checkKey(arrayOfTestKeys[4]), "");
    EXPECT_DEATH(checkKey(arrayOfTestKeys[5]), "");
    EXPECT_DEATH(checkKey(arrayOfTestKeys[6]), "");
}


TEST(mainTests, returnDecimalKeyTest)
{
    char hexKey[] = "e6fa4cb274fa5bd2";
    uint64_t key = 16643699702251543506ul;

    EXPECT_EQ(returnDecimalKey(hexKey), key);
}


TEST(mainTests, encryptAndDecryptTest)
{
    uint64_t key = 0;
    char hexKey[] = "e6fa4cb274fa5bd2";
    char arrayOfFilePaths[6][60] = {"../../tests/mockFiles/mockMainTestFile.txt", "../../tests/mockFiles/encryptedTestFile",
        "../../tests/mockFiles/encryptedTestFile", "../../tests/mockFiles/decryptedMockMainTestFile.txt", "../../tests/mockFiles/mockMainTestFile.txt", "../../tests/mockFiles/decryptedMockMainTestFile.txt"};

    key = returnDecimalKey(hexKey);

    struct EncryptionInformation encryptionInformation = {LASTCIPHERTEXT, CHECKSUM, ARRAYOFSUBKEYS, 
        NOOFBLOCKS, SIZEOFLASTBLOCK, PLAINTEXTFILEPOINTER, CIPHERTEXTFILEPOINTER};

    openFileToBeRead(arrayOfFilePaths[0], &encryptionInformation.plaintextFilePointer);
    openFileToBeWritten(arrayOfFilePaths[1], &encryptionInformation.cipertextFilePointer);
    encryptPlaintext(&encryptionInformation, key);

    struct DecryptionInformation decryptionInformation = {LASTCIPHERTEXT, CHECKSUM, ARRAYOFSUBKEYS, NOOFBLOCKS, 
        PENULTIMATE, SIZEOFPENULTIMATEBLOCK, FINALBLOCK, PLAINTEXTFILEPOINTER, CIPHERTEXTFILEPOINTER};

    openFileToBeRead(arrayOfFilePaths[2], &decryptionInformation.cipertextFilePointer);
    openFileToBeWritten(arrayOfFilePaths[3], &decryptionInformation.plaintextFilePointer);
    decryptCiphertext(&decryptionInformation, key);

    FILE *originalFile = NULL;
    FILE *decryptedFile = NULL;
    openFileToBeRead(arrayOfFilePaths[4], &originalFile);
    openFileToBeRead(arrayOfFilePaths[5], &decryptedFile);

    EXPECT_EQ(compareTwoFiles(11, &originalFile, &decryptedFile), 0);

    closeFiles(originalFile, decryptedFile);
}