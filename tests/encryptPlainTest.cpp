#include <gtest/gtest.h>
extern "C"
{
    #include "../headers/encryptPlaintext.h"
    #include "../headers/fileFunctions.h"
    #include "../headers/subkeyGenerator.h"
}


namespace Encrypt
{
    struct EncryptionInformation encryptionInformation = {LASTCIPHERTEXT, CHECKSUM, ARRAYOFSUBKEYS, 
        NOOFBLOCKS, SIZEOFLASTBLOCK, PLAINTEXTFILEPOINTER, CIPHERTEXTFILEPOINTER};
}

using namespace Encrypt;


TEST(encryptPlaintextTest, writeInitialisationVectorTestWithNullPointers)
{
    //EXPECT_EQ(writeInitialisationVector(&encryptionInformation), -1);

    int error = 0;
    size_t fileSize = 0;
    encryptionInformation.noOfBlocks = 2;
    encryptionInformation.sizeOfLastBlock = 5;
    encryptionInformation.lastCiphertext = 11338317721715223088lu;
    char targetFilePath[] = "../../tests/mockFiles/encryptionTest.txt";
    char destinationFilePath[] = "../../tests/mockFiles/encryptionTest"; 

    error = openFileToBeRead(targetFilePath, &encryptionInformation.plaintextFilePointer);
    error = openFileToBeWritten(destinationFilePath, &encryptionInformation.cipertextFilePointer);

    generateSubkeysFromKey(16643699702251543506lu, encryptionInformation.arrayOfSubkeys);
}


TEST(encryptPlaintextTest, checkFileIsntTooLargeTest)
{
    size_t tooLargeFileSize = pow(2, 57) * 8;
    EXPECT_EQ(checkFileIsntTooLarge(tooLargeFileSize), -1);
}


TEST(encryptPlaintextTest, desWithCbccForEncryptionTest)
{
    fseek(encryptionInformation.plaintextFilePointer, 8, SEEK_SET);
    fseek(encryptionInformation.cipertextFilePointer, 8, SEEK_SET);

    uint64_t expectedLastCiphertext = 3708743939735060808lu;

    desWithCbccForEncryption(&encryptionInformation);

    EXPECT_EQ(expectedLastCiphertext, encryptionInformation.lastCiphertext);
}


TEST(encryptPlaintextTest, writeFinalBlockTest)
{
    uint64_t expectedFinalBlock = 18034945518686787422ul;
    uint64_t writtenBlock = 0;

    writeFinalBlock(&encryptionInformation);

    fseek(encryptionInformation.cipertextFilePointer, -8, SEEK_CUR);
    fread(&writtenBlock, 8, 1, encryptionInformation.cipertextFilePointer);

    EXPECT_EQ(expectedFinalBlock, writtenBlock);
}


TEST(encryptPlaintextTest, checkIfWriteWasSuccessfulTest)
{
    EXPECT_EQ(checkIfWriteWasSuccessful(&encryptionInformation), none);

    encryptionInformation.noOfBlocks = 0;

    EXPECT_EQ(checkIfWriteWasSuccessful(&encryptionInformation), encryptionFailure);
}