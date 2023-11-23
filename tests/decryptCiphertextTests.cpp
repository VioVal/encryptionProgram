#include <gtest/gtest.h>
extern "C"
{
    #include "../headers/decryptCiphertext.h"
    #include "../headers/fileFunctions.h"
    #include "../headers/subkeyGenerator.h"
    #include "../headers/errorHandling.h"
}


namespace Decrypt
{
    struct DecryptionInformation decryptionInformation = {LASTCIPHERTEXT, CHECKSUM, ARRAYOFSUBKEYS, NOOFBLOCKS, 
        PENULTIMATE, SIZEOFPENULTIMATEBLOCK, FINALBLOCK, PLAINTEXTFILEPOINTER, CIPHERTEXTFILEPOINTER};
}

using namespace Decrypt;


TEST(decryptCiphertextTests, reverseSubkeyArrayTests)
{
    generateSubkeysFromKey(16643699702251543506lu, decryptionInformation.arrayOfSubkeys);
    reverseSubkeyArray(decryptionInformation.arrayOfSubkeys);

    uint64_t reversedSubkeyArray[16] = {205980008419325, 205980008419325, 254945147840472, 278066850885396,
        222917302079331, 123137328928737, 253086846088927, 172336618458319,
        270449348115325, 89197811473385, 169288515655599, 258848785093535,
        175223457147341, 25237182703029, 225794418531735, 68154083931694};

    EXPECT_EQ(memcmp(reversedSubkeyArray, decryptionInformation.arrayOfSubkeys, sizeof(uint64_t)), 0);
}


TEST(decryptCiphertextTests, setLastCipherTextToInitialisationVectorTests)
{
    decryptionInformation.noOfBlocks = 4;
    char targetFilePath[] = "../../tests/mockFiles/decryptionTest";
    char destinationFilePath[] = "../../tests/mockFiles/decryptionTests.txt";
    
    openFileToBeRead(targetFilePath, &decryptionInformation.cipertextFilePointer);
    openFileToBeWritten(destinationFilePath, &decryptionInformation.plaintextFilePointer);

    uint64_t expectedCiphertext = 17987096311105970965ul;
    setLastCipherTextToInitialisationVector(&decryptionInformation);
    EXPECT_EQ(expectedCiphertext, decryptionInformation.lastCiphertext);
}


TEST(decryptCiphertextTests, desWithCbccForDecryptionTests)
{
    uint64_t expectedPenultimate = 143418749551ul;
    desWithCbccForDecryption(&decryptionInformation);
    EXPECT_EQ(expectedPenultimate, decryptionInformation.penultimate);
}


TEST(decryptCiphertextTests, decryptFinalBlockTests)
{
    uint64_t expectedFinalBlock = 360287970189639682ul;
    decryptFinalBlock(&decryptionInformation);
    EXPECT_EQ(expectedFinalBlock, decryptionInformation.finalBlock);
}


TEST(decryptCiphertextTests, getSizeOfPenultimateBlockTests)
{
    uint64_t expectedSizeOfPenultimateBlock = 5;
    decryptionInformation.sizeOfPenultimateBlock = getSizeOfPenultimateBlock(decryptionInformation.finalBlock);
    EXPECT_EQ(expectedSizeOfPenultimateBlock, decryptionInformation.sizeOfPenultimateBlock);
}


TEST(decryptCiphertextTests, writePenultimateBlockTest)
{
    uint64_t expectedPenultimateBlock = 143418749551ul;
    uint64_t writtenBlock = 0;

    writePenultimateBlock(&decryptionInformation);
    fseek(decryptionInformation.plaintextFilePointer, -5, SEEK_CUR);
    fread(&writtenBlock, 1, 5, decryptionInformation.plaintextFilePointer);
    
    EXPECT_EQ(expectedPenultimateBlock, writtenBlock);
}


TEST(decryptCiphertextTests, checkChecksumTests)
{
    ErrorMessage error = none;

    error = checkChecksum(&decryptionInformation);
    EXPECT_EQ(error, none);

    decryptionInformation.noOfBlocks = 0;

    error = checkChecksum(&decryptionInformation);
    EXPECT_EQ(error, decryptionFailure);
}