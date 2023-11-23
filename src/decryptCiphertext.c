#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "../headers/decryptCiphertext.h"
#include "../headers/subkeyGenerator.h"
#include "../headers/desRounds.h"
#include "../headers/errorHandling.h"
#include "../headers/fileFunctions.h"


void reverseSubkeyArray(uint64_t subkeyArray[KEYARRAYSIZE])
{
    uint64_t tempArray[KEYARRAYSIZE] = {0};

    for(int i = 0; i < KEYARRAYSIZE; i++)
    {
        tempArray[i] = subkeyArray[i];
    }
    for(int i = 0; i < KEYARRAYSIZE; i++)
    {
        subkeyArray[i] = tempArray[15-i];
    }
}


ErrorMessage setLastCipherTextToInitialisationVector(DecryptionInformation *decryptionInformation)
{
    size_t error = 0;

    error = fseek(decryptionInformation->cipertextFilePointer, 0, SEEK_SET);
    if(error != 0)
    {
        closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
        return readError;
    }

    error = fread(&decryptionInformation->lastCiphertext, 8, 1, decryptionInformation->cipertextFilePointer);
    if(error != 1)
    {
        closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
        return readError;
    }

    return none;
}


ErrorMessage desWithCbccForDecryption(DecryptionInformation *decryptionInformation)
{
    int error = 0;
    uint64_t currentBlock = 0;
    uint64_t currentCiphertext = 0;

    error = fseek(decryptionInformation->plaintextFilePointer, 0, SEEK_SET);
    if(error != 0)
    {
        closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
        return readError;
    }

    // minus 2 because the write file won't have the first or last blocks

    for(size_t i = 0; i < decryptionInformation->noOfBlocks - 2; i++)
    {
        error = fread(&currentBlock, 8, 1, decryptionInformation->cipertextFilePointer);
        if(error != 1)
        {
            closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
            return readError;
        }

        currentCiphertext = currentBlock;
        currentBlock = desRounds(currentBlock, decryptionInformation->arrayOfSubkeys);
        currentBlock ^= decryptionInformation->lastCiphertext;
        decryptionInformation->lastCiphertext = currentCiphertext;
        decryptionInformation->checkSum ^= currentBlock;

        if(i >= decryptionInformation->noOfBlocks - 3)
        {
            decryptionInformation->penultimate = currentBlock;
            return none;
        }

        error = fwrite(&currentBlock, 8, 1, decryptionInformation->plaintextFilePointer);
        if(error != 1)
        {
            closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
            return writeError;
        }
        
        currentBlock = 0;
    }
}


ErrorMessage decryptFinalBlock(DecryptionInformation *decryptionInformation)
{
    size_t error = 0;
    uint64_t finalBlock = 0;

    error = fread(&finalBlock, 8, 1, decryptionInformation->cipertextFilePointer);
    if(error != 1)
    {
        closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
        return readError;
    }

    finalBlock = desRounds(finalBlock, decryptionInformation->arrayOfSubkeys);
    finalBlock ^= decryptionInformation->lastCiphertext;
    finalBlock ^= decryptionInformation->checkSum;

    decryptionInformation->finalBlock = finalBlock;

    return none;
}


size_t getSizeOfPenultimateBlock(uint64_t finalBlock)
{
    size_t sizeOfPenultimateBlock = 0;

    for(int i = 63; i > 55; i--)
    {
        if((finalBlock >> i) & 1)
        {
            sizeOfPenultimateBlock |= 1;
        }
        if(i > 56)
        {
            sizeOfPenultimateBlock <<= 1;
        }
    }

    return sizeOfPenultimateBlock;
}


ErrorMessage writePenultimateBlock(DecryptionInformation *decryptionInformation)
{
    int error = 0;

    if(decryptionInformation->sizeOfPenultimateBlock == 0)
    {
        decryptionInformation->sizeOfPenultimateBlock = 8;
    }

    error = fwrite(&decryptionInformation->penultimate, 1, decryptionInformation->sizeOfPenultimateBlock, decryptionInformation->plaintextFilePointer);
    if(error != decryptionInformation->sizeOfPenultimateBlock)
    {
        closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
        return writeError;
    }

    return none;
}


ErrorMessage checkChecksum(DecryptionInformation *decryptionInformation)
{
    uint64_t mask = 0;

    for(int i = 0; i < 56; i++)
    {
        mask |= 1;

        if(i < 55)
        {
            mask <<= 1;
        }
    }

    decryptionInformation->finalBlock &= mask;

    if(decryptionInformation->finalBlock != decryptionInformation->noOfBlocks - 2)
    {
        closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
        return decryptionFailure;
    }

    return none;
}


void printSuccessMessage()
{
    printf("The file was successfully decrypted\n");
}


ErrorMessage decryptCiphertext(DecryptionInformation *decryptionInformation, uint64_t key)
{
    ErrorMessage errorMessage = none;
    size_t sizeOfFile = 0;

    sizeOfFile = checkSizeOfFile(decryptionInformation->cipertextFilePointer);
    if(sizeOfFile == -1)
    {
        closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
        return readError;
    }

    decryptionInformation->noOfBlocks = calculateNoOfBlocksNeeded(sizeOfFile);

    generateSubkeysFromKey(key, decryptionInformation->arrayOfSubkeys);
    reverseSubkeyArray(decryptionInformation->arrayOfSubkeys);

    errorMessage = setLastCipherTextToInitialisationVector(decryptionInformation);
    if(errorMessage != none) return errorMessage;

    errorMessage = desWithCbccForDecryption(decryptionInformation);
    if(errorMessage != none) return errorMessage;

    errorMessage = decryptFinalBlock(decryptionInformation);
    if(errorMessage != none) return errorMessage;

    decryptionInformation->sizeOfPenultimateBlock = getSizeOfPenultimateBlock(decryptionInformation->finalBlock);

    errorMessage = writePenultimateBlock(decryptionInformation);
    if(errorMessage != none) return errorMessage;

    errorMessage = checkChecksum(decryptionInformation);
    if(errorMessage != none) return errorMessage;

    printSuccessMessage();

    closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);

    return none;
}