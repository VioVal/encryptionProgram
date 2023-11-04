#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "../headers/decryptCiphertext.h"
#include "../headers/subkeyGenerator.h"
#include "../headers/desRounds.h"
#include "../headers/errorHandling.h"
#include "../headers/fileFunctions.h"

extern enum ErrorMessage errorMessage;


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


int setLastCipherTextToInitialisationVector(uint64_t *lastCiphertext, FILE *cipertextFilePointer)
{
    int error = 0;

    error = fseek(cipertextFilePointer, 0, SEEK_SET);
    if(error != 0)
    {
        errorMessage = readError;
        return -1;
    }

    error = fread(lastCiphertext, 8, 1, cipertextFilePointer);
    if(error != 1)
    {
        errorMessage = readError;
        return -1;
    }

    return 0;
}


uint64_t desWithCbccForDecryption(struct DecryptionInformation *decryptionInformation)
{
    int error = 0;
    uint64_t currentBlock = 0;
    uint64_t currentCiphertext = 0;

    error = fseek(decryptionInformation->plaintextFilePointer, 0, SEEK_SET);
    if(error != 0)
    {
        errorMessage = readError;
        return -1;
    }

    // minus 2 because the write file won't have the first or last blocks

    for(size_t i = 0; i < decryptionInformation->noOfBlocks - 2; i++)
    {
        error = fread(&currentBlock, 8, 1, decryptionInformation->cipertextFilePointer);
        if(error != 1)
        {
            errorMessage = readError;
            return -1;
        }

        currentCiphertext = currentBlock;
        currentBlock = desRounds(currentBlock, decryptionInformation->arrayOfSubkeys);
        currentBlock ^= decryptionInformation->lastCiphertext;
        decryptionInformation->lastCiphertext = currentCiphertext;
        decryptionInformation->checkSum ^= currentBlock;

        if(i >= decryptionInformation->noOfBlocks - 3)
        {
            return currentBlock;
        }

        error = fwrite(&currentBlock, 8, 1, decryptionInformation->plaintextFilePointer);
        if(error != 1)
        {
            errorMessage = writeError;
            return -1;
        }
        currentBlock = 0;
    }
}


uint64_t decryptFinalBlock(struct DecryptionInformation *decryptionInformation)
{
    int error = 0;
    uint64_t finalBlock = 0;

    error = fread(&finalBlock, 8, 1, decryptionInformation->cipertextFilePointer);
    if(error != 1)
    {
        errorMessage = readError;
        return -1;
    }

    finalBlock = desRounds(finalBlock, decryptionInformation->arrayOfSubkeys);
    finalBlock ^= decryptionInformation->lastCiphertext;
    finalBlock ^= decryptionInformation->checkSum;

    return finalBlock;
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


int writePenultimateBlock(struct DecryptionInformation *decryptionInformation)
{
    int error = 0;

    if(decryptionInformation->sizeOfPenultimateBlock == 0)
    {
        decryptionInformation->sizeOfPenultimateBlock = 8;
    }

    error = fwrite(&decryptionInformation->penultimate, 1, decryptionInformation->sizeOfPenultimateBlock, decryptionInformation->plaintextFilePointer);
    if(error != decryptionInformation->sizeOfPenultimateBlock)
    {
        errorMessage = writeError;
        return -1;
    }

    return 0;
}


int checkChecksum(int noOfBlocks, uint64_t finalBlock)
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

    finalBlock &= mask;

    if(finalBlock != noOfBlocks - 2)
    {
        errorMessage = decryptionFailure;
        return -1;
    }

    return 0;
}


void printSuccessMessage()
{
    printf("The file was successfully decrypted\n");
}


int decryptCiphertext(struct DecryptionInformation *decryptionInformation, uint64_t key)
{
    int error = 0;
    size_t sizeOfFile = 0;

    sizeOfFile = checkSizeOfFile(decryptionInformation->cipertextFilePointer);
    if(sizeOfFile == -1) return -1;
    decryptionInformation->noOfBlocks = calculateNoOfBlocksNeeded(sizeOfFile);

    generateSubkeysFromKey(key, decryptionInformation->arrayOfSubkeys);
    reverseSubkeyArray(decryptionInformation->arrayOfSubkeys);

    error = setLastCipherTextToInitialisationVector(&decryptionInformation->lastCiphertext, decryptionInformation->cipertextFilePointer);
    if(error == -1) return -1;

    decryptionInformation->penultimate = desWithCbccForDecryption(decryptionInformation);
    if(decryptionInformation->penultimate == -1) return -1;

    decryptionInformation->finalBlock = decryptFinalBlock(decryptionInformation);
    if(decryptionInformation->finalBlock == -1) return -1;

    decryptionInformation->sizeOfPenultimateBlock = getSizeOfPenultimateBlock(decryptionInformation->finalBlock);

    error = writePenultimateBlock(decryptionInformation);
    if(error == -1) return -1;

    error = checkChecksum(decryptionInformation->noOfBlocks, decryptionInformation->finalBlock);
    if(error == -1) return -1;

    printSuccessMessage();

    closeFiles(decryptionInformation->cipertextFilePointer, decryptionInformation->plaintextFilePointer);
}