#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include "../headers/encryptPlaintext.h"
#include "../headers/subkeyGenerator.h"
#include "../headers/desRounds.h"
#include "../headers/errorHandling.h"
#include "../headers/fileFunctions.h"

extern enum ErrorMessage errorMessage;


int checkFileIsntTooLarge(size_t sizeOfFile)
{
    //we use a 56 bits of the final block to represent the number of 64 bit blocks.
    if(sizeOfFile > (pow(2, 56) * 8) - 1)
    {
        errorMessage = sizeOfFile;
        return -1;
    }

    return 0;
}


int writeInitialisationVector(struct EncryptionInformation *encryptionInformation)
{
    int error = 0;

    error = fseek(encryptionInformation->cipertextFilePointer, 0, SEEK_SET);
    if(error != 0)
    {
        errorMessage = readError;
        return -1;
    }

    time_t currentTime;
    uint64_t iv = 0;

    currentTime = time(NULL);
    iv |= currentTime;
    iv = desRounds(iv, encryptionInformation->arrayOfSubkeys);
    encryptionInformation->lastCiphertext = iv;

    error = fwrite(&iv, 8, 1, encryptionInformation->cipertextFilePointer);
    if(error != 1)
    {
        errorMessage = writeError;
        return -1;
    }

    return 0;
}


int desWithCbccForEncryption(struct EncryptionInformation *encryptionInformation)
{
    int error = 0;
    uint64_t currentBlock = 0;

    error = fseek(encryptionInformation->plaintextFilePointer, 0, SEEK_SET);
    if(error != 0)
    {
        errorMessage = readError;
        return -1;
    }

    for(size_t i = 0; i < encryptionInformation->noOfBlocks; i++)
    {
        size_t blockSize = (i < encryptionInformation->noOfBlocks - 1 ? 8 : encryptionInformation->sizeOfLastBlock);

        error = fread(&currentBlock, 1, blockSize, encryptionInformation->plaintextFilePointer);
        if(error != blockSize)
        {
            errorMessage = readError;
            return -1;
        }

        encryptionInformation->checkSum ^= currentBlock;
        currentBlock ^= encryptionInformation->lastCiphertext;
        currentBlock = desRounds(currentBlock, encryptionInformation->arrayOfSubkeys);
        encryptionInformation->lastCiphertext = currentBlock;

        error = fwrite(&currentBlock, 8, 1, encryptionInformation->cipertextFilePointer);
        if(error != 1)
        {
            errorMessage = writeError;
            return -1;
        }

        currentBlock = 0;
    }

    return 0;
}


int writeFinalBlock(struct EncryptionInformation *encryptionInformation)
{
    int error = 0;
    uint64_t finalBlock = 0;

    finalBlock |= encryptionInformation->sizeOfLastBlock;
    finalBlock <<= 56;
    finalBlock |= encryptionInformation->noOfBlocks;
    finalBlock ^= encryptionInformation->lastCiphertext;
    finalBlock ^= encryptionInformation->checkSum;
    finalBlock = desRounds(finalBlock, encryptionInformation->arrayOfSubkeys);

    error = fwrite(&finalBlock, 8, 1, encryptionInformation->cipertextFilePointer);
    if(error != 1)
    {
        errorMessage = writeError;
        return -1;
    }

    return 0;
}


int checkIfWriteWasSuccessful(int noOfBlocks, FILE *cipertextFilePointer)
{
    size_t noOfBlocksWritten = 0;

    noOfBlocksWritten = calculateNoOfBlocksNeeded(checkSizeOfFile(cipertextFilePointer));
    
    if(noOfBlocksWritten != noOfBlocks + 2)
    {
        errorMessage = encryptionFailure;
        return -1;
    }

    return 0;
}


void successMessage()
{
    printf("Encryption successful\n");
}


int encryptPlaintext(struct EncryptionInformation *encryptionInformation, uint64_t key)
{
    int error = 0;
    size_t sizeOfFile = 0;

    sizeOfFile = checkSizeOfFile(encryptionInformation->plaintextFilePointer);
    if(sizeOfFile == -1) return -1;

    error = checkFileIsntTooLarge(sizeOfFile);
    if(error == -1) return -1;

    encryptionInformation->noOfBlocks = calculateNoOfBlocksNeeded(sizeOfFile);
    encryptionInformation->sizeOfLastBlock = calculateSizeOfLastBlock(sizeOfFile);

    generateSubkeysFromKey(key, encryptionInformation->arrayOfSubkeys);

    error = writeInitialisationVector(encryptionInformation);
    if(error == -1) return -1;

    error = desWithCbccForEncryption(encryptionInformation);
    if(error == -1) return -1;

    writeFinalBlock(encryptionInformation);
    if(error == -1) return -1;

    checkIfWriteWasSuccessful(encryptionInformation->noOfBlocks, encryptionInformation->cipertextFilePointer);
    if(error == -1) return -1;

    successMessage();

    closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);

    return 0;
}