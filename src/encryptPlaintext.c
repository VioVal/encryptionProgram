#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include "../headers/encryptPlaintext.h"
#include "../headers/subkeyGenerator.h"
#include "../headers/desRounds.h"


size_t checkFileIsntTooLarge(size_t sizeOfFile)
{
    //we use a 56 bits of the final block to represent the number of 64 bit blocks.
    if(sizeOfFile > (pow(2, 56) * 8) - 1)
    {
        return -1;
    }

    return 0;
}


ErrorMessage writeInitialisationVector(EncryptionInformation *encryptionInformation)
{
    int error = 0;

    error = fseek(encryptionInformation->cipertextFilePointer, 0, SEEK_SET);
    if(error != 0)
    {
        closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
        return readError;
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
        closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
        return writeError;
    }

    return none;
}


ErrorMessage desWithCbccForEncryption(EncryptionInformation *encryptionInformation)
{
    int error = 0;
    uint64_t currentBlock = 0;

    error = fseek(encryptionInformation->plaintextFilePointer, 0, SEEK_SET);
    if(error != 0)
    {
        closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
        return readError;
    }

    for(size_t i = 0; i < encryptionInformation->noOfBlocks; i++)
    {
        size_t blockSize = (i < encryptionInformation->noOfBlocks - 1 ? 8 : encryptionInformation->sizeOfLastBlock);

        error = fread(&currentBlock, 1, blockSize, encryptionInformation->plaintextFilePointer);
        if(error != blockSize)
        {
            closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
            return readError;
        }

        encryptionInformation->checkSum ^= currentBlock;
        currentBlock ^= encryptionInformation->lastCiphertext;
        currentBlock = desRounds(currentBlock, encryptionInformation->arrayOfSubkeys);
        encryptionInformation->lastCiphertext = currentBlock;

        error = fwrite(&currentBlock, 8, 1, encryptionInformation->cipertextFilePointer);
        if(error != 1)
        {
            closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
            return writeError;
        }

        currentBlock = 0;
    }

    return none;
}


ErrorMessage writeFinalBlock(EncryptionInformation *encryptionInformation)
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
        closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
        return writeError;
    }

    return none;
}


ErrorMessage checkIfWriteWasSuccessful(EncryptionInformation *encryptionInformation)
{
    size_t noOfBlocksWritten = 0;

    noOfBlocksWritten = calculateNoOfBlocksNeeded(checkSizeOfFile(encryptionInformation->cipertextFilePointer));
    
    if(noOfBlocksWritten != encryptionInformation->noOfBlocks + 2)
    {
        closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
        return encryptionFailure;
    }

    return none;
}


void successMessage()
{
    printf("Encryption successful\n");
}


ErrorMessage encryptPlaintext(EncryptionInformation *encryptionInformation, uint64_t key)
{
    ErrorMessage errorMessage = none;
    size_t sizeOfFile = 0;

    sizeOfFile = checkSizeOfFile(encryptionInformation->plaintextFilePointer);
    if(sizeOfFile == -1)
    {
        closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
        return sizeOfFile;
    }

    if(checkFileIsntTooLarge(sizeOfFile) == -1)
    {
        closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);
        return sizeOfFileTooLarge;
    }

    encryptionInformation->noOfBlocks = calculateNoOfBlocksNeeded(sizeOfFile);
    encryptionInformation->sizeOfLastBlock = calculateSizeOfLastBlock(sizeOfFile);

    generateSubkeysFromKey(key, encryptionInformation->arrayOfSubkeys);

    errorMessage = writeInitialisationVector(encryptionInformation);
    if(errorMessage != none) return -errorMessage;

    errorMessage = desWithCbccForEncryption(encryptionInformation);
    if(errorMessage != none) return -errorMessage;

    errorMessage = writeFinalBlock(encryptionInformation);
    if(errorMessage != none) return -errorMessage;

    errorMessage = checkIfWriteWasSuccessful(encryptionInformation);
    if(errorMessage != none) return -errorMessage;

    successMessage();

    closeFiles(encryptionInformation->plaintextFilePointer, encryptionInformation->cipertextFilePointer);

    return none;
}