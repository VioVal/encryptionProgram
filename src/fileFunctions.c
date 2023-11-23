#include <stdio.h>
#include <stdlib.h>
#include "../headers/fileFunctions.h"
#include "../headers/errorHandling.h"

void closeFile(FILE *filePointer)
{
    fclose(filePointer);
}

void closeFiles(FILE *firstFilePointer, FILE *secondFilePointer)
{
    closeFile(firstFilePointer);
    closeFile(secondFilePointer);
}

ErrorMessage openFileToBeRead(char filePath[], FILE **filePointer)
{
    *filePointer = fopen(filePath, "rb");

    if(*filePointer == NULL)
    {
        return openErrorReadFile;
    }

    return none;
}

ErrorMessage openFileToBeWritten(char filePath[], FILE **filePointer)
{
    *filePointer = fopen(filePath, "wb+");

    if(*filePointer == NULL)
    {
        return openErrorWriteFile;
    }

    return none;
}

size_t checkSizeOfFile(FILE *filePointer)
{
    size_t sizeOfFile = 0;
    int error = 0;

    if(filePointer == NULL) return -1;

    error = fseek(filePointer, 0, SEEK_END);
    if(error != 0) return -1;

    sizeOfFile = ftell(filePointer);
    if(sizeOfFile == -1) return sizeOfFile;

    error = fseek(filePointer, 0, SEEK_SET);
    if(error != 0) return -1;

    return sizeOfFile;
}


size_t calculateSizeOfLastBlock(size_t sizeOfFile)
{
    size_t sizeOfLastBlock = 0;
    sizeOfLastBlock = (sizeOfFile % 8);

    return sizeOfLastBlock;
}


size_t calculateNoOfBlocksNeeded(size_t sizeOfFile)
{
    size_t noOfBlocks = 0;
    noOfBlocks = sizeOfFile/8;
    if (calculateSizeOfLastBlock(sizeOfFile) > 0){
        noOfBlocks += 1;
    }
    return noOfBlocks;
}