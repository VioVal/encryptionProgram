#include <stdio.h>
#include <stdlib.h>
#include "../headers/fileFunctions.h"
#include "../headers/errorHandling.h"

extern enum ErrorMessage errorMessage;

int closeFile(FILE *filePointer)
{
    if(filePointer == NULL) return 0;
    int error = 0;
    error = fclose(filePointer);
    
    if(error != 0)
    {
        errorMessage = closeError;
        return -1;
    }
}

int closeFiles(FILE *firstFilePointer, FILE *secondFilePointer)
{
    int error = 0;

    error = closeFile(firstFilePointer);
    error = closeFile(secondFilePointer);

    if(error == -1) return -1;

    return 0;
}

int openFileToBeRead(char filePath[], FILE **filePointer)
{
    *filePointer = fopen(filePath, "rb");

    if(*filePointer == NULL)
    {
        errorMessage = openErrorReadFile;
        return -1;
    }
}

int openFileToBeWritten(char filePath[], FILE **filePointer)
{
    *filePointer = fopen(filePath, "wb+");

    if(*filePointer == NULL)
    {
        errorMessage = openErrorWriteFile;
        return -1;
    }
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


int compareTwoFiles(size_t sizeOfFile, FILE **firstFilePointer, FILE **secondFilePointer)
{
    int error = 0;
    int firstFileByte = 0;
    int secondFileByte = 0;

    for(size_t i = 0; i < sizeOfFile; i++)
    {
        fread(&firstFileByte, 1, 1, *firstFilePointer);
        fread(&secondFileByte, 1, 1, *secondFilePointer);

        if(firstFileByte != secondFileByte)
        {
            return -1;
        }
    }

    return 0;
}