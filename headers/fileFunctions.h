#ifndef FILEFUNCTIONS_H
#define FILEFUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include "../headers/errorHandling.h"

struct FilePointers
{
    FILE *plaintextFilePointer;
    FILE *cipertextFilePointer;
};

void closeFile(FILE *filePointer);
void closeFiles(FILE *firstFilePointer, FILE *secondFilePointer);
ErrorMessage openFileToBeRead(char filePath[], FILE **filePointer);
ErrorMessage openFileToBeWritten(char filePath[], FILE **filePointer);
size_t checkSizeOfFile(FILE *plaintextFilePointer);
size_t calculateSizeOfLastBlock(size_t sizeOfFile);
size_t calculateNoOfBlocksNeeded(size_t sizeOfFile);

#endif