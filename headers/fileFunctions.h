#ifndef FILEFUNCTIONS_H
#define FILEFUNCTIONS_H

struct FilePointers
{
    FILE *plaintextFilePointer;
    FILE *cipertextFilePointer;
};

int closeFile(FILE *filePointer);
int closeFiles(FILE *firstFilePointer, FILE *secondFilePointer);
int openFileToBeRead(char filePath[], FILE **filePointer);
int openFileToBeWritten(char filePath[], FILE **filePointer);
size_t checkSizeOfFile(FILE *plaintextFilePointer);
size_t calculateSizeOfLastBlock(size_t sizeOfFile);
size_t calculateNoOfBlocksNeeded(size_t sizeOfFile);
int compareTwoFiles(size_t sizeOfFile, FILE **firstFilePointer, FILE **secondFilePointer);

#endif