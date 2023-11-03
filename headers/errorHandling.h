#ifndef ERRORHANDLING_H
#define ERRORHANDLING_H

#include <errno.h>
#include <stdlib.h>

enum ErrorMessage
{
    none,
    numberOfArguments, 
    incorrectArgument, 
    keyInWrongBase, 
    wrongKeySize, 
    weakKey, 
    sizeOfFile, 
    encryptionFailure, 
    decryptionFailure, 
    openErrorReadFile, 
    openErrorWriteFile, 
    closeError, 
    readError, 
    writeError, 
    test 
};

extern int errno;
extern enum ErrorMessage errorMessage;

void errorHandler(FILE *firstFilePointer, FILE *secondFilePointer);

#endif