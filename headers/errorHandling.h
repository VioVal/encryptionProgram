#ifndef ERRORHANDLING_H
#define ERRORHANDLING_H

#include <errno.h>
#include <stdlib.h>

typedef enum ErrorMessage
{
    none,
    numberOfArguments, 
    incorrectArgument, 
    keyInWrongBase, 
    wrongKeySize, 
    weakKey, 
    sizeOfFileTooLarge, 
    encryptionFailure, 
    decryptionFailure, 
    openErrorReadFile, 
    openErrorWriteFile, 
    closeError, 
    readError, 
    writeError, 
    test 
} ErrorMessage;

extern int errno;

void errorHandler(ErrorMessage errorMessage);

#endif