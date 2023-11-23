#ifndef ENCRYPTPLAINTEXT_H
#define ENCRYPTPLAINTEXT_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include "../headers/fileFunctions.h"
#include "../headers/errorHandling.h"

#define LENGTHOFARRAY 16
#define KEYARRAYSIZE 16

#define LASTCIPHERTEXT 0
#define CHECKSUM 0
#define ARRAYOFSUBKEYS {0}
#define NOOFBLOCKS 0
#define SIZEOFLASTBLOCK 0
#define PLAINTEXTFILEPOINTER NULL
#define CIPHERTEXTFILEPOINTER NULL

typedef struct EncryptionInformation
{
    uint64_t lastCiphertext;
    uint64_t checkSum;
    uint64_t arrayOfSubkeys[LENGTHOFARRAY];
    size_t noOfBlocks;
    size_t sizeOfLastBlock;
    FILE *plaintextFilePointer;
    FILE *cipertextFilePointer;
} EncryptionInformation;

size_t checkFileIsntTooLarge(size_t sizeOfFile);
ErrorMessage writeInitialisationVector(EncryptionInformation *encryptionInformation);
ErrorMessage desWithCbccForEncryption(EncryptionInformation *encryptionInformation);
ErrorMessage writeFinalBlock(EncryptionInformation *encryptionInformation);
ErrorMessage closePlaintextFile(FILE *plaintextFilePointer);
ErrorMessage checkIfWriteWasSuccessful(EncryptionInformation *encryptionInformation);
ErrorMessage encryptPlaintext(EncryptionInformation *encryptionInformation, uint64_t key);

#endif