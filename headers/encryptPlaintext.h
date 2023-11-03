#ifndef ENCRYPTPLAINTEXT_H
#define ENCRYPTPLAINTEXT_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include "../headers/fileFunctions.h"

#define LENGTHOFARRAY 16
#define KEYARRAYSIZE 16

#define LASTCIPHERTEXT 0
#define CHECKSUM 0
#define ARRAYOFSUBKEYS {0}
#define NOOFBLOCKS 0
#define SIZEOFLASTBLOCK 0
#define PLAINTEXTFILEPOINTER NULL
#define CIPHERTEXTFILEPOINTER NULL

struct EncryptionInformation
{
    uint64_t lastCiphertext;
    uint64_t checkSum;
    uint64_t arrayOfSubkeys[LENGTHOFARRAY];
    size_t noOfBlocks;
    size_t sizeOfLastBlock;
    FILE *plaintextFilePointer;
    FILE *cipertextFilePointer;
};

void openPlaintextFileForEncryption(char plaintextFilePath[], FILE **plaintextFilePointer);
void openCipertextFileForEncryption(char ciphertextFilePath[], FILE **ciphertextFilePointer);
int checkFileIsntTooLarge(size_t sizeOfFile);
int writeInitialisationVector(struct EncryptionInformation *encryptionInformation);
int desWithCbccForEncryption(struct EncryptionInformation *encryptionInformation);
int writeFinalBlock(struct EncryptionInformation *encryptionInformation);
void closePlaintextFile(FILE *plaintextFilePointer);
int checkIfWriteWasSuccessful(int noOfBlocks, FILE *cipertextFilePointer);
int encryptPlaintext(struct EncryptionInformation *encryptionInformation, uint64_t key);

#endif