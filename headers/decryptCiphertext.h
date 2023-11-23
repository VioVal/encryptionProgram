#ifndef DECRYPTCIPHERTEXT_H
#define DECRYPTCIPHERTEXT_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "../headers/errorHandling.h"

#define LENGTHOFARRAY 16
#define KEYARRAYSIZE 16

#define LASTCIPHERTEXT 0
#define CHECKSUM 0
#define ARRAYOFSUBKEYS {0}
#define NOOFBLOCKS 0
#define PENULTIMATE 0
#define SIZEOFPENULTIMATEBLOCK 0
#define FINALBLOCK 0
#define PLAINTEXTFILEPOINTER NULL
#define CIPHERTEXTFILEPOINTER NULL


typedef struct DecryptionInformation
{
    uint64_t lastCiphertext;
    uint64_t checkSum;
    uint64_t arrayOfSubkeys[LENGTHOFARRAY];
    size_t noOfBlocks;
    uint64_t penultimate;
    size_t sizeOfPenultimateBlock;
    uint64_t finalBlock;
    FILE *plaintextFilePointer;
    FILE *cipertextFilePointer;
} DecryptionInformation;

void reverseSubkeyArray(uint64_t subkeyArray[KEYARRAYSIZE]);
ErrorMessage setLastCipherTextToInitialisationVector(DecryptionInformation *decryptionInformation);
ErrorMessage desWithCbccForDecryption(DecryptionInformation *decryptionInformation);
ErrorMessage decryptFinalBlock(DecryptionInformation *decryptionInformation);
size_t getSizeOfPenultimateBlock(uint64_t finalBlock);
ErrorMessage writePenultimateBlock(DecryptionInformation *decryptionInformation);
ErrorMessage checkChecksum(DecryptionInformation *decryptionInformation);
ErrorMessage decryptCiphertext(struct DecryptionInformation *decryptionInformation, uint64_t key);

#endif