#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "../tests/mockMain.h"
#include "../headers/errorHandling.h"
#include "../headers/encryptPlaintext.h"
#include "../headers/decryptCiphertext.h"
#include "../headers/fileFunctions.h"

#define TRUE 1
#define FALSE 0

enum ErrorMessage errorMessage = none;


static void printProgramInstructions()
{
    printf("This program uses the DES encryption algorithm along with the CBCC mode to encrypt files.\n\nIt takes 4 arguments, which are as follows.\n\nThe first argument must be \"-e\" or \"--encrypt\" for encryption, or \"-d\" or \"--decrypt\"\n\nThe second must be a 64 bit key in hexedecimal. That means it should 16 charactes long.\n\nThe third argument should be the absolute or relative path to the file you would like to encrypt or decrypt.\n\nThe forth should be where you would like the encrypted or decrypted file to be written. Use the absolute or relative path with the name of the file you would like to use. If it is an already existing file it will be overwritten.\n");
}


void checkNumberOfArguments(int argc)
{
    if(argc != 5)
    {
        if(argc > 1)
        {
            errorMessage = numberOfArguments;
            errorHandler(NULL, NULL);
        }
    }
}


EncryptOrDecrypt_t checkEncryptOrDecrypt(char *encryptOrDecryptArg)
{
    EncryptOrDecrypt_t encryptOrDecrypt;

    if(strcmp(encryptOrDecryptArg, "-e") == 0 || strcmp(encryptOrDecryptArg, "--encrypt") == 0)
    {
        encryptOrDecrypt = encrypt;
        return TRUE;
    } 
    else if(strcmp(encryptOrDecryptArg, "-d") == 0 || strcmp(encryptOrDecryptArg, "--decrypt") == 0)
    {
        encryptOrDecrypt = decrypt;
        return FALSE;
    } 
    else 
    {
        errorMessage = incorrectArgument;
        errorHandler(NULL, NULL);
    }
}


static void checkWeakKey(char keyHalf[9])
{
    const char weakKeyHalf1[] = "00000000";
    const char weakKeyHalf2[] = "FFFFFFFF";

    size_t keySize = sizeof(char) * 8;

    if(memcmp(keyHalf, weakKeyHalf1, keySize) == 0 || memcmp(keyHalf, weakKeyHalf2, keySize) == 0)
    {
        errorMessage = weakKey;
        errorHandler(NULL, NULL);
    }
}


void checkKey(char *key)
{
    int error = 0;

    for(int i = 0; i < strlen(key); i++)
    {
        if(isxdigit(key[i]) == 0){
            errorMessage = keyInWrongBase;
            errorHandler(NULL, NULL);
        }
    }

    if(strlen(key) != 16)
    {
        errorMessage = wrongKeySize;
        errorHandler(NULL, NULL);
    }

    char firstHalf[9];
    char secondHalf[9];

    for(int i = 0; i < 8; i++)
    {
        firstHalf[i] = toupper(key[i]); 
    }

    for(int i = 0; i < 8; i++)
    {
        secondHalf[i] = toupper(key[i+8]);
    }

    checkWeakKey(firstHalf);
    checkWeakKey(secondHalf);
}


uint64_t returnDecimalKey(char *hexKey)
{
    uint64_t key = 0;
    key = strtoul(hexKey, NULL, 16);
    return key;
}


int mockMain(int argc, char *argv[])
{
    int error = 0;
    EncryptOrDecrypt_t EncryptOrDecrypt;
    uint64_t key = 0;
    char *encryptOrDecryptArg = argv[1];
    char *keyInHex = argv[2];
    char *targetFilePath = argv[3];
    char *destinationFilePath = argv[4];

    checkNumberOfArguments(argc);
    EncryptOrDecrypt = checkEncryptOrDecrypt(encryptOrDecryptArg);
    checkKey(keyInHex);
    key = returnDecimalKey(keyInHex);

    if(EncryptOrDecrypt = encrypt)
    {
        struct EncryptionInformation encryptionInformation = {LASTCIPHERTEXT, CHECKSUM, ARRAYOFSUBKEYS, 
        NOOFBLOCKS, SIZEOFLASTBLOCK, PLAINTEXTFILEPOINTER, CIPHERTEXTFILEPOINTER};

        error = openFileToBeRead(targetFilePath, &encryptionInformation.plaintextFilePointer);
        if(error == -1) errorHandler(encryptionInformation.plaintextFilePointer, NULL);

        error = openFileToBeWritten(destinationFilePath, &encryptionInformation.cipertextFilePointer);
        if(error == -1) errorHandler(encryptionInformation.plaintextFilePointer, encryptionInformation.cipertextFilePointer);

        error = encryptPlaintext(&encryptionInformation, key);
        if(error == -1) errorHandler(encryptionInformation.plaintextFilePointer, encryptionInformation.cipertextFilePointer);

        error = closeFiles(encryptionInformation.plaintextFilePointer, encryptionInformation.cipertextFilePointer);
        if(error == -1) errorHandler(encryptionInformation.plaintextFilePointer, encryptionInformation.cipertextFilePointer);
    } 
    else
    {
        struct DecryptionInformation decryptionInformation = {LASTCIPHERTEXT, CHECKSUM, ARRAYOFSUBKEYS, NOOFBLOCKS, 
        PENULTIMATE, SIZEOFPENULTIMATEBLOCK, FINALBLOCK, PLAINTEXTFILEPOINTER, CIPHERTEXTFILEPOINTER};

        error = openFileToBeRead(targetFilePath, &decryptionInformation.cipertextFilePointer);
        if(error == -1) errorHandler(decryptionInformation.cipertextFilePointer, NULL);

        error = openFileToBeWritten(destinationFilePath, &decryptionInformation.plaintextFilePointer);
        if(error == -1) errorHandler(decryptionInformation.cipertextFilePointer, decryptionInformation.plaintextFilePointer);
        
        error = decryptCiphertext(&decryptionInformation, key);
        if(error == -1) errorHandler(decryptionInformation.cipertextFilePointer, decryptionInformation.plaintextFilePointer);

        error = closeFiles(decryptionInformation.cipertextFilePointer, decryptionInformation.plaintextFilePointer);
        if(error == -1) errorHandler(decryptionInformation.cipertextFilePointer, decryptionInformation.plaintextFilePointer);
    }

    return 0;
}