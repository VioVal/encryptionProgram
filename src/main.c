#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "../headers/main.h"
#include "../headers/errorHandling.h"
#include "../headers/encryptPlaintext.h"
#include "../headers/decryptCiphertext.h"
#include "../headers/fileFunctions.h"

#define TRUE 1
#define FALSE 0


static void printProgramInstructions()
{
    printf("This program uses the DES encryption algorithm along with the CBCC mode to encrypt files.\n\nIt takes 4 arguments, which are as follows.\n\nThe first argument must be \"-e\" or \"--encrypt\" for encryption, or \"-d\" or \"--decrypt\"\n\nThe second must be a 64 bit key in hexedecimal. That means it should 16 charactes long.\n\nThe third argument should be the absolute or relative path to the file you would like to encrypt or decrypt.\n\nThe forth should be where you would like the encrypted or decrypted file to be written. Use the absolute or relative path with the name of the file you would like to use. If it is an already existing file it will be overwritten.\n");
}


void checkNumberOfArguments(int argc)
{
    if(argc == 1)
    {
        printProgramInstructions();
        exit(0);
    }
    if(argc != 5)
    {
        errorHandler(numberOfArguments);
    }
}


EncryptOrDecrypt_t checkEncryptOrDecrypt(char *encryptOrDecryptArg)
{
    EncryptOrDecrypt_t encryptOrDecrypt;

    if(strcmp(encryptOrDecryptArg, "-e") == 0 || strcmp(encryptOrDecryptArg, "--encrypt") == 0)
    {
        encryptOrDecrypt = encrypt;
        return encryptOrDecrypt;
    } 
    else if(strcmp(encryptOrDecryptArg, "-d") == 0 || strcmp(encryptOrDecryptArg, "--decrypt") == 0)
    {
        encryptOrDecrypt = decrypt;
        return encryptOrDecrypt;
    } 
    else 
    {
        errorHandler(incorrectArgument);
    }
}


static void checkWeakKey(char keyHalf[9])
{
    const char weakKeyHalf1[] = "00000000";
    const char weakKeyHalf2[] = "FFFFFFFF";

    size_t keySize = sizeof(char) * 8;

    if(memcmp(keyHalf, weakKeyHalf1, keySize) == 0 || memcmp(keyHalf, weakKeyHalf2, keySize) == 0)
    {
        errorHandler(weakKey);
    }
}


void checkKey(char *key)
{
    int error = 0;

    for(int i = 0; i < strlen(key); i++)
    {
        if(isxdigit(key[i]) == 0){
            errorHandler(keyInWrongBase);
        }
    }

    if(strlen(key) != 16)
    {
        errorHandler(wrongKeySize);
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


int main(int argc, char *argv[])
{
    ErrorMessage errorMessage = none;
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

    if(EncryptOrDecrypt == encrypt)
    {
        EncryptionInformation encryptionInformation = {LASTCIPHERTEXT, CHECKSUM, ARRAYOFSUBKEYS, 
        NOOFBLOCKS, SIZEOFLASTBLOCK, PLAINTEXTFILEPOINTER, CIPHERTEXTFILEPOINTER};

        errorMessage = openFileToBeRead(targetFilePath, &encryptionInformation.plaintextFilePointer);
        if(errorMessage != none) errorHandler(errorMessage);

        errorMessage = openFileToBeWritten(destinationFilePath, &encryptionInformation.cipertextFilePointer);
        if(errorMessage != none)
        {
            closeFile(encryptionInformation.plaintextFilePointer);
            errorHandler(errorMessage);
        }

        errorMessage = encryptPlaintext(&encryptionInformation, key);
        if(errorMessage != none) errorHandler(errorMessage);
    } 
    else
    {
        DecryptionInformation decryptionInformation = {LASTCIPHERTEXT, CHECKSUM, ARRAYOFSUBKEYS, NOOFBLOCKS, 
        PENULTIMATE, SIZEOFPENULTIMATEBLOCK, FINALBLOCK, PLAINTEXTFILEPOINTER, CIPHERTEXTFILEPOINTER};

        errorMessage = openFileToBeRead(targetFilePath, &decryptionInformation.cipertextFilePointer);
        if(errorMessage != none) errorHandler(errorMessage);

        errorMessage = openFileToBeWritten(destinationFilePath, &decryptionInformation.plaintextFilePointer);
        if(errorMessage != none)
        {
            closeFile(decryptionInformation.cipertextFilePointer);
            errorHandler(errorMessage);
        }
        
        errorMessage = decryptCiphertext(&decryptionInformation, key);
        if(errorMessage != none) errorHandler(errorMessage);
    }

    return 0;
}