#ifndef MOCKMAIN_H
#define MOCKMAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>

#define TRUE 1
#define FALSE 0

typedef enum EncryptOrDecrypt
{
    encrypt,
    decrypt
} EncryptOrDecrypt_t; 

void checkNumberOfArguments(int argc);
EncryptOrDecrypt_t checkEncryptOrDecrypt(char encryptOrDecrypt[]);
void checkKey(char key[]);
uint64_t returnDecimalKey(char hexKey[]);

#endif