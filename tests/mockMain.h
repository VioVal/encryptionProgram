#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>

#define TRUE 1
#define FALSE 0

void checkNumberOfArguments(int argc);
int checkEncryptOrDecrypt(char encryptOrDecrypt[]);
int checkKey(char key[]);
uint64_t returnKey(char *hexKey);
int encryptPlaintext(struct EncryptionInformation *encryptionInformation, uint64_t key);
int decryptCiphertext(struct DecryptionInformation *decryptionInformation, uint64_t key);

#endif