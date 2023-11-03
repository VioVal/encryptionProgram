#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>

#define TRUE 1
#define FALSE 0

void printProgramInstructions();
void checkNumberOfArguments(int argc);
int checkEncryptOrDecrypt(char encryptOrDecrypt[]);
int checkKey(char key[]);
uint64_t returnKey(char hexKey[]);

#endif