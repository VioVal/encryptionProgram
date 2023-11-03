#include <stdio.h>
#include <stdlib.h>
#include "../headers/errorHandling.h"
#include "../headers/fileFunctions.h"

static void displayErrorMessages()
{
    const char arrayOfErrorMessages[15][100] = 
    {
        "", 
        "This program takes 4 arguments. Please run the program with no arguments to read the guide\n", 
        "The arguments are not correct. Please run the program with no arguments to read the guide\n", 
        "The key needs to be in hexidecimal\n", 
        "The key needs to be 64 bits in length\n", 
        "I'm afraid this is considered a weak key. Please enter another\n", 
        "I'm afraid this file is too big to be encrypted by this program\n", 
        "The encryption failed\n",
        "The decryption failed\n",
        "There was an error opening the file to be read\n", 
        "There was an error opening the file ro be written\n",
        "There was an error closing one of the files\n", 
        "There was an error while reading files\n", 
        "There was an error while writing files\n", 
        "Testing\n" 
        };

    if(errorMessage > 0 && errorMessage <= 15)
    {
        printf("%s", arrayOfErrorMessages[errorMessage]);
    }

    if(errorMessage > 8 && errorMessage <= 14)
    {
        perror("error: ");
    }
}


void errorHandler(FILE *firstFilePointer, FILE *secondFilePointer)
{
    displayErrorMessages();

    int error = 0;
    error = closeFiles(firstFilePointer, secondFilePointer);
    if(error == -1)
    {
        errorMessage = closeError;
        displayErrorMessages();
    }

    exit(-1);
}