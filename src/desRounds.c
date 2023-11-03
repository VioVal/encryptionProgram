#include <stdint.h>
#include "../headers/desRounds.h"


struct HalvesOfText splitPlaintextIntoHalves(uint64_t plaintext, struct HalvesOfText halvesOfText)
{
    for(int i = TEXTSIZE-1; i >= HALFSIZE; i--)
    {
        if((plaintext >> i) & 0x01)
        {
            halvesOfText.leftHalf |= 0x01;
        }
        if(i > HALFSIZE)
        {
            halvesOfText.leftHalf <<= 1;
        }
    }

    for(int i = HALFSIZE-1; i >= 0; i--)
    {
        if((plaintext >> i) & 0x01)
        {
            halvesOfText.rightHalf |= 0x01;
        }
        if(i > 0)
        {
            halvesOfText.rightHalf <<= 1;
        }
    }

    return halvesOfText;
}


uint64_t expansionPermutation(uint64_t valueToBeWorkedOn)
{
    uint64_t tempValue = 0;

    static const uint8_t eBox[KEYSIZE] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

    for(int i = 0; i < KEYSIZE; i++)
    {
        if((valueToBeWorkedOn >> HALFSIZE - eBox[i]) & 0x01)
        {
            tempValue |= 0x01;
        }
        if(i < KEYSIZE-1)
        {
            tempValue <<= 1;
        }
    }

    valueToBeWorkedOn = tempValue;
    return valueToBeWorkedOn;   
}



uint64_t xorWithSubkey(uint64_t valueToBeWorkedOn, uint64_t subkey)
{
    valueToBeWorkedOn ^= subkey;
    return valueToBeWorkedOn;
}


void seperateValueToBeWorkedOnIntoBytes(uint64_t valueToBeWorkedOn, uint8_t arrayOfValuesToBeWorkedOn[NUMBEROFSBOXES])
{
    int counter = 0;    

    for(int i = KEYSIZE-1; i >= 0 ; i--)
    {
        if((valueToBeWorkedOn >> i) & 0x01)
        {
            arrayOfValuesToBeWorkedOn[counter] |= 0x01;
        }
        if(i%6)
        {
            arrayOfValuesToBeWorkedOn[counter] <<= 1;
        }
        if(i%6 == 0)
        {
            counter += 1;
        }
    }
}


uint8_t individualSBox(uint8_t byteToReduce, const int sBox[ROWSIZE][COLUMNSIZE])
{    
    int row = 0, column = 0;

    if((byteToReduce >> 5) & 0x01)
    {
        row |= 0x01;
    }

    row <<= 1;
    
    if(byteToReduce & 0x01)
    {
        row |= 0x01;
    }

    for(int i = 4; i > 0; i--)
    {
        if((byteToReduce >> i) & 0x01)
        {
            column |= 0x01;
        }
        if(i > 1)
        {
            column <<= 1;
        }
    }

    byteToReduce = sBox[row][column];

    return byteToReduce;
}


void choosingBoxes(uint8_t arrayOfValuesToBeWorkedOn[NUMBEROFSBOXES])
{
    static const int sBoxes[NUMBEROFSBOXES][ROWSIZE][COLUMNSIZE] =
    {
        {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, 
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},

        {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, 
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},

        {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, 
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},

        {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, 
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},

        {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, 
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},

        {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, 
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},

        {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, 
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},

        {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, 
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
    };

    for(int i = 0; i < NUMBEROFSBOXES; i++)
    {
        arrayOfValuesToBeWorkedOn[i] = individualSBox(arrayOfValuesToBeWorkedOn[i], sBoxes[i]);
    }
}


uint64_t reassembleValueToBeWorkedOn(uint64_t valueToBeWorkedOn, uint8_t arrayOfValuesToBeWorkedOn[NUMBEROFSBOXES])
{
    int counter = 0;
    valueToBeWorkedOn = 0;

    for(int i = 0; i < NUMBEROFSBOXES; i++)
    {
        for(int j = 3; j >= 0; j--)
        {
            counter += 1;
            if((arrayOfValuesToBeWorkedOn[i] >> j) & 0x01)
            {
                valueToBeWorkedOn |= 0x01;
            }
            if(counter < HALFSIZE)
            {
                valueToBeWorkedOn <<= 1;
            }
        }
    }

    return valueToBeWorkedOn;
}


uint64_t sBoxSubstitution(uint64_t valueToBeWorkedOn)
{    
    uint8_t arrayOfValuesToBeWorkedOn[NUMBEROFSBOXES] = {0};

    seperateValueToBeWorkedOnIntoBytes(valueToBeWorkedOn, arrayOfValuesToBeWorkedOn);
    choosingBoxes(arrayOfValuesToBeWorkedOn);
    valueToBeWorkedOn = reassembleValueToBeWorkedOn(valueToBeWorkedOn, arrayOfValuesToBeWorkedOn);

    return valueToBeWorkedOn;
}


uint64_t pBoxPermutation(int64_t valueToBeWorkedOn)
{
    int32_t tempValue = 0;

    static const int pBox[HALFSIZE] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

    for(int i = 0; i < HALFSIZE; i++)
    {
        if((valueToBeWorkedOn >> HALFSIZE - pBox[i]) & 0x01)
        {
            tempValue |= 0x01;
        }
        if(i < HALFSIZE-1)
        {
            tempValue <<= 1;
        }
    }

    valueToBeWorkedOn = 0;
    for(int i = HALFSIZE-1; i >= 0; i--)
    {
        if((tempValue >> i) & 0x01)
        {
            valueToBeWorkedOn |= 0x01;
        }
        if(i > 0)
        {
            valueToBeWorkedOn <<= 1;
        }
    }

    return valueToBeWorkedOn;
}


uint64_t xorWithLeftHandSide(uint32_t leftHalf, uint64_t valueToBeWorkedOn)
{
    valueToBeWorkedOn ^= leftHalf;
    return valueToBeWorkedOn;
}


struct HalvesOfText individualRounds(struct HalvesOfText halvesOfText, uint64_t subkey)
{
    uint64_t valueToBeWorkedOn = halvesOfText.rightHalf;

    valueToBeWorkedOn = expansionPermutation(valueToBeWorkedOn);
    valueToBeWorkedOn = xorWithSubkey(valueToBeWorkedOn, subkey);
    valueToBeWorkedOn = sBoxSubstitution(valueToBeWorkedOn);
    valueToBeWorkedOn = pBoxPermutation(valueToBeWorkedOn);
    valueToBeWorkedOn = xorWithLeftHandSide(halvesOfText.leftHalf, valueToBeWorkedOn);

    halvesOfText.leftHalf = halvesOfText.rightHalf;
    valueToBeWorkedOn &= 0x00000000FFFFFFFF;
    halvesOfText.rightHalf = valueToBeWorkedOn;

    return halvesOfText;
}


struct HalvesOfText loopThroughRounds(struct HalvesOfText halvesOfText, uint64_t subkeyArray[])
{
    for(int i = 0; i < KEYARRAYSIZE; i++)
    {
        halvesOfText = individualRounds(halvesOfText, subkeyArray[i]);
    }

    return halvesOfText;
}


uint64_t combineHalves(struct HalvesOfText halvesOfText)
{
    uint64_t ciphertext = 0;

    for(int i = HALFSIZE-1; i >= 0; i--)
    {
        if((halvesOfText.rightHalf >> i) & 1)
        {
            ciphertext ^= 1;
        }
        ciphertext <<= 1;
    }
    
    for(int i = HALFSIZE-1; i >= 0; i--)
    {
        if((halvesOfText.leftHalf >> i) & 1)
        {
            ciphertext ^= 1;
        }
        if(i > 0)
        {
            ciphertext <<= 1;
        }
    }

    return ciphertext;
}


uint64_t desRounds(uint64_t plaintext, uint64_t subkeyArray[KEYARRAYSIZE])
{
    uint64_t ciphertext = 0;
    struct HalvesOfText halvesOfText = {LEFTHALF, RIGHTHALF};

    halvesOfText = splitPlaintextIntoHalves(plaintext, halvesOfText);
    halvesOfText = loopThroughRounds(halvesOfText, subkeyArray);
    ciphertext = combineHalves(halvesOfText);

    return ciphertext;
}