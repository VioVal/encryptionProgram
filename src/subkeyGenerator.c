#include <stdint.h>
#include "../headers/subkeyGenerator.h"


uint64_t reduceKeyTo56Bits(uint64_t key)
{
    uint64_t tempKey = 0;
    int counter = 0;

    for(int i = ORIGINALKEYLENGTH - 1; i >= 0; i--)
    {
        counter += 1;
        if(counter % BITTOBEDROPPED)
        {
            if((key >> i) & 0x01)
            {
                tempKey |= 0x01;
            }
            if(i > 1)
            {
                tempKey <<= 1;
            }
        }
    }

    key = tempKey;
    return key;
}


struct KeyHalves halveKey(uint64_t key, struct KeyHalves keyHalves)
{
    for(int i = LENGTHOFREDUCEDKEY - 1; i >= HALFOFKEY; i--)
    {
        if((key >> i) & 0x01)
        {
            keyHalves.leftHalf |= 0x01;
        } 
        if(i > HALFOFKEY)
        {
            keyHalves.leftHalf <<= 1;
        }
    }

    for(int i = HALFOFKEY - 1; i >= 0; i--)
    {
        if((key >> i) & 0x01)
        {
            keyHalves.rightHalf |= 0x01;
        }
        if(i > 0)
        {
            keyHalves.rightHalf <<= 1;
        }
    }

    return keyHalves;
}


uint32_t circularShift(uint32_t bits, int numberOfRounds)
{
    for(int i = 0; i < numberOfRounds; i++)
    {
        bits <<= 1;
        if((bits >> HALFOFKEY) & 0x01)
        {
            bits |= 0x01;
        }
    }
    return bits;
}


struct ArrayOfHalves bitshiftHalvesAndProduceArrayOfKeys(struct KeyHalves keyHalves, struct ArrayOfHalves arrayOfHalves)
{
    const int bitsShiftedPerRound[LENGTHOFARRAY] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    arrayOfHalves.leftHalves[0] = circularShift(keyHalves.leftHalf, 1);
    arrayOfHalves.rightHalves[0] = circularShift(keyHalves.rightHalf, 1);

    for(int i = 1; i < LENGTHOFARRAY; i++)
    {
        arrayOfHalves.leftHalves[i] = circularShift(arrayOfHalves.leftHalves[i-1], bitsShiftedPerRound[i]);
        arrayOfHalves.rightHalves[i] = circularShift(arrayOfHalves.rightHalves[i-1], bitsShiftedPerRound[i]);
    }

    return arrayOfHalves;
}


void recombineKeys(struct ArrayOfHalves arrayOfHalves, uint64_t transformedKeyArray[LENGTHOFARRAY])
{
    for(int i = 0; i < LENGTHOFARRAY; i++)
    {
        for(int j = HALFOFKEY - 1; j >= 0; j--)
        {
            if((arrayOfHalves.leftHalves[i] >> j) & 0x01)
            {
                transformedKeyArray[i] |= 0x01;
            }
            transformedKeyArray[i] <<= 1;
        }

        for(int k = HALFOFKEY - 1; k >= 0; k--)
        {
            if((arrayOfHalves.rightHalves[i] >> k) & 0x01)
            {
                transformedKeyArray[i] |= 1;
            }
            if(k > 0)
            {
                transformedKeyArray[i] <<= 1;
            }
        }
    }
}


void pick48BitsToProduceArrayOfSubkeys(uint64_t transformedKeyArray[LENGTHOFARRAY])
{
    uint64_t temporaryArray[LENGTHOFARRAY] = {0};
    
    const int compressionPermutation[LENGTHOFCOMPRESSEDKEY] = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

    for(int i = 0; i < LENGTHOFARRAY; i++)
    {
        for(int j = 0; j < LENGTHOFCOMPRESSEDKEY; j++)
        {
            if((transformedKeyArray[i] >> (LENGTHOFREDUCEDKEY - compressionPermutation[j])) & 0x01)
            {
                temporaryArray[i] ^= 1;
            }
            if(j < LENGTHOFCOMPRESSEDKEY - 1)
            {
                temporaryArray[i] <<= 1;
            }
        }
    }

    for(int i = 0; i < LENGTHOFARRAY; i++)
    {
        transformedKeyArray[i] = temporaryArray[i];
    }
}


void generateSubkeysFromKey(uint64_t key, uint64_t transformedKeyArray[LENGTHOFARRAY])
{
    struct KeyHalves keyHalves = {LEFTHALF, RIGHTHALF};
    struct ArrayOfHalves arrayOfHalves = {LEFTHALVES, RIGHTHALVES};

    key = reduceKeyTo56Bits(key);
    keyHalves = halveKey(key, keyHalves);
    arrayOfHalves = bitshiftHalvesAndProduceArrayOfKeys(keyHalves, arrayOfHalves);
    recombineKeys(arrayOfHalves, transformedKeyArray);
    pick48BitsToProduceArrayOfSubkeys(transformedKeyArray);
}