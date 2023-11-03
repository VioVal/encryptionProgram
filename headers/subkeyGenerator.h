#ifndef SUBKEYGENERATOR_H
#define SUBKEYGENERATOR_H

#include <stdint.h>

#define LENGTHOFARRAY 16
#define ORIGINALKEYLENGTH 64
#define LENGTHOFREDUCEDKEY 56
#define HALFOFKEY 28
#define LENGTHOFCOMPRESSEDKEY 48
#define BITTOBEDROPPED 8
#define LEFTHALF 0
#define RIGHTHALF 0
#define LEFTHALVES {0}
#define RIGHTHALVES {0}

struct KeyHalves
{
    uint32_t leftHalf;
    uint32_t rightHalf;
};


struct ArrayOfHalves
{
    uint32_t leftHalves[LENGTHOFARRAY];
    uint32_t rightHalves[LENGTHOFARRAY];
};

uint64_t reduceKeyTo56Bits(uint64_t key);
struct KeyHalves halveKey(uint64_t key, struct KeyHalves keyHalves);
uint32_t circularShift(uint32_t bits, int numberOfRounds);
struct ArrayOfHalves bitshiftHalvesAndProduceArrayOfKeys(struct KeyHalves keyHalves, struct ArrayOfHalves arrayOfHalves);
void recombineKeys(struct ArrayOfHalves arrayOfHalves, uint64_t transformedKeyArray[LENGTHOFARRAY]);
void pick48BitsToProduceArrayOfSubkeys(uint64_t transformedKeyArray[LENGTHOFARRAY]);
void generateSubkeysFromKey(uint64_t key, uint64_t transformedKeyArray[LENGTHOFARRAY]);

#endif