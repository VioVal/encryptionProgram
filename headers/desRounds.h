#ifndef DESROUNDS_H
#define DESROUNDS_H

#include <stdint.h>

#define TEXTSIZE 64
#define HALFSIZE 32
#define KEYSIZE 48
#define KEYARRAYSIZE 16
#define NUMBEROFSBOXES 8
#define ROWSIZE 4
#define COLUMNSIZE 16
#define LEFTHALF 0
#define RIGHTHALF 0

struct HalvesOfText
{
    uint32_t leftHalf;
    uint32_t rightHalf;
};

struct HalvesOfText splitPlaintextIntoHalves(uint64_t plaintext, struct HalvesOfText halvesOfText);
uint64_t expansionPermutation(uint64_t valueToBeWorkedOn);
uint64_t xorWithSubkey(uint64_t valueToBeWorkedOn, uint64_t subkey);
uint64_t sBoxSubstitution(uint64_t valueToBeWorkedOn);
uint64_t pBoxPermutation(int64_t valueToBeWorkedOn);
uint64_t xorWithLeftHandSide(uint32_t leftHalf, uint64_t valueToBeWorkedOn);
struct HalvesOfText individualRounds(struct HalvesOfText halvesOfText, uint64_t subkey);
struct HalvesOfText loopThroughRounds(struct HalvesOfText halvesOfText, uint64_t subkeyArray[]);
uint64_t combineHalves(struct HalvesOfText halvesOfText);
uint64_t desRounds(uint64_t plaintext, uint64_t subkeyArray[KEYARRAYSIZE]);

#endif