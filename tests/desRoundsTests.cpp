#include <gtest/gtest.h>
extern "C"
{
    #include "../headers/desRounds.h"
}


//Here I'm using the values from the second block. The first block is the IV and as such the first 32 bits is empty
uint64_t correctPlainText = 12728426358741245764ul;
uint64_t correctCipherText = 6605293619756645587;
uint64_t correctArrayOfSubkeys[16] = {68154083931694, 225794418531735, 25237182703029, 175223457147341, 
    258848785093535, 169288515655599, 89197811473385, 270449348115325, 
    172336618458319, 253086846088927, 123137328928737, 222917302079331, 
    278066850885396, 254945147840472, 117355014910475, 205980008419325};


TEST(desRoundsTests, splitPlaintextIntoHalvesTests)
{   
    //Elena: One test one assertion, make sure that the test name is self explanatory. e.g. if doing boundaries analysis specify what is upper boundary, lower boundary.
    // Elena: Correct = expected
    struct HalvesOfText correctHalvesOfText = {2963567701, 3464339268};
    struct HalvesOfText testHalvesOfText = {0, 0};

    // Elena: returned value should be named current value
    testHalvesOfText = splitPlaintextIntoHalves(correctPlainText, testHalvesOfText);

    EXPECT_EQ(correctHalvesOfText.leftHalf, testHalvesOfText.leftHalf);
    EXPECT_EQ(correctHalvesOfText.rightHalf, testHalvesOfText.rightHalf);
}


TEST(desRoundsTests, expansionPermutationTests)
{
    uint64_t correctValue = 111892417735177;
    uint64_t testValue = 3464339268;

    testValue = expansionPermutation(testValue);

    EXPECT_EQ(correctValue, testValue);
}


TEST(desRoundsTests, xorWithSubkeyTests)
{
    uint64_t correctValue = 97030294314023;
    uint64_t testValue = 111892417735177;
    uint64_t subkey = 68154083931694;

    testValue = xorWithSubkey(testValue, subkey);

    EXPECT_EQ(correctValue, testValue);
}


TEST(desRoundsTests, sBoxSubstitutionTests)
{
    uint64_t correctValue = 3447349415;
    uint64_t testValue = 97030294314023;

    testValue = sBoxSubstitution(testValue);

    EXPECT_EQ(correctValue, testValue);
}


TEST(desRoundsTests, pBoxPermutationTests)
{
    uint64_t correctValue = 80727285;
    uint64_t testValue = 3447349415;

    testValue = pBoxPermutation(testValue);

    EXPECT_EQ(correctValue, testValue);
}


TEST(desRoundsTests, xorWithLeftHandSide)
{
    uint64_t correctValue = 3026958496;
    uint64_t testValue = 80727285;
    uint64_t leftHalf = 2963567701;

    testValue = xorWithLeftHandSide(leftHalf, testValue);

    EXPECT_EQ(correctValue, testValue);
}


TEST(desRoundsTests, individualRoundsTests)
{   

    struct HalvesOfText correctHalvesOfText = {3464339268, 3026958496};
    struct HalvesOfText testHalvesOfText = {2963567701, 3464339268};

    uint64_t subkey = 68154083931694;

    testHalvesOfText = individualRounds(testHalvesOfText, subkey);

    EXPECT_EQ(correctHalvesOfText.leftHalf, testHalvesOfText.leftHalf);
    EXPECT_EQ(correctHalvesOfText.rightHalf, testHalvesOfText.rightHalf);
}


TEST(desRoundsTests, loopThroughRoundsTests)
{
    struct HalvesOfText correctHalvesOfText = {46120147, 1537914765};
    struct HalvesOfText testHalvesOfText = {2963567701, 3464339268};

    testHalvesOfText = loopThroughRounds(testHalvesOfText, correctArrayOfSubkeys);

    EXPECT_EQ(correctHalvesOfText.leftHalf, testHalvesOfText.leftHalf);
    EXPECT_EQ(correctHalvesOfText.rightHalf, testHalvesOfText.rightHalf);
}


TEST(desRoundsTests, combineHalvesTests)
{
    uint64_t initialCipherText = 0;
    struct HalvesOfText halvesOfText = {46120147, 1537914765};

    initialCipherText = combineHalves(halvesOfText);

    EXPECT_EQ(initialCipherText, correctCipherText);
}