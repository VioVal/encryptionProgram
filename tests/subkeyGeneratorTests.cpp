#include <gtest/gtest.h>
extern "C"
{
    #include "../headers/subkeyGenerator.h"
}


TEST(subkeyGeneratorTests, ReduceKeyTo56BitsTest)
{
    EXPECT_EQ(reduceKeyTo56Bits(16643699702251543506ul), 65290330141841129ul);
}


TEST(subkeyGeneratorTests, halveKeyTest)
{
    struct KeyHalves testKeyHalves = {0, 0};
    struct KeyHalves correctKeyHalves = {243225433, 123688681};
    testKeyHalves = halveKey(65290330141841129ul, testKeyHalves);
    EXPECT_EQ(testKeyHalves.leftHalf, correctKeyHalves.leftHalf);
    EXPECT_EQ(testKeyHalves.rightHalf, correctKeyHalves.rightHalf);
}


TEST(subkeyGeneratorTests, circularShiftTest)
{
    EXPECT_EQ(circularShift(243225433, 1), 486450867);
    EXPECT_EQ(circularShift(972901735, 2), 3891606942);
    uint32_t ans = circularShift(972901735, 28);
    ans &= 0x0FFFFFFF;
    uint32_t ans2 = 972901735;
    ans2 &= 0x0FFFFFFF;
    EXPECT_EQ(ans, ans2);
}


TEST(subkeyGeneratorTests, circularShiftMaxRounds)
//testing that the circular shift can do a complete shift. The answers are masked because the first 4 bits are junk.
{
    uint32_t expectedValue = 972901735;
    expectedValue &= 0x0FFFFFFF;
    uint32_t currentValue = circularShift(972901735, 28);
    currentValue &= 0x0FFFFFFF;
    EXPECT_EQ(currentValue, expectedValue);
}


struct ArrayOfHalves correctArrayOfHalves = {{486450867, 972901735, 3891606942, 2681525881, 2136168935, 4249708447, 4113931903, 3570825725, 
    2846684154, 2796802026, 2597273513, 1799159462, 2901670554, 3016747627, 3477055916, 2659144537}, 

    {247377362, 494754725, 1979018903, 3621108317, 1599531381, 2103158231, 4117665631, 3585760637, 
    2876553978, 2916281322, 3075190699, 3710828205, 1958410935, 3538676445, 1269803892, 2539607785}};


TEST(subkeyGeneratorTests, arraysOfHalvesTest)
{   
    struct KeyHalves keyHalves = {243225433, 123688681};
    uint32_t initialArrayOfLeftHalves[16] = {0};
    struct ArrayOfHalves testArrayOfHalves = {{0}, {0}};

    testArrayOfHalves = bitshiftHalvesAndProduceArrayOfKeys(keyHalves, testArrayOfHalves);

    EXPECT_EQ(memcmp(testArrayOfHalves.leftHalves, correctArrayOfHalves.leftHalves, sizeof(uint32_t) * 16), 0);
    EXPECT_EQ(memcmp(testArrayOfHalves.rightHalves, correctArrayOfHalves.rightHalves, sizeof(uint32_t) * 16), 0);
}


uint64_t correctTransformedKeyArray[16] = {58523066514189778, 44988538990451621, 35838967617515159, 71298276432132701, 
        69020324151617909, 59908514492687831, 23461275856967519, 21787509389942141, 
        43575018779884282, 30184887043681258, 48681953599926187, 50612626592284333, 
        58335318024846007, 17168490522471133, 68673962089884532, 65290330141841129};


TEST(subkeyGeneratorTests, recombineKeysTest)
{
    uint64_t testTransformedKeyArray[16] = {0};

    recombineKeys(correctArrayOfHalves, testTransformedKeyArray);

    EXPECT_EQ(memcmp(correctTransformedKeyArray, testTransformedKeyArray, sizeof(uint64_t) * 16), 0);
}


uint64_t arrayOfSubkeys[16] = {68154083931694, 225794418531735, 25237182703029, 175223457147341, 
    258848785093535, 169288515655599, 89197811473385, 270449348115325, 
    172336618458319, 253086846088927, 123137328928737, 222917302079331, 
    278066850885396, 254945147840472, 117355014910475, 205980008419325};


TEST(subkeyGeneratorTests, pick48BitsToProduceArrayOfSubkeysTest)
{
    pick48BitsToProduceArrayOfSubkeys(correctTransformedKeyArray);

    EXPECT_EQ(memcmp(correctTransformedKeyArray, arrayOfSubkeys, sizeof(uint64_t) * 16), 0);
}


TEST(subkeyGeneratorTests, generateSubkeysFromKeyTest)
{
    uint64_t key = 16643699702251543506ul;
    uint64_t initialArrayOfSubkeys[16] = {0};

    generateSubkeysFromKey(key, initialArrayOfSubkeys);

    EXPECT_EQ(memcmp(initialArrayOfSubkeys, arrayOfSubkeys, sizeof(uint64_t) * 16), 0);
}