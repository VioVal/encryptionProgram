#include <gtest/gtest.h>
extern "C"
{
    #include "../headers/errorHandling.h"
}

TEST(errorHandlingTests, errorHandlerTest)
{
    errorMessage = test;
    ASSERT_DEATH(errorHandler(NULL, NULL), "");
}