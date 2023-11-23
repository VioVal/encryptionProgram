#include <gtest/gtest.h>
extern "C"
{
    #include "../headers/errorHandling.h"
}

TEST(errorHandlingTests, errorHandlerTest)
{
    ErrorMessage errorMessage = test;
    ASSERT_DEATH(errorHandler(errorMessage), "");
}