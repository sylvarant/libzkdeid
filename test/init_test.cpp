/**
 * @file init_test.cpp
 * main function for tests
 */

#include "gtest/gtest.h"
#include <mcl/bn256.hpp>
using namespace mcl::bn256;

using namespace testing;

int main(int argc, char **argv) {
	initPairing();
    InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

