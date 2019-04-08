/** 
 * Test some crypto functions
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <iostream>
#include <gtest/gtest.h>

#include <mcl/bn256.hpp>

#include <crypto.hpp>

using namespace philips;
using namespace mcl::bn256;


TEST(Crypto,FiatShamir) 
{
    G1 g1;
    G2 g2;
    Fp12 base,a,b,c; 
    Fr rand, fsc, fsc2, fsc3;

    hashAndMapToG1(g1,"abc");
    hashAndMapToG2(g2,"abc");
    pairing(base,g1,g2);

    rand.setRand();
    Fp12::pow(a,base,rand);
    rand.setRand();
    Fp12::pow(b,base,rand);
    rand.setRand();
    Fp12::pow(c,base,rand);

    // go once
    FiatShamir<Fp12>(a,b,c,fsc);
    
    FiatShamir<Fp12>(a,b,c,fsc2);

    ASSERT_EQ(fsc,fsc2); // Check consistency

    // random again
    rand.setRand();
    Fp12::pow(a,base,rand);
    rand.setRand();
    Fp12::pow(b,base,rand);
    rand.setRand();
    Fp12::pow(c,base,rand);

    FiatShamir<Fp12>(a,b,c,fsc3);
    ASSERT_NE(fsc,fsc3);
}

