/** 
 * Test our BB implementation
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <iostream>
#include <gtest/gtest.h>

#include <mcl/bn256.hpp>

#include <crypto.hpp>
#include <protocol.hpp>
#include <bb.hpp>

using namespace philips;
using namespace philips::bb;
using namespace mcl::bn256;

// Test signatures
TEST(BbTest,SigninG1) {

    // setup 
    Curve crv;

    // generate keypair for issuer & create trustchain info
    KeyPair<G2,G1> kp(crv.g2,crv.g1);
    std::string message = "not guilty";

    // Sign a message
    G1 sig;
    Sign(kp,message,sig);
	std::cout << "Signature sigma: " << sig << std::endl;

    // Test Signature Verification
    auto p = [](G2 a,G1 b){ 
        Fp12 pair; 
        pairing(pair,b,a);
        return pair; 
    };
    bool r = Verify<G2,G1>(crv.g2,crv.g1,kp.pub,p,sig,message);
    ASSERT_EQ(r,1); 
    r = Verify<G2,G1>(crv.g2,crv.g1,kp.pub,p,sig,"guilty");
    ASSERT_EQ(r,0); 
}


