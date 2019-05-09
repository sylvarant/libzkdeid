#pragma once
/** 
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <array>
#include <mcl/bn256.hpp>

#include "crypto.hpp"


#ifndef MESSAGE_COUNT
#define MESSAGE_COUNT   50
#endif
// TODO remove
#ifndef SPECIAL_COUNT 
#define SPECIAL_COUNT   2
#endif
// Dependent constants
#define GENERATOR_COUNT (MESSAGE_COUNT + 2)

namespace philips {

using namespace mcl::bn256; 

/*--------------------------------------------------------------------------------------
 * Protocol definitions
 *-------------------------------------------------------------------------------------*/

struct Curve {
    G1 g1;
    G2 g2;
    Fp12 e;

    Curve() {
	    mapToG1(g1, 1); 
	    mapToG2(g2, 1);
        pairing(e,g1,g2);
    }
};

struct Protocol {
    G1 uH;
    G1 lH;
    G1 iH; 
    Curve crv;
    std::array<G1,GENERATOR_COUNT> generators; 
    Protocol() {
        hashAndMapToG1(iH,"uniqueH");
        hashAndMapToG1(lH,"lambdaH");
        hashAndMapToG1(uH,"issuerH");
        SetupGenerators(generators); 
    }
};

struct TrustLayer {
    G2 pub;    
};

}

