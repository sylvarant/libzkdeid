#pragma once
/** 
 * Crypto utilities
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <mcl/bn256.hpp>

using namespace mcl::bn256; 

// Global constants
const size_t G1_size = 32;
const size_t Fr_size = 32;
const size_t G2_size = 64;
const size_t Fp12_size = 384;

namespace philips {

/**
 * Generate Generators
 * ------------------------------------------
 */
template<size_t COUNT>
void SetupGenerators(std::array<G1,COUNT>& generators) 
{
    for(size_t i = 0; i < COUNT; i++){
        G1 P;
	    Fp t;
	    t.setRand();
	    mapToG1(P,t);
        generators[i] = P;
    }
}


/**
 * Create commitment: g^a * h^b
 * ------------------------------------------
 */
inline void PedersenCmt(const G1& g, const G1& h, const Fr& a, const Fr& b, G1& cmt) 
{
    G1 right;
    G1::mul(right,h,b);
    G1::mul(cmt,g,a);
    G1::add(cmt,cmt,right);
}

}

