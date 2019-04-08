#pragma once
/** 
 * schnorr zk proof helpers
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <memory>
#include <mcl/bn256.hpp>

using namespace mcl::bn256;

namespace philips {

/**
 * Verify Schnorr over fixed array sizes
 * ------------------------------------------
 */
template <size_t N, size_t M>
bool VerifySchnorrProofG1(const G1& cmt, const G1& left, const Fr& challenge, 
    const typename std::array<Fr,N>::const_iterator& response, 
    const typename std::array<G1,M>::const_iterator& generators) 
{
    G1 right; 
    G1::mul(right,cmt,challenge);
    auto resp = response;  
    auto gen = generators;  
    for(size_t i = 0; i < M ; i++) {
        G1 mult;
        G1::mul(mult,*gen++,*resp++);
        G1::add(right,right,mult);
    }

    return (left == right);
}


/**
 * Verify Schnorr over fixed array sizes of Gt
 */
template <size_t N, size_t M>
bool VerifySchnorrProofGt(const Fp12& cmt, const Fp12& left, const Fr& challenge, 
    const typename std::array<Fr,N>::const_iterator& response, 
    const typename std::array<Fp12,M>::const_iterator& generators) 
{
    Fp12 right; 
    Fp12::pow(right,cmt,challenge);
    auto resp = response;  
    auto gen = generators;  
    for(size_t i = 0; i < M ; i++) {
        if(*resp != (Fr) 0) { // security risk?
            Fp12 exp;
            Fp12::pow(exp,*gen,*resp);
            Fp12::mul(right,right,exp);
        }
        gen++;
        resp++;
    }

    return (left == right);
}

}

