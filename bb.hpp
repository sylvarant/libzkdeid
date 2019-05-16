#pragma once
/** 
 * Boneh Boyen signatures 
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <memory>

#include <mcl/bn256.hpp>

namespace philips { namespace bb {

using namespace mcl::bn256;

// templated to enable use in either G1 or G2
template <typename T, typename Z>
struct KeyPair {
    T pub; 
    Fr priv;
    T pubgen;
    Z siggen;

    // Random pair for given base
    KeyPair(const T& pubgen, const Z& siggen) : pubgen(pubgen), siggen(siggen) {
        priv.setRand();
        T::mul(pub,pubgen,priv);
    }

    KeyPair(const T& pub, const Fr& priv, const T& p, const Z& s): pub(pub), priv(priv), 
        pubgen(p), siggen(s) {}
};


/*--------------------------------------------------------------------------------------
 * Basic Boneh Boyen signature functionality
 *-------------------------------------------------------------------------------------*/

/**
 * Sign a message BB style
 */
template <typename T, typename Z>
void Sign(const KeyPair<T,Z>& kp, const std::string& message, Z& sig)
{ 
    Fr inv,sum,hash;
    hash.setHashOf(message);
    Fr::add(sum,kp.priv,hash);
    Fr::inv(inv,sum);

    Z::mul(sig,kp.siggen,inv);
}


/**
 * Sign a number BB style
 */
template <typename T, typename Z>
void Sign(const KeyPair<T,Z>& kp, const Fr& num, Z& sig)
{ 
    Fr inv,sum;
    Fr::add(sum,kp.priv,num);
    Fr::inv(inv,sum);

    Z::mul(sig,kp.siggen,inv);
}


/**
 * doubleSign
 */
template <typename T, typename Z>
void DoubleSign(const KeyPair<T,Z>& kp, const std::string& message, Fr sec, Z& sig)
{ 
    Fr inv,sum,hash;
    hash.setHashOf(message);
    Fr::add(sum,kp.priv,hash);
    Fr::add(sum,sum,sec);
    Fr::inv(inv,sum);

    Z::mul(sig,kp.siggen,inv);
}


/**
 * Verify a given BB signature
 * ------------------------------------------
 */
template <typename T, typename Z>
bool Verify(const T& pubgen, const Z& siggen, const T& pub,Fp12 (*p)(T,Z), const Z& sig, 
    const std::string& message)
{
    T gm;
    Fr hash;
    Fp12 left,right;
    left = p(pubgen,siggen);
    hash.setHashOf(message);
    T::mul(gm,pubgen,hash);
    T::add(gm,gm,pub);
    right = p(gm,sig);
    return (right == left);
}

}}

