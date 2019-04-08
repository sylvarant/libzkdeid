#pragma once
/** 
 * Accumulator implementation
 * utilizing mcl
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <array>
#include <memory>
#include <mcl/bn256.hpp>

//philips
#include "crypto.hpp"
#include "protocol.hpp"

// CLS based constants
#define PROOF_COUNT     (MESSAGE_COUNT + SPECIAL_COUNT + 4)
#define RESPONSE_COUNT  (MESSAGE_COUNT + SPECIAL_COUNT + 9) 

namespace philips { namespace cls {

using namespace mcl::bn256;

/*--------------------------------------------------------------------------------------
 * Basic CLS signature functionality
 *-------------------------------------------------------------------------------------*/

struct KeyPair {
    G2 pub;
    Fr priv;
};

struct Signature {
    G1 sigma;
    Fr c;
    Fr s;
};

/**
 * Generate a keypair for a trusted party 
 * ------------------------------------------
 */
void KeyGen(const G2& base, KeyPair& kp);

/**
 * Sign a set of record
 * ------------------------------------------
 */
void Sign(const KeyPair& kp, const std::array<G1,GENERATOR_COUNT>& gens, 
    const std::array<std::string,MESSAGE_COUNT>& record, 
    const std::array<G1,SPECIAL_COUNT>& specials, Signature& sig,
    std::array<Fr,MESSAGE_COUNT>* hashes = nullptr); 


/**
 * Verify a given CLS signature without zk
 * ------------------------------------------
 */
bool VerifySignature(const G2& base, const G2& pub, const Signature& sig, 
    const std::array<G1,GENERATOR_COUNT>& generators, 
    const std::array<std::string,MESSAGE_COUNT>& record,
    const std::array<G1,SPECIAL_COUNT>& special);


/*--------------------------------------------------------------------------------------
 * Innovations
 *-------------------------------------------------------------------------------------*/

struct Special {
    Fr u, g;
    G1 hu, hg;

    Special(std::shared_ptr<const Protocol> p)
    {
        u.setRand();
        g.setRand();
        G1::mul(hu,p->uH,u);
        G1::mul(hg,p->gH,g);
    }

    Special() {}
};

struct DeidRecord {
    std::array<std::string,MESSAGE_COUNT> record;
    std::array<Fr,MESSAGE_COUNT> hashvalues;
    std::array<G1,SPECIAL_COUNT> specials; 
    Special sp;
    Signature sig;

    // simplify initialization
    DeidRecord(const KeyPair &kp, const std::array<std::string,MESSAGE_COUNT>& rec,
        std::shared_ptr<const Protocol> p) : record(rec)
    {
        sp = Special(p);   
        specials = { sp.hu, sp.hg };
        Sign(kp,p->generators,record,specials,sig,&hashvalues);
    } 
    DeidRecord() {}
};


// The public part of the zero-knowledge proof 
struct ZkProof { 
    G1 cmtA;
    G1 cmtB;
    G1 cmtPf1;    // counter commit for proof 1
    G1 cmtBc;      // B^c for proving knowledge of mult => rc
    G1 cmtPf2;    // counter commit for proof 2
    G1 cmtPf2b;   // counter commit for H based proof 
    Fp12 cmtPf3;  // counter commit for proof 3
    std::array<G1,SPECIAL_COUNT> specials; // Vals to be proved again further 
    std::array<Fr,RESPONSE_COUNT> response; // response to fiat-shamir
};

struct ZkProofKnowledge : ZkProof {
    Fr r;                           // secret for A
    Fr open;                        // secret for B
    std::array<Fr,SPECIAL_COUNT> s; // secrets for blinding the specials
    Fr pf1a, pf1b;                  // secrets for Dpf1
    Fr pf2a, pf2b, pf2c;            // secrets for Dpf2 & Dpf2b
    std::array<Fr,PROOF_COUNT> pf3; // secrets for Dpf3
};

struct Prover {
    std::unique_ptr<ZkProofKnowledge> proof; 
    std::array<Fp12,PROOF_COUNT> pairings; // precomputed pairings
    DeidRecord drec;     
    TrustLayer trust;
    std::shared_ptr<const Protocol> protocol;

    Prover(const DeidRecord& drec, const TrustLayer& trust, 
        std::shared_ptr<const Protocol> p) :  drec(drec), trust(trust), protocol(p) 
    {
        pairing(pairings[1],protocol->iH,trust.pub); 
        pairing(pairings[2],protocol->iH,protocol->crv.g2);
        for(size_t i = 1; i < GENERATOR_COUNT; i++) {
            pairing(pairings[2+i],protocol->generators[i],protocol->crv.g2); 
        }
        for(size_t i = 0; i < SPECIAL_COUNT; i++) {
            pairing(pairings[2+GENERATOR_COUNT+i],protocol->iH,protocol->crv.g2); 
        }
    }
};

struct Verifier {
    std::array<Fp12,PROOF_COUNT> pairings; // precomputed pairings
    TrustLayer trust;
    std::shared_ptr<const Protocol> protocol;

    Verifier(const TrustLayer& trust, std::shared_ptr<const Protocol> p) : 
        trust(trust), protocol(p)
    {
        pairing(pairings[1],protocol->iH,trust.pub); 
        pairing(pairings[2],protocol->iH,protocol->crv.g2);
        for(size_t i = 1; i < GENERATOR_COUNT; i++) {
            pairing(pairings[2+i],protocol->generators[i],protocol->crv.g2); 
        }
        for(size_t i = 0; i < SPECIAL_COUNT; i++) {
            pairing(pairings[2+GENERATOR_COUNT+i],protocol->iH,protocol->crv.g2); 
        }
    }
};
    

/*--------------------------------------------------------------------------------------
 * CLS Zero Knowledge Proof
 *-------------------------------------------------------------------------------------*/

/**
 * Create a New set of proof secrets & commitments
 * -----------------------------------------------
 */
void NewZkProof(Prover &p, const std::vector<size_t>& disclose);


/**
 * Verify the response to a challenge 
 * -----------------------------------------------
 */
bool VerifyProof(Verifier& v, const ZkProof& proof,
    std::vector<std::pair<std::string,size_t>>& disclosed);

}}

