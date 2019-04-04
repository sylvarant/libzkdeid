/** 
 * CLS signature & zk proof
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

// philips 
#include "cls.hpp"
#include "schnorr.hpp"

using namespace mcl::bn256;

using namespace philips;
using namespace philips::cls;

/*--------------------------------------------------------------------------------------
 * Setup & Infrastructure
 *-------------------------------------------------------------------------------------*/

/**
 * Generate a keypair for a trusted party
 * ------------------------------------------
 */
void philips::cls::KeyGen(const G2& base, KeyPair& kp) 
{
    kp.priv.setRand(); 
    G2::mul(kp.pub,base,kp.priv); // pub =  base ^ priv
}


/*--------------------------------------------------------------------------------------
 * Basic CLS signature functionality
 *-------------------------------------------------------------------------------------*/

/**
 * Sign a set of record
 * ------------------------------------------
 */
void philips::cls::Sign(const KeyPair& kp, const std::array<G1,GENERATOR_COUNT>& gens, 
    const std::array<std::string,MESSAGE_COUNT>& record,     
    const std::array<G1,SPECIAL_COUNT>& specials, Signature& sig,
    std::array<Fr,MESSAGE_COUNT>* hashes) 
{ 
    // random members
    sig.s.setRand();
    sig.c.setRand();

    Fr inv,sum;
    Fr::add(sum,kp.priv,sig.c);
    Fr::inv(inv,sum);

    G1 last, mult;
    int i = 0;
    mult = gens[0]; 
    for(auto const& value: record) {
        Fr mp;
        G1 hm;
        mp.setHashOf(value);
        if(hashes) { 
            (*hashes)[i] = mp;
        }
        G1::mul(hm,gens[++i],mp);
        G1::add(mult,mult,hm);
    }
    for(auto const& gval: specials) {
        G1::add(mult,mult,gval);
    }
    G1::mul(last,gens.at(++i),sig.s);  
    G1::add(mult,mult,last); 
    G1::mul(sig.sigma,mult,inv);
}


/**
 * Verify a given CLS signature without zk
 * ------------------------------------------
 */
bool philips::cls::VerifySignature(const G2& base, const G2& pub, const Signature& sig, 
    const std::array<G1,GENERATOR_COUNT>& generators, 
    const std::array<std::string,MESSAGE_COUNT>& record,
    const std::array<G1,SPECIAL_COUNT>& specials) 
{
    // you need to compute 2 pairings
    Fp12 left, right; 
    G2 yhc;

    // pair(sigma, y+G2.base^c) 
    G2::mul(yhc,base,sig.c);  
    G2::add(yhc,yhc,pub);
    pairing(left,sig.sigma,yhc);

    // pair(hi^m,G2.base)
    G1 last, mult;
    int i = 0;
    mult = generators.at(0); 
    for(auto const& value: record) {
        Fr mp;
        G1 hm;
        mp.setHashOf(value);
        G1::mul(hm,generators[++i],mp);
        G1::add(mult,mult,hm);
    }
    for(auto const& gval: specials) {
        G1::add(mult,mult,gval);
    }
    G1::mul(last,generators[++i],sig.s);  
    G1::add(mult,mult,last); 
    pairing(right,mult,base);
    
    // Gt1 == Gt2
    return left == right; 
}


/*--------------------------------------------------------------------------------------
 * CLS Zero Knowledge Proof
 *-------------------------------------------------------------------------------------*/

/**
 * Create a New set of proof secrets & commitments
 * -----------------------------------------------
 */
void philips::cls::NewZkProof(Prover& p) 
{
    p.proof.reset(new(ZkProofKnowledge));

    // random factors
    p.proof->r.setRand();
    p.proof->open.setRand();
    p.proof->pf1a.setRand();
    p.proof->pf1b.setRand();
    p.proof->pf2a.setRand();
    p.proof->pf2b.setRand();
    p.proof->pf2c.setRand();
    for(Fr pfi: p.proof->pf3) {
       pfi.setRand(); 
    }
    for(Fr sp : p.proof->s) {
        sp.setRand();
    }

    // commitment time
    G1 sigblind;
    PedersenCmt(p.protocol->crv.g1,p.protocol->iH,p.proof->r,p.proof->open,
        p.proof->cmtB);
    G1::mul(sigblind,p.protocol->iH,p.proof->r);
    G1::add(p.proof->cmtA,sigblind,p.drec.sig.sigma);
    PedersenCmt(p.protocol->crv.g1,p.protocol->iH,p.proof->pf1a,p.proof->pf1b,
        p.proof->cmtPf1);
    G1::mul(p.proof->cmtBc,p.proof->cmtB,p.drec.sig.c);
    G1::mul(p.proof->cmtPf2,p.proof->cmtB,p.proof->pf2a);
    PedersenCmt(p.protocol->crv.g1,p.protocol->iH,p.proof->pf2b,p.proof->pf2c,
        p.proof->cmtPf2b);

    // pf3 is complicated
    pairing(p.pairings[0],p.proof->cmtA,p.protocol->crv.g2); 
    Fp12::pow(p.proof->cmtPf3,p.pairings[0],p.proof->pf3[0]);
    for(size_t i =1; i < PROOF_COUNT; i++) {
        Fp12 exp;
        Fp12::pow(exp,p.pairings[i],p.proof->pf3[i]);
        Fp12::mul(p.proof->cmtPf3,p.proof->cmtPf3,exp);
    }

    // blind the special values
    for(size_t i = 0; i < SPECIAL_COUNT; i++) {
        G1 blind;
        G1::mul(blind,p.protocol->iH,p.proof->s[i]);
        G1::add(p.proof->specials[i],p.drec.specials[i],blind);
    }
}


/**
 * Respond to a challenge from the verifier schnorr-style
 * ------------------------------------------------------
 */
void philips::cls::RespondToChallenge(const Prover& p, const Fr& challenge, 
    std::array<Fr,RESPONSE_COUNT>& response)
{
    // the randoms used to populate the schnorr style commits
    std::array<Fr,RESPONSE_COUNT> randoms = {p.proof->pf1a, p.proof->pf1b, p.proof->pf2a,
        p.proof->pf2b, p.proof->pf2c};
    std::copy(p.proof->pf3.begin(),p.proof->pf3.end(),randoms.begin()+5);

    // our actual secrets
    std::array<Fr,RESPONSE_COUNT> secrets = {p.proof->r,p.proof->open,p.drec.sig.c};
    Fr::mul(secrets[3],p.drec.sig.c,p.proof->r); 
    Fr::mul(secrets[4],p.drec.sig.c,p.proof->open); 
    secrets[5] = p.drec.sig.c;
    Fr::neg(secrets[6],p.proof->r);
    Fr::neg(secrets[7],secrets[3]);
    for(size_t i = 0; i < MESSAGE_COUNT; i++) {
        Fr::neg(secrets[8+i],p.drec.hashvalues[i]);
    }
    Fr::neg(secrets[RESPONSE_COUNT-SPECIAL_COUNT-1],p.drec.sig.s);
    for(size_t i = 0; i < SPECIAL_COUNT; i++) {
        secrets[RESPONSE_COUNT - SPECIAL_COUNT + i] = p.proof->s[i];
    }

    Fr mult;
    for(size_t i = 0; i < RESPONSE_COUNT; i++) {
        Fr::mul(mult,secrets[i],challenge);
        Fr::sub(response[i],randoms[i],mult);
    }
}


/**
 * The verifier process the ZkProof by precomputing 
 * -----------------------------------------------
 */
void philips::cls::ProcessZkProof(const ZkProof zk, Verifier& v) 
{
    Fp12 newleft, newtop;
    G1 addtop;

    // set left bottom
    pairing(v.leftbottom,zk.cmtA,v.trust.pub);

    // adjust top 
    if(SPECIAL_COUNT > 0) {
        addtop.clear();
        for(G1 sp: zk.specials) {
            G1::add(addtop,addtop,sp);
        }
        pairing(newtop,addtop,v.protocol->crv.g2);
        Fp12::mul(v.lefttop,newtop,v.lefttop);
    }

    // divide & go
    Fp12::div(newleft,v.lefttop,v.leftbottom);
    v.left.reset(new(Fp12)(newleft));
    pairing(v.pairings[0],zk.cmtA,v.protocol->crv.g2);
    v.proof.reset(new(ZkProof)(zk));
}


/**
 * Verify the response to a challenge 
 * -----------------------------------------------
 */
bool philips::cls::VerifyProof(const Verifier& v, const Fr& challenge, 
    const std::array<Fr,RESPONSE_COUNT>& response,
    const std::vector<std::pair<std::string,size_t>>* disclosed)
{
    // sanity checks
    if(v.proof == nullptr || v.left == nullptr) return false; 

    // simplified calling
    const std::array<G1,2> pf1gens = {v.protocol->crv.g1,v.protocol->iH};
    const std::array<G1,1> pf2gens = {v.proof->cmtB};

    // check proof 1
    if (!VerifySchnorrProofG1<RESPONSE_COUNT,2>(v.proof->cmtB,v.proof->cmtPf1,
    challenge,response.begin(),pf1gens.begin())) {
        return false;
    }

    // check proof 2a
    if (!VerifySchnorrProofG1<RESPONSE_COUNT,1>(v.proof->cmtBc,v.proof->cmtPf2,
    challenge,(response.begin() + 2),pf2gens.begin())) {
        return false;
    }

    // check proof 2b :: Note minimal perf impact
    if (!VerifySchnorrProofG1<RESPONSE_COUNT,2>(v.proof->cmtBc,v.proof->cmtPf2b,
    challenge,(response.begin() + 3),pf1gens.begin())) {
        return false;
    }

    // Recompute left-side hand if there are disclosures
    Fp12 lefthand;
    if(disclosed) {
        Fp12 disclp;
        G1 multi;
        for(auto pair: (*disclosed)) {
            G1 tmp;
            Fr hash;
            hash.setHashOf(pair.first);
            G1::mul(tmp,v.protocol->generators[pair.second],hash);
            G1::add(multi,multi,tmp);
        }
        pairing(disclp,multi,v.protocol->crv.g2);  
        Fp12::mul(disclp,v.lefttop,disclp);
        Fp12::div(disclp,disclp,v.leftbottom);
        lefthand = disclp;
    } else {
        lefthand = *(v.left);
    }

    // check proof 3 :: EXPENSIVE
    if (!VerifySchnorrProofGt<RESPONSE_COUNT,PROOF_COUNT>(lefthand,v.proof->cmtPf3,
    challenge,(response.begin() + 5),v.pairings.begin())) {
        return false;
    } 

    return true;
}

