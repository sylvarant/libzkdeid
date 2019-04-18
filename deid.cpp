/** 
 * Deid by means of CLS
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

// philips 
#include "deid.hpp"
#include "schnorr.hpp"

#include <iostream>

using namespace mcl::bn256;

using namespace philips;

/*--------------------------------------------------------------------------------------
 * Setup & Infrastructure
 *-------------------------------------------------------------------------------------*/

/**
 * Generate a keypair for a trusted party
 * ------------------------------------------
 */
void philips::KeyGen(const G2& base, KeyPair& kp) 
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
void philips::Sign(const KeyPair& kp, const std::shared_ptr<const Protocol>& p, 
    const std::array<std::string,MESSAGE_COUNT>& record, Signature& sig,
    std::array<Fr,MESSAGE_COUNT>* hashes) 
{ 
    // random members
    sig.s.setRand();
    sig.c.setRand();
    sig.u.setRand();
    sig.l.setRand();

    Fr inv,sum;
    Fr::add(sum,kp.priv,sig.c);
    Fr::inv(inv,sum);

    G1 last, mult;
    int i = 0;
    mult = p->generators[0]; 
    for(auto const& value: record) {
        Fr mp;
        G1 hm;
        mp.setHashOf(value);
        if(hashes) { 
            (*hashes)[i] = mp;
        }
        G1::mul(hm,p->generators[++i],mp);
        G1::add(mult,mult,hm);
    }
    // special values
    G1 hu;
    G1 hl;
    G1::mul(hu,p->uH,sig.u);
    G1::add(mult,mult,hu);
    G1::mul(hl,p->lH,sig.l);
    G1::add(mult,mult,hl);
    // last one
    G1::mul(last,p->generators[++i],sig.s);  
    G1::add(mult,mult,last); 
    G1::mul(sig.sigma,mult,inv);
}


/**
 * Verify a given CLS signature without zk
 * ------------------------------------------
 */
bool philips::VerifySignature(const G2& base, const G2& pub, const Signature& sig, 
    const std::shared_ptr<const Protocol>& p, 
    const std::array<std::string,MESSAGE_COUNT>& record) 
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
    mult = p->generators[0]; 
    for(auto const& value: record) {
        Fr mp;
        G1 hm;
        mp.setHashOf(value);
        G1::mul(hm,p->generators[++i],mp);
        G1::add(mult,mult,hm);
    }

    // special values
    G1 hu;
    G1 hl;
    G1::mul(hu,p->uH,sig.u);
    G1::add(mult,mult,hu);
    G1::mul(hl,p->lH,sig.l);
    G1::add(mult,mult,hl);

    G1::mul(last,p->generators[++i],sig.s);  
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
void philips::NewZkProof(Prover& p, const std::vector<size_t>& disclose) 
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

    for (size_t i = 0; i < PROOF_COUNT; i++) {
        Fr x; 
        x.setRand();
        p.proof->pf3[i] = x;
    }
    p.proof->ublind.setRand();
    p.proof->lblind.setRand();

    // process the disclosure request
    std::vector<size_t> targets = disclose;
    std::sort(targets.begin(),targets.end()); 

    // empty randoms for disclosed messages
    for(size_t target : targets) {
        p.proof->pf3[3 + target] = (Fr) 0;
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
    
    // blind the special values
    G1 hu;
    G1 hl;
    G1 blind;
    G1::mul(hu,p.protocol->uH,p.drec.sig.u);
    G1::mul(blind,p.protocol->iH,p.proof->ublind);
    G1::add(p.proof->cmtU,blind,hu);
    G1::mul(hl,p.protocol->lH,p.drec.sig.l);
    G1::mul(blind,p.protocol->iH,p.proof->lblind);
    G1::add(p.proof->cmtL,blind,hl);

    // pf3 is complicated
    pairing(p.pairings[0],p.proof->cmtA,p.protocol->crv.g2); 
    Fp12::pow(p.proof->cmtPf3,p.pairings[0],p.proof->pf3[0]);
    for(size_t i =1; i < PROOF_COUNT; i++) {
        if(p.proof->pf3[i] != (Fr) 0) {
            Fp12 exp;
            Fp12::pow(exp,p.pairings[i],p.proof->pf3[i]);
            Fp12::mul(p.proof->cmtPf3,p.proof->cmtPf3,exp);
        }
    }

    // compute the lefthand side
    Fp12 left;
    Fp12 leftbottom;
    G1 disclosed = p.protocol->generators[0];
    for(size_t target : targets) {
        G1 tmp;
        G1::mul(tmp,p.protocol->generators[target+1],p.drec.hashvalues[target]);
        G1::add(disclosed,disclosed,tmp);
    }
    G1::add(disclosed,disclosed,p.proof->cmtU);
    G1::add(disclosed,disclosed,p.proof->cmtL);
    pairing(left,disclosed,p.protocol->crv.g2);  
    pairing(leftbottom,p.proof->cmtA,p.trust.pub);
    Fp12::div(left,left,leftbottom);

    // fiat shamir over cmtPf3, left 
    Fr fsc;
    FiatShamir<Fp12>(p.proof->cmtPf3,left,p.pairings[0],fsc);

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
    Fr::neg(secrets[RESPONSE_COUNT-3],p.drec.sig.s);
    secrets[RESPONSE_COUNT - 2] = p.proof->ublind;
    secrets[RESPONSE_COUNT - 1] = p.proof->lblind;

    for(size_t i = 0; i < RESPONSE_COUNT; i++) {
        if(randoms[i] != (Fr) 0){
            Fr mult;
            Fr::mul(mult,secrets[i],fsc);
            Fr::sub(p.proof->response[i],randoms[i],mult);
        } else {
            p.proof->response[i] = (Fr) 0;
        }
    }
}

/**
 * Verify the response to a challenge 
 * -----------------------------------------------
 */
bool philips::VerifyProof(Verifier& v, const ZkProof& proof,
    std::vector<std::pair<std::string,size_t>>& disclosed)
{
    // PROCESS the proof
    Fp12 left, newtop, leftbottom, lefttop;
    G1 addtop;

    // set left bottom & top
    pairing(leftbottom,proof.cmtA,v.trust.pub);
    addtop = v.protocol->generators[0];

    // adjust top 
    G1::add(addtop,addtop,proof.cmtU);
    G1::add(addtop,addtop,proof.cmtL);

    // deal with the disclosed info
    std::sort(disclosed.begin(),disclosed.end(), 
        [](const std::pair<std::string,size_t>&a,const std::pair<std::string,size_t>& b) 
            { return a.second < b.second; }); 
    for(auto pair: disclosed) {
        G1 tmp;
        Fr hash;
        hash.setHashOf(pair.first);
        G1::mul(tmp,v.protocol->generators[pair.second+1],hash);
        G1::add(addtop,addtop,tmp);
    }
    pairing(lefttop,addtop,v.protocol->crv.g2);  
    Fp12::div(left,lefttop,leftbottom);

    // update pairing
    pairing(v.pairings[0],proof.cmtA,v.protocol->crv.g2);

    // compute fiat-shamir
    Fr fsc;
    Fp12 p0 = v.pairings[0];
    FiatShamir<Fp12>(proof.cmtPf3,left,p0,fsc);

    // simplified calling
    const std::array<G1,2> pf1gens = {v.protocol->crv.g1,v.protocol->iH};
    const std::array<G1,1> pf2gens = {proof.cmtB};

    // check proof 1
    if (!VerifySchnorrProofG1<RESPONSE_COUNT,2>(proof.cmtB,proof.cmtPf1,fsc,
        proof.response.begin(),pf1gens.begin())) {
        return false;
    }

    // check proof 2a
    if (!VerifySchnorrProofG1<RESPONSE_COUNT,1>(proof.cmtBc,proof.cmtPf2,fsc,
        (proof.response.begin() + 2),pf2gens.begin())) {
        return false;
    }

    // check proof 2b 
    if (!VerifySchnorrProofG1<RESPONSE_COUNT,2>(proof.cmtBc,proof.cmtPf2b,fsc,
        (proof.response.begin() + 3),pf1gens.begin())) {
        return false;
    }

    // check proof 3 
    if (!VerifySchnorrProofGt<RESPONSE_COUNT,PROOF_COUNT>(left,proof.cmtPf3,fsc,
        (proof.response.begin() + 5),v.pairings.begin())) {
        return false;
    } 

    return true;
}

