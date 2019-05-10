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

#define SECRET_COUNT RESPONSE_COUNT + ROW_RESPONSE_COUNT

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
void philips::NewZkProof(const std::vector<size_t>& disclose, const G2& tablekey,
    const DeidRecord& drec, ZkProofKnowledge& proof, Prover& p) 
{
    // random factors
    proof.r.setRand();
    proof.open.setRand();
    proof.pf1a.setRand();
    proof.pf1b.setRand();
    proof.pf2a.setRand();
    proof.pf2b.setRand();
    proof.pf2c.setRand();

    for (size_t i = 0; i < PROOF_COUNT; i++) {
        Fr x; 
        x.setRand();
        proof.pf3[i] = x;
    }
    for (size_t i = 0; i < ROW_PROOF_COUNT; i++) {
        Fr x; 
        x.setRand();
        proof.pf4[i] = x;
    }
    proof.ublind.setRand();
    proof.lblind.setRand();

    // process the disclosure request
    std::vector<size_t> targets = disclose;
    std::sort(targets.begin(),targets.end()); 

    // empty randoms for disclosed messages
    for(size_t target : targets) {
        proof.pf3[3 + target] = (Fr) 0;
    }

    // commitment time
    G1 sigblind;
    PedersenCmt(p.protocol->crv.g1,p.protocol->iH,proof.r,proof.open,
        proof.cmtB);
    G1::mul(sigblind,p.protocol->iH,proof.r);
    G1::add(proof.cmtA,sigblind,drec.sig.sigma);
    PedersenCmt(p.protocol->crv.g1,p.protocol->iH,proof.pf1a,proof.pf1b,
        proof.cmtPf1);
    G1::mul(proof.cmtBc,proof.cmtB,drec.sig.c);
    G1::mul(proof.cmtPf2,proof.cmtB,proof.pf2a);
    PedersenCmt(p.protocol->crv.g1,p.protocol->iH,proof.pf2b,proof.pf2c,
        proof.cmtPf2b);
    
    // blind the special values
    G1 hu;
    G1 hl;
    G1 blind;
    G1::mul(hu,p.protocol->uH,drec.sig.u);
    G1::mul(blind,p.protocol->iH,proof.ublind);
    G1::add(proof.cmtU,blind,hu);
    G1::mul(hl,p.protocol->lH,drec.sig.l);
    G1::mul(blind,p.protocol->iH,proof.lblind);
    G1::add(proof.cmtL,blind,hl);

    // the rowId
    pairing(proof.rowId,hu,tablekey);

    // pf3 is complicated
    pairing(p.pairings[0],proof.cmtA,p.protocol->crv.g2); 
    Fp12::pow(proof.cmtPf3,p.pairings[0],proof.pf3[0]);
    for(size_t i =1; i < PROOF_COUNT; i++) {
        if(proof.pf3[i] != (Fr) 0) {
            Fp12 exp;
            Fp12::pow(exp,p.pairings[i],proof.pf3[i]);
            Fp12::mul(proof.cmtPf3,proof.cmtPf3,exp);
        }
    }

    // pf4
    Fp12 left4;
    pairing(left4,proof.cmtU,p.protocol->crv.g2);
    Fp12::div(left4,left4,proof.rowId);    
    pairing(p.pairings[PAIRING_COUNT-3],p.protocol->uH,tablekey); 

    Fp12::pow(proof.cmtPf4,p.pairings[PAIRING_COUNT-3],proof.pf4[0]); 
    for(size_t i = 0; i < 2; i++) {
        Fp12 exp;
        Fp12::pow(exp,p.pairings[PAIRING_COUNT-2+i],proof.pf4[i+1]);
        Fp12::mul(proof.cmtPf4,proof.cmtPf4,exp);
    }

    Fr fsc4;
    FiatShamir<Fp12>(proof.cmtPf4,left4,p.pairings[PAIRING_COUNT-3],fsc4);
    std::cout << fsc4 << std::endl;

    // compute the lefthand side
    Fp12 left;
    Fp12 leftbottom;
    G1 disclosed = p.protocol->generators[0];
    for(size_t target : targets) {
        G1 tmp;
        G1::mul(tmp,p.protocol->generators[target+1],drec.hashvalues[target]);
        G1::add(disclosed,disclosed,tmp);
    }
    G1::add(disclosed,disclosed,proof.cmtU);
    G1::add(disclosed,disclosed,proof.cmtL);
    pairing(left,disclosed,p.protocol->crv.g2);  
    pairing(leftbottom,proof.cmtA,p.trust.pub);
    Fp12::div(left,left,leftbottom);

    // fiat shamir over cmtPf3, left 
    // TODO fsc for each proof ... ?
    Fr fsc;
    FiatShamir<Fp12>(proof.cmtPf3,left,p.pairings[0],fsc);

    // the randoms used to populate the schnorr style commits
    std::array<Fr,SECRET_COUNT> randoms = {proof.pf1a, proof.pf1b, proof.pf2a,
        proof.pf2b, proof.pf2c};
    std::copy(proof.pf3.begin(),proof.pf3.end(),randoms.begin()+5);
    std::copy(proof.pf4.begin(),proof.pf4.end(),randoms.begin()+5+PROOF_COUNT);

    // our actual secrets
    std::array<Fr,SECRET_COUNT> secrets = {proof.r,proof.open,drec.sig.c};
    Fr::mul(secrets[3],drec.sig.c,proof.r); 
    Fr::mul(secrets[4],drec.sig.c,proof.open); 
    secrets[5] = drec.sig.c;
    Fr::neg(secrets[6],proof.r);
    Fr::neg(secrets[7],secrets[3]);
    for(size_t i = 0; i < MESSAGE_COUNT; i++) {
        Fr::neg(secrets[8+i],drec.hashvalues[i]);
    }
    Fr::neg(secrets[RESPONSE_COUNT-3],drec.sig.s);
    secrets[RESPONSE_COUNT - 2] = proof.ublind;
    secrets[RESPONSE_COUNT - 1] = proof.lblind;
    Fr::neg(secrets[SECRET_COUNT - 3],drec.sig.u);
    secrets[SECRET_COUNT - 2] = drec.sig.u;
    secrets[SECRET_COUNT - 1] = proof.ublind;

    for(size_t i = 0; i < RESPONSE_COUNT; i++) {
        if(randoms[i] != (Fr) 0){
            Fr mult;
            Fr::mul(mult,secrets[i],fsc);
            Fr::sub(proof.response[i],randoms[i],mult);
        } else {
            proof.response[i] = (Fr) 0;
        }
    }

    for(size_t i = 0; i < ROW_RESPONSE_COUNT; i++) {
        Fr mult;
        Fr::mul(mult,secrets[RESPONSE_COUNT+i],fsc4);
        Fr::sub(proof.row_response[i],randoms[RESPONSE_COUNT+i],mult);
    }
}

/**
 * Verify the response to a challenge 
 * -----------------------------------------------
 */
bool philips::VerifyProof(const ZkProof& proof, const G2& tablekey,
    std::vector<std::pair<std::string,size_t>>& disclosed, Verifier& v)
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

    // uniqueness time
    Fp12 left4;
    pairing(left4,proof.cmtU,v.protocol->crv.g2);
    Fp12::div(left4,left4,proof.rowId);    
    pairing(v.pairings[PAIRING_COUNT-3],v.protocol->uH,tablekey); 

    Fr fsc4;
    FiatShamir<Fp12>(proof.cmtPf4,left4,v.pairings[PAIRING_COUNT-3],fsc4);
    std::cout << fsc4 << std::endl;

    if (!VerifySchnorrProofGt<ROW_RESPONSE_COUNT,ROW_PROOF_COUNT>(left4,proof.cmtPf4,
        fsc4,proof.row_response.begin(),v.pairings.begin()+PROOF_COUNT)) {
        return false;
    } 

    return true;
}


/*--------------------------------------------------------------------------------------
 * Table Business
 *-------------------------------------------------------------------------------------*/

/**
 * Create a new table of deidentified data
 * -----------------------------------------------
 */
void philips::NewTable(const std::string& phrase, Prover &p,
    std::pair<size_t,std::vector<size_t>>* discl, size_t rowcount)
{
    p.table.reset(new Table(rowcount,phrase));
    p.knowledge.reset(new std::vector<std::pair<size_t,ZkProofKnowledge>>());
    p.knowledge->reserve(rowcount);
    for(size_t i = 0; i < rowcount; i++) {
        size_t index = (*(discl+i)).first;
        ZkProofKnowledge proof;
        NewZkProof((*(discl+i)).second,p.table->tablekey,p.drecords[index],proof,p); 
        p.knowledge->at(i) = std::make_pair(index,proof);
        std::vector<std::pair<std::string,size_t>> disclosed;
        for(size_t n : (*(discl+i)).second) { 
            disclosed.push_back(std::make_pair(p.drecords[index].record[n],index));
        }
        Row r =  { disclosed, (ZkProof) proof, proof.rowId };
        p.table->deidrows.at(i) = r;
    }
}


/**
 * Create a new table of deidentified data
 * -----------------------------------------------
 */
bool philips::CheckTable(Verifier& v, const G2& tablekey, Row* table, size_t rowcount)
{
    char buf[FP_SIZE];
    std::hash<std::string> hash_fn;
    std::unordered_map<size_t,int> map;
    for(size_t i = 0; i < rowcount; i++){
        (*(table+i)).rowId.serialize(buf,FP_SIZE);
        std::string stringrep(buf);
        size_t hashv = hash_fn(stringrep);
        if(map.find(hashv) != map.end()) return false;
        map[hashv] = 1;
        if(!VerifyProof((*(table+i)).proof,tablekey,(*(table+i)).disclosed,v)) 
            return false; 
    }
    return true;
}

