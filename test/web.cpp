/** 
 * Demo our deid technology
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <iostream>
#include <gtest/gtest.h>

#include <crypto.hpp>
#include <protocol.hpp>
#include <deid.hpp>
#include <base.hpp>

using namespace philips;

std::string G1str(G1 el) 
{
    std::string dump;
    char buffer[G1_size];
    el.serialize(buffer,G1_size);
    base64_encode(dump,(uint8_t *)buffer,G1_size);
    return dump;
}

std::string G2str(G2 el) 
{
    std::string dump;
    char buffer[G2_size];
    el.serialize(buffer,G2_size);
    base64_encode(dump,(uint8_t *)buffer,G2_size);
    return dump;
}

std::string Fp12str(Fp12 el) 
{
    std::string dump;
    char buffer[Fp12_size];
    el.serialize(buffer,Fp12_size);
    base64_encode(dump,(uint8_t *)buffer,Fp12_size);
    return dump;
}

std::string Frstr(Fr el) 
{
    std::string dump;
    char buffer[Fr_size];
    el.serialize(buffer,Fr_size);
    base64_encode(dump,(uint8_t *)buffer,Fr_size);
    return dump;
}

void dumpG2(G2 key) 
{
    std::string dump;
    char buffer[G2_size];
    key.serialize(buffer,G2_size);
    base64_encode(dump,(uint8_t *)buffer,G2_size);
    std::cout << "G2: " << dump  << std::endl;
}

void dumpProof(const ZkProof& proof) 
{
    std::vector<std::string> result;
    result.push_back(G1str(proof.cmtA));  
    result.push_back(G1str(proof.cmtB));  
    result.push_back(G1str(proof.cmtPf1));  
    result.push_back(G1str(proof.cmtBc));  
    result.push_back(G1str(proof.cmtPf2));  
    result.push_back(G1str(proof.cmtPf2b));  
    result.push_back(Fp12str(proof.cmtPf3));  
    result.push_back(Fp12str(proof.cmtPf4));  
    for(const G1& el: proof.SiV) { result.push_back(G1str(el)); }
    for(const Fp12& el: proof.cmtSnip) { result.push_back(Fp12str(el)); }
    result.push_back(Fp12str(proof.rowId));  
    result.push_back(G1str(proof.cmtU));  
    result.push_back(G1str(proof.cmtL));  
    result.push_back(G1str(proof.cmtY));  
    for(const Fr& el: proof.response) { result.push_back(Frstr(el)); }
    for(const Fr& el: proof.row_response) { result.push_back(Frstr(el)); }
    for(const Fr& el: proof.snip_response) { result.push_back(Frstr(el)); }
    for(const std::string& el : result) {
        std::cout << el;
    }
    std::cout << std::endl;
}

// Test signatures
TEST(Demo,log) {

    // setup 
    auto p = std::make_shared<const Protocol>();
    
    KeyPair kp;
    BBKey bbk(p->crv.g2,p->crv.g1);
    BBKey bbk2(p->crv.g2,p->crv.g1);
    TrustLayer trust;
    KeyGen(p->crv.g2,kp); 
    trust.pub = kp.pub;
    trust.bbkeys = {bbk.pub, bbk2.pub};

    // log for demo
    dumpG2(trust.pub);
    dumpG2(bbk.pub);
    dumpG2(bbk2.pub);


    std::vector<std::string> snips = {
        "1       15850   .       G       T       .       .       .",
        "1       396781  .       T       A       .       .       .",
        "1       447872  .       A       T       .       .       .",
        "1       539230  .       T       A       .       .       .",
        "1       660507  .       A       C       .       .       .",
        "1       666172  .       A       G       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       943484  .       T       C       .       .       ."
    };

    // AGE=64; CANCER=LIVER; BMI=25
    std::array<std::string,MESSAGE_COUNT> record = {"AGE=64","CANCER=LIVER","BMI=25","MALE","USA"};
    std::array<std::string,MESSAGE_COUNT> record2 = {"AGE=52","CANCER=LIVER","BMI=19","FEMALE","USA"};
    std::array<std::string,MESSAGE_COUNT> record3 = {"AGE=55","CANCER=LIVER","BMI=20","FEMALE","USA"};
    std::array<std::string,MESSAGE_COUNT> record4 = {"AGE=60","CANCER=LIVER","BMI=22","FEMALE","USA"};
    std::array<std::string,MESSAGE_COUNT> record5 = {"AGE=55","CANCER=LIVER","BMI=22","FEMALE","USA"};
    DeidRecord drec = DeidRecord(kp,bbk,record,p,snips); // Signed by trusted source
    DeidRecord drec2 = DeidRecord(kp,bbk,record2,p,snips); // Signed by trusted source
    DeidRecord drec3 = DeidRecord(kp,bbk,record3,p,snips); // Signed by trusted source
    DeidRecord drec4 = DeidRecord(kp,bbk,record4,p,snips); // Signed by trusted source
    DeidRecord drec5 = DeidRecord(kp,bbk,record5,p,snips); // Signed by trusted source
    std::vector<DeidRecord> records = { drec, drec2, drec3, drec4, drec5 };

    // Create a prover  & Verifier
    Prover prover = Prover(records,trust,p); 
    Verifier verifier = Verifier(trust,p);

    std::vector<size_t> discl1 = {1};
    std::vector<size_t> discl2 = {2};
    std::array<std::pair<size_t,std::vector<size_t>>,5> disclose;
    disclose[0] = std::make_pair(0, discl1); 
    disclose[1] = std::make_pair(1, discl2); 
    disclose[2] = std::make_pair(2, discl1); 
    disclose[3] = std::make_pair(3, discl1); 
    disclose[4] = std::make_pair(4, discl2); 

    std::vector<size_t> sdiscl1 = {3,6};
    std::vector<size_t> sdiscl2 = {4,6};
    std::array<std::pair<size_t,std::vector<size_t>>,5> discsnips;
    discsnips[0] = std::make_pair(0, sdiscl1); 
    discsnips[1] = std::make_pair(1, sdiscl2); 
    discsnips[2] = std::make_pair(2, sdiscl1); 
    discsnips[3] = std::make_pair(3, sdiscl1); 
    discsnips[4] = std::make_pair(4, sdiscl2); 

    // create a table
    NewTable("random phrase", prover, disclose.data(), discsnips.data(), 3);

    dumpG2(prover.table->tablekey);

    for(const Row& r: prover.table->deidrows) {
        std::cout << "-----------------------------------------"<<std::endl;
        dumpProof(r.proof);
    }

}
