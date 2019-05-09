/** 
 * Test our deid technology
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <iostream>
#include <gtest/gtest.h>

#include <crypto.hpp>
#include <protocol.hpp>
#include <deid.hpp>

using namespace philips;

// Test signatures
TEST(DeidTest,Sign) {

    // setup 
    auto p = std::make_shared<const Protocol>();

    // generate keypair for issuer & create trustchain info
    KeyPair kp;
    TrustLayer trust;
    KeyGen(p->crv.g2,kp); 
    trust.pub = kp.pub;

    // Sign a record
    Signature sig;
    std::array<Fr,MESSAGE_COUNT> hashes;
    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    Sign(kp,p,record,sig,&hashes);
	std::cout << "Signature sigma: " << sig.sigma << std::endl;

    // Test Signature Verification
    ASSERT_EQ(VerifySignature(p->crv.g2,trust.pub,sig,p,record),1); 
    ASSERT_EQ(VerifySignature(p->crv.g2,trust.pub,sig,p,{"b"}),0);
}


// Test Proofs
TEST(DeidTest,Prove) {

    // setup 
    auto p = std::make_shared<const Protocol>();

    // generate keypair for issuer & create trustchain info
    KeyPair kp;
    KeyPair kp2;
    TrustLayer trust;
    KeyGen(p->crv.g2,kp); 
    KeyGen(p->crv.g2,kp2); 
    trust.pub = kp.pub;

    // Sign a record
    Signature sig;
    std::array<Fr,MESSAGE_COUNT> hashes;
    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    Sign(kp,p,record,sig,&hashes);
    DeidRecord drec = DeidRecord(kp,record,p);
    std::vector<DeidRecord> records = { drec };

    // Create a prover  & Verifier
    Prover prover = Prover(records,trust,p); 
    Verifier verifier = Verifier(trust,p);

    // Now proof, process, challenge, response & verify 
    bool result;
    ZkProofKnowledge deserial;
    NewZkProof({0},kp2.pub,drec,deserial,prover);
    ZkProof zkp = (ZkProof) (deserial);
    std::vector<std::pair<std::string,size_t>> disclose = {{"a",0}};
    result = VerifyProof(zkp,kp2.pub,disclose,verifier);
    ASSERT_EQ(result,1);
}

