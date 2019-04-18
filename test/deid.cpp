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
    TrustLayer trust;
    KeyGen(p->crv.g2,kp); 
    trust.pub = kp.pub;

    // Sign a record
    Signature sig;
    std::array<Fr,MESSAGE_COUNT> hashes;
    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    Sign(kp,p,record,sig,&hashes);

    // Create a prover  & Verifier
    Prover prover = Prover(DeidRecord(kp,record,p),trust,p); 
    Verifier verifier = Verifier(trust,p);

    // Now proof, process, challenge, response & verify 
    bool result;
    ZkProof deserial;
    NewZkProof(prover,{0});
    ZkProof zkp = (ZkProof) *(prover.proof);
    std::vector<std::pair<std::string,size_t>> disclose = {{"a",0}};
    result = VerifyProof(verifier,zkp,disclose);
    ASSERT_EQ(result,1);
}

