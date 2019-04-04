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
#include <cls.hpp>

using namespace philips;
using namespace philips::cls;

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
    std::array<G1,SPECIAL_COUNT> ign = { p->crv.g1 , p->crv.g1 };
    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    Sign(kp,p->generators,record,ign,sig,&hashes);
	std::cout << "Signature sigma: " << sig.sigma << std::endl;

    // Test Signature Verification
    ASSERT_EQ(VerifySignature(p->crv.g2,trust.pub,sig,p->generators,record,ign),1); 
    ASSERT_EQ(VerifySignature(p->crv.g2,trust.pub,sig,p->generators,{"b"},ign),0);
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
    std::array<G1,SPECIAL_COUNT> ign = { p->crv.g1 };
    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    Sign(kp,p->generators,record,ign,sig,&hashes);

    // Create a prover  & Verifier
    Prover prover = Prover(DeidRecord(kp,record,p),trust,p); 
    Verifier verifier = Verifier(trust,p);

    // Now proof, process, challenge, response & verify 
    bool result;
    Fr challenge;
    ZkProof deserial;
    std::array<Fr,RESPONSE_COUNT> response;
    std::vector<char> buf((G1_size * 6)+Fp12_size); 
    NewZkProof(prover);
    ZkProof zkp = (ZkProof) *(prover.proof);

    ProcessZkProof(zkp,verifier);
    challenge.setRand();
    RespondToChallenge(prover,challenge,response);
    result = VerifyProof(verifier,challenge,response);
    ASSERT_EQ(result,1);
}

