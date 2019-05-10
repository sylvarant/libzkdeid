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
    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
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


TEST(DeidTest,Table) {
    auto p = std::make_shared<const Protocol>();
    KeyPair kp;
    TrustLayer trust;
    KeyGen(p->crv.g2,kp); 
    trust.pub = kp.pub;

    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    DeidRecord drec = DeidRecord(kp,record,p); // Signed by trusted source
    DeidRecord drec2 = DeidRecord(kp,record,p); // Signed by trusted source
    DeidRecord drec3 = DeidRecord(kp,record,p); // Signed by trusted source
    std::vector<DeidRecord> records = { drec, drec2, drec3 };

    // Create a prover  & Verifier
    Prover prover = Prover(records,trust,p); 
    Verifier verifier = Verifier(trust,p);

    std::vector<size_t> discl1 = {1};
    std::vector<size_t> discl2 = {2};
    std::array<std::pair<size_t,std::vector<size_t>>,3> disclose;
    disclose[0] = std::make_pair(0, discl1); 
    disclose[1] = std::make_pair(1, discl2); 
    disclose[2] = std::make_pair(2, discl1); 

    // create a table
    NewTable("random phrase", prover, disclose.data(), 3);

    bool result;
    result = CheckTable(verifier,prover.table->tablekey,prover.table->deidrows.data(),3);
    ASSERT_EQ(result,true);

    // refuse duplicates
    disclose[2] = disclose[1];
    NewTable("another phrase", prover, disclose.data(), 3);
    result = CheckTable(verifier,prover.table->tablekey,prover.table->deidrows.data(),3);
    ASSERT_EQ(result,false);
}

