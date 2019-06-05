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
    KeyPair kp, kp2;
    BBKey bbk(p->crv.g2,p->crv.g1);
    BBKey bbk2(p->crv.g2,p->crv.g1);
    TrustLayer trust;
    KeyGen(p->crv.g2,kp); 
    KeyGen(p->crv.g2,kp2); 
    trust.pub = kp.pub;
    trust.bbkeys = {bbk.pub, bbk2.pub};

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

    // Sign a record
    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    DeidRecord drec = DeidRecord(kp,bbk,record,p,snips);
    std::vector<DeidRecord> records = { drec };

    // Create a prover  & Verifier
    Prover prover = Prover(records,trust,p); 
    Verifier verifier = Verifier(trust,p);

    // Now proof, process, challenge, response & verify 
    bool result;
    ZkProofKnowledge deserial;
    NewZkProof({0},{1},kp2.pub,drec,deserial,prover);
    ZkProof zkp = (ZkProof) (deserial);
    std::vector<std::pair<std::string,size_t>> disclose = {{"a",0}};
    std::vector<std::string> disclsnip = 
        { "1       396781  .       T       A       .       .       ." };
    result = VerifyProof(zkp,kp2.pub,disclsnip,disclose,verifier);
    ASSERT_EQ(result,1);
}

TEST(DeidTest,Table) {
    auto p = std::make_shared<const Protocol>();
    KeyPair kp;
    TrustLayer trust;
    KeyGen(p->crv.g2,kp); 
    BBKey bbk(p->crv.g2,p->crv.g1);
    BBKey bbk2(p->crv.g2,p->crv.g1);
    trust.pub = kp.pub;
    trust.bbkeys = {bbk.pub, bbk2.pub};

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

    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    DeidRecord drec = DeidRecord(kp,bbk,record,p,snips); // Signed by trusted source
    DeidRecord drec2 = DeidRecord(kp,bbk,record,p,snips); // Signed by trusted source
    DeidRecord drec3 = DeidRecord(kp,bbk,record,p,snips); // Signed by trusted source
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

    std::vector<size_t> sdiscl1 = {3,6};
    std::vector<size_t> sdiscl2 = {4,6};
    std::array<std::pair<size_t,std::vector<size_t>>,3> discsnips;
    discsnips[0] = std::make_pair(0, sdiscl1); 
    discsnips[1] = std::make_pair(1, sdiscl2); 
    discsnips[2] = std::make_pair(2, sdiscl1); 

    // create a table
    NewTable("random phrase", prover, disclose.data(), discsnips.data(), 3);

    bool result;
    result = CheckTable(verifier,prover.table->tablekey,prover.table->deidrows.data(),3);
    ASSERT_EQ(result,true);

    // refuse duplicates
    disclose[2] = disclose[1];
    NewTable("another phrase", prover, disclose.data(), discsnips.data(), 3);
    result = CheckTable(verifier,prover.table->tablekey,prover.table->deidrows.data(),3);
    ASSERT_EQ(result,false);
}

