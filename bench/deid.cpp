/** 
 * Bench our implementation
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <mcl/bn256.hpp>

#define CYBOZU_BENCH_USE_GETTIMEOFDAY
#include <cybozu/benchmark.hpp>

#undef CYBOZU_BENCH_USE_CPU_TIMER

#include <protocol.hpp>
#include <deid.hpp>

#include <iostream>

#define TESTCOUNT 3

using namespace mcl::bn256;

using namespace philips;

//---------------------------------------------------
// starting point
//---------------------------------------------------
int main(void) 
{
    // setup 
    initPairing();
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
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       701549  .       G       A       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       708702  .       T       G       .       .       .",
        "1       943484  .       T       C       .       .       ."
    };

    // Sign a record
    std::array<std::string,MESSAGE_COUNT> record = {"a","b","c","d","e"};
    const size_t testsize = 1000;
    std::vector<DeidRecord> records(testsize);
    for(size_t i = 0; i < testsize; i++) {
        records[i] = DeidRecord(kp,bbk,record,p,snips);
    }

    // Create a prover  & Verifier
    Prover prover = Prover(records,trust,p); 
    Verifier verifier = Verifier(trust,p);

    std::vector<size_t> discl1 = {1};
    std::array<std::pair<size_t,std::vector<size_t>>,testsize> disclose;
    for(size_t i = 0; i < testsize; i++) {
        disclose[i] = std::make_pair(i,discl1);
    }

    std::vector<size_t> sdiscl1 = {1,2,3,4,5};
    std::array<std::pair<size_t,std::vector<size_t>>,testsize> discsnips;
    for(size_t i = 0; i < testsize; i++) {
        discsnips[i] = std::make_pair(i,sdiscl1);
    }

    // create a table
    NewTable("random phrase", prover, disclose.data(), discsnips.data(), testsize);

    bool result;
    result = CheckTable(verifier,prover.table->tablekey,prover.table->deidrows.data(),testsize);
    std::cout << result << std::endl;

    // BENCHMARKING
    CYBOZU_BENCH_C("[Prover] Create::Table",TESTCOUNT,NewTable, "huhhhy", prover, disclose.data(), discsnips.data(), testsize);

    CYBOZU_BENCH_C("[Verifier] Check::Table",TESTCOUNT,CheckTable,verifier,prover.table->tablekey,prover.table->deidrows.data(),testsize);

    

    // Now proof, process, challenge, response & verify 
   // ZkProofKnowledge deserial,test;
//    NewZkProof({0},{1,2,3,4,5,6,7,8,9,10},kp2.pub,drec,deserial,prover);
   // NewZkProof({0,1},{},kp2.pub,drec,deserial,prover);
  //  ZkProof zkp = (ZkProof) (deserial);
/*    std::vector<std::pair<std::string,size_t>> disclose = {{"a",0},{"b",1}};//,{"c",2}};
    std::vector<std::string> disclsnip = 
        { "1       396781  .       T       A       .       .       .",
          "1       447872  .       A       T       .       .       .",
          "1       539230  .       T       A       .       .       .",
          "1       660507  .       A       C       .       .       .",
          "1       666172  .       A       G       .       .       .",
        };
*/
/*    bool result;
    result = VerifyProof(zkp,kp2.pub,{},disclose,verifier);
    std::cout << result << std::endl;

    // BENCHMARKING
    CYBOZU_BENCH_C("[Prover] Create::ZkProof",1000,NewZkProof,{0,1},{},kp2.pub,drec,test,prover);

    CYBOZU_BENCH_C("[Verifier] Verify::Proof",1000,VerifyProof,zkp,kp2.pub,{},disclose,verifier);
*/
}

