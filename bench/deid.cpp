/** 
 * Bench our implementation
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <mcl/bn256.hpp>
#include <cybozu/benchmark.hpp>

#include <protocol.hpp>
#include <deid.hpp>

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
    KeyPair kp;
    TrustLayer trust;
    KeyGen(p->crv.g2,kp); 
    trust.pub = kp.pub;

    // Sign a message
    Signature sig;
    std::array<Fr,MESSAGE_COUNT> hashes;
    std::array<G1,SPECIAL_COUNT> ign = { p->crv.g1 };
    std::array<std::string,MESSAGE_COUNT> message = {"a","b","c","d","e"};
    Sign(kp,p->generators,message,ign,sig,&hashes);

    // Create a prover  & Verifier
    Prover prover = Prover(Credential(sig,message,ign,hashes),trust,p); 
    Verifier verifier = Verifier(trust,p);

    // Now proof, process, challenge, response & verify 
    Fr challenge;
    ZkProof deserial;
    std::array<Fr,RESPONSE_COUNT> response;
    std::vector<char> buf((G1_size * 6)+Fp12_size); 
    NewZkProof(prover);
    ZkProof zkp = (ZkProof) *(prover.proof);
    ProcessZkProof(zkp,verifier);
    challenge.setRand();
    RespondToChallenge(prover,challenge,response);

    // BENCHMARKING
    CYBOZU_BENCH_C("Verify::Sig",1000,VerifySignature,p->crv.g2,kp.pub,sig,p->generators,
        message,ign);

    CYBOZU_BENCH_C("[Prover] Create::ZkProof",1000,NewZkProof,prover);

    CYBOZU_BENCH_C("[Verifier] Process::ZkProof",1000,ProcessZkProof,*(prover.proof),
        verifier);

    CYBOZU_BENCH_C("[Prover] Create::Response",1000,RespondToChallenge,prover,challenge,
        response);

    CYBOZU_BENCH_C("[Verifier] Verify::Proof",1000,VerifyProof,verifier,challenge,
        response);
}

