#pragma once
/** 
 * Deidentification through cls
 * utilizing mcl
 * by AJHL
 * for philips
 * written to be C++11 compliant, columnwidth = 90
 */

#include <array>
#include <memory>
#include <unordered_map>
#include <mcl/bn256.hpp>

//philips
#include "crypto.hpp"
#include "protocol.hpp"

// CLS based constants
#define PROOF_COUNT     (MESSAGE_COUNT + SPECIAL_COUNT + 4)
#define PAIRING_COUNT   (PROOF_COUNT + 3)
#define RESPONSE_COUNT  (MESSAGE_COUNT + SPECIAL_COUNT + 9) 
#define ROW_RESPONSE_COUNT 3
#define ROW_PROOF_COUNT 4

// for marshalling
#define FP_SIZE 384

namespace philips { 

using namespace mcl::bn256;

/*--------------------------------------------------------------------------------------
 * Basic CLS signature functionality
 *-------------------------------------------------------------------------------------*/

struct KeyPair {
    G2 pub;
    Fr priv;
};

struct Signature {
    G1 sigma;
    Fr c;
    Fr s;
    Fr u;
    Fr l;
};

/**
 * Generate a keypair for a trusted party 
 * ------------------------------------------
 */
void KeyGen(const G2& base, KeyPair& kp);

/**
 * Sign a set of record
 * ------------------------------------------
 */
void Sign(const KeyPair& kp, const std::shared_ptr<const Protocol>& p, 
    const std::array<std::string,MESSAGE_COUNT>& record, Signature& sig,
    std::array<Fr,MESSAGE_COUNT>* hashes = nullptr); 

/**
 * Verify a given CLS signature without zk
 * ------------------------------------------
 */
bool VerifySignature(const G2& base, const G2& pub, const Signature& sig, 
    const std::shared_ptr<const Protocol>& p, 
    const std::array<std::string,MESSAGE_COUNT>& record);


/*--------------------------------------------------------------------------------------
 * Innovations
 *-------------------------------------------------------------------------------------*/

struct DeidRecord {
    std::array<std::string,MESSAGE_COUNT> record;
    std::array<Fr,MESSAGE_COUNT> hashvalues;
    Signature sig;

    // simplify initialization
    DeidRecord(const KeyPair &kp, const std::array<std::string,MESSAGE_COUNT>& rec,
        const std::shared_ptr<const Protocol> p) : record(rec)
    {
        Sign(kp,p,record,sig,&hashvalues);
    } 
    DeidRecord() {}
};

// The public part of the zero-knowledge proof 
struct ZkProof { 
    G1 cmtA;
    G1 cmtB;
    G1 cmtPf1;    
    G1 cmtBc;     
    G1 cmtPf2;   
    G1 cmtPf2b; 
    Fp12 cmtPf3;
    Fp12 cmtPf4;
    Fp12 rowId;  
    G1 cmtU; // u value blinder
    G1 cmtL; // l value blinder
    std::array<Fr,RESPONSE_COUNT> response; // response to fiat-shamir
    std::array<Fr,ROW_RESPONSE_COUNT> row_response; 
};

struct ZkProofKnowledge : ZkProof {
    Fr r;                           // secret for A
    Fr open;                        // secret for B
    Fr ublind; 
    Fr lblind; 
    Fr pf1a, pf1b;                  
    Fr pf2a, pf2b, pf2c;            
    std::array<Fr,PROOF_COUNT> pf3; 
    std::array<Fr,ROW_PROOF_COUNT> pf4; 
};

// a row of deid data
struct Row {
    std::vector<std::pair<std::string,size_t>> disclosed; 
    ZkProof proof;
    Fp12 rowId; 
};

// a table of deidentified data
struct Table {
    std::vector<Row> deidrows; 
    G2 tablekey; 

    Table(size_t size,const std::string& phrase) {
        deidrows.reserve(size);
        hashAndMapToG2(tablekey,phrase);
    }

    Table(){}
};

struct Prover {
    std::vector<DeidRecord> drecords;
    std::unique_ptr<Table> table; 
    std::unique_ptr<std::vector<std::pair<size_t,ZkProofKnowledge>>> knowledge;
    std::array<Fp12,PAIRING_COUNT> pairings; // precomputed pairings
    TrustLayer trust;
    std::shared_ptr<const Protocol> protocol;

    Prover(const std::vector<DeidRecord>& drec, const TrustLayer& trust, 
        std::shared_ptr<const Protocol> p) :  drecords(drec), trust(trust), protocol(p) 
    {
        pairing(pairings[1],protocol->iH,trust.pub); 
        pairing(pairings[2],protocol->iH,protocol->crv.g2);
        for(size_t i = 1; i < GENERATOR_COUNT; i++) {
            pairing(pairings[2+i],protocol->generators[i],protocol->crv.g2); 
        }
        for(size_t i = 0; i < SPECIAL_COUNT; i++) {
            pairing(pairings[2+GENERATOR_COUNT+i],protocol->iH,protocol->crv.g2); 
        }
        pairing(pairings[PAIRING_COUNT-2],protocol->uH,protocol->crv.g2);
        pairings[PAIRING_COUNT-1] = pairings[2+GENERATOR_COUNT];
    }
};

struct Verifier {
    std::array<Fp12,PAIRING_COUNT> pairings; // precomputed pairings
    TrustLayer trust;
    std::shared_ptr<const Protocol> protocol;

    Verifier(const TrustLayer& trust, std::shared_ptr<const Protocol> p) : 
        trust(trust), protocol(p)
    {
        pairing(pairings[1],protocol->iH,trust.pub); 
        pairing(pairings[2],protocol->iH,protocol->crv.g2);
        for(size_t i = 1; i < GENERATOR_COUNT; i++) {
            pairing(pairings[2+i],protocol->generators[i],protocol->crv.g2); 
        }
        for(size_t i = 0; i < SPECIAL_COUNT; i++) {
            pairing(pairings[2+GENERATOR_COUNT+i],protocol->iH,protocol->crv.g2); 
        }
        pairing(pairings[PAIRING_COUNT-2],protocol->uH,protocol->crv.g2);
        pairings[PAIRING_COUNT-1] = pairings[2+GENERATOR_COUNT];
    }
};
    

/*--------------------------------------------------------------------------------------
 * Proof methods for rows
 *-------------------------------------------------------------------------------------*/

/**
 * Create a New set of proof secrets & commitments
 * -----------------------------------------------
 */
void NewZkProof(const std::vector<size_t>& disclose, const G2& tablekey,
    const DeidRecord& drec, ZkProofKnowledge& proof, Prover& p);


/**
 * Verify the response to a challenge 
 * -----------------------------------------------
 */
bool VerifyProof(const ZkProof& proof, const G2& tablekey,
    std::vector<std::pair<std::string,size_t>>& disclosed, Verifier& v);


/*--------------------------------------------------------------------------------------
 * Deid table
 *-------------------------------------------------------------------------------------*/

/**
 * Create a new table of deidentified data
 * -----------------------------------------------
 */
void NewTable(const std::string& phrase, Prover &p,
    std::pair<size_t,std::vector<size_t>>* discl, size_t rowcount);


/**
 * Create a new table of deidentified data
 * -----------------------------------------------
 */
bool CheckTable(Verifier& v,const G2& tablekey,Row* table, size_t rowcount);

}
