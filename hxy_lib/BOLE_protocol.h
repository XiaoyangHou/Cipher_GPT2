#ifndef HXY_BOLE_protocol_H
#define HXY_BOLE_protocol_H
#include "define.h"
#include "Common.h"

class BOLE_protocol{
private:
    uint32_t party;
    NetIO * IO;
    uint32_t bole_num = 0, used_bole_num = 0;
    const uint32_t POLYNOMIAL_DEGREE = 8192;
    const static uint64_t p0 = 2061584302081ULL, p1 = 2748779069441ULL;
    const static uint64_t p0_inv = 4ULL, p1_inv = 2061584302078ULL;
    shared_ptr<EncryptionParameters> parms0, parms1;
    shared_ptr<SEALContext> context0{nullptr}, context1{nullptr};
    shared_ptr<PublicKey> publicKey0{nullptr}, publicKey1{nullptr};
    shared_ptr<seal::UniformRandomGenerator> seal_uniform_random_generator{nullptr};
    const vector<int> moduli_bits{52, 52, 52};
    shared_ptr<Evaluator> evaluator0{nullptr}, evaluator1{nullptr};
    shared_ptr<BatchEncoder> encoder0{nullptr}, encoder1{nullptr};
    shared_ptr<Decryptor> decryptor0{nullptr}, decryptor1{nullptr};
    shared_ptr<Encryptor> encryptor0{nullptr}, encryptor1{nullptr};
    void init();
    void offline_check();
public:
    BOLE_protocol(uint32_t _party_id, NetIO * _IO, const uint32_t _bole_num);
    ~BOLE_protocol();
    void BOLE_online(const uint32_t N, const uint32_t bw, const uint64_t * x, const uint64_t * y, uint64_t * z);
    void BOLE_online(const uint32_t N, const uint32_t bw, const uint64_t * x, uint64_t * z); //TODO
    void BOLE_square_online(const uint32_t N, const uint32_t bw, const uint64_t * x, uint64_t * z); // TODO
    static uint64_t CRT(const uint64_t a0, const uint64_t a1) {
        uint64_t u = mulmod(a0, p1_inv, p0);
        uint64_t v = mulmod(a1, p0_inv, p1);
        return u * p1 + v * p0 - 1;
    }
    uint64_t offline_time, offline_comm; // time in ms, comm in byte
    vector<uint64_t> offline_x, offline_a; // x_C * x_S = a_C + a_S;
};

#endif