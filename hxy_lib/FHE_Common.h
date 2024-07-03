#ifndef HXY_FHE_COMMON_H
#define HXY_FHE_COMMON_H

#include <seal/seal.h>
#include <seal/secretkey.h>
#include <seal/util/polyarithsmallmod.h>
#include <seal/util/rlwe.h>
#include <emp-tool/emp-tool.h>

using namespace std;
using namespace seal;
using emp::NetIO;

int get_noise_budget(Decryptor & decryptor, const Ciphertext & ciphertext_x);

int get_noise_budget(Decryptor & decryptor, const vector<Ciphertext> & ciphertext_vct);

void sample_random_mask(vector<uint64_t> &coeffs_buff,
                        seal::Plaintext &mask,
                        seal::parms_id_type pid,
                        std::shared_ptr<seal::UniformRandomGenerator> prng,
                        const seal::SEALContext &context);

void flood_ciphertext(seal::Ciphertext &ct,
                      std::shared_ptr<seal::UniformRandomGenerator> prng,
                      const seal::SEALContext &context,
                      const seal::PublicKey &pk,
                      const seal::Evaluator &evaluator);

void asymmetric_encrypt_zero(
        const seal::SEALContext &context,
        const seal::PublicKey &public_key,
        const seal::parms_id_type parms_id,
        bool is_ntt_form,
        std::shared_ptr<seal::UniformRandomGenerator> prng,
        seal::Ciphertext &destination);

void flood_ciphertext(seal::Ciphertext &ct,
                      std::shared_ptr<seal::UniformRandomGenerator> prng,
                      const seal::SEALContext &context,
                      const seal::PublicKey &pk,
                      const seal::Evaluator &evaluator);

void sub_poly_inplace(seal::Ciphertext &ct,
                      const seal::Plaintext &pt,
                      const seal::SEALContext &context,
                      const seal::Evaluator &evaluator);

void rotate_ciphertext_inplace(const SEALContext & context, Ciphertext & ciphertext, const uint32_t offset);

void send_publickey(const PublicKey &publicKey, NetIO & empIO);
void recv_publickey(const SEALContext &context, PublicKey & publicKey, NetIO & empIO);

void encrypt_then_send(const SEALContext & context, const Plaintext & plaintext, Encryptor & encryptor, NetIO & empIO);
void recv_cipher_then_expand(const SEALContext &context, Ciphertext & ciphertext, NetIO & empIO);

void encrypt_then_send(const SEALContext & context, const vector<Plaintext> & plaintext_vct, Encryptor & encryptor, NetIO & empIO);
void recv_cipher_then_expand(const SEALContext &context, vector<Ciphertext> & ciphertext_vct, NetIO & empIO);

void send_final_ciphertext(const SEALContext & context, const Ciphertext & ciphertext, const vector<uint32_t> & used_coefficient_index, NetIO & empIO);
void recv_final_ciphertext(const SEALContext & context, Ciphertext & ciphertext, const vector<uint32_t> & used_coefficient_index, NetIO & empIO);

void send_final_ciphertext(const SEALContext & context, const vector<Ciphertext> & ciphertext_vct, const vector<uint32_t> & used_coefficient_index, NetIO & empIO);
void recv_final_ciphertext(const SEALContext & context, vector<Ciphertext> & ciphertext, const vector<uint32_t> & used_coefficient_index, NetIO & empIO);

void send_ciphertext(const Ciphertext & ciphertext, NetIO & empIO);
void recv_ciphertext(const SEALContext & context, Ciphertext & ciphertext, NetIO & empIO);

void send_ciphertext(const vector<Ciphertext> & ciphertext_vct, NetIO & empIO);
void recv_ciphertext(const SEALContext & context, vector<Ciphertext> & ciphertext, NetIO & empIO);

void remove_unused_coeffient(Ciphertext & ciphertext, const vector<uint32_t> & used_coefficient_index);
void remove_unused_coeffient(vector<Ciphertext> & ciphertext_vct, const vector<uint32_t> & used_coefficient_index);

#endif