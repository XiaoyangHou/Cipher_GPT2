#include "FHE_Common.h"

int get_noise_budget(Decryptor & decryptor, const Ciphertext & ciphertext_x) {
    return decryptor.invariant_noise_budget(ciphertext_x);
}

int get_noise_budget(Decryptor & decryptor, const vector<Ciphertext> & ciphertext_vct) {
    int ret = INT32_MAX;
    for (const auto &p : ciphertext_vct) {
        ret = min(ret, decryptor.invariant_noise_budget(p));
    }
    return ret;
}

void sample_random_mask(vector<uint64_t> & coeffs_buff,
                        seal::Plaintext &mask,
                        seal::parms_id_type pid,
                        std::shared_ptr<seal::UniformRandomGenerator> prng,
                        const seal::SEALContext & context) {
    using namespace seal::util;

    auto cntxt_data = context.get_context_data(pid);

    auto parms = cntxt_data->parms();
    const size_t N = parms.poly_modulus_degree();

    mask.parms_id() = seal::parms_id_zero;  // foo SEAL when using BFV
    mask.resize(N);

    const size_t nbytes = mul_safe(mask.coeff_count(), sizeof(uint64_t));
    if (prng) {
        prng->generate(nbytes, reinterpret_cast<std::byte *>(mask.data()));
    } else {
        auto _prng = parms.random_generator()->create();
        _prng->generate(nbytes, reinterpret_cast<std::byte *>(mask.data()));
    }

    const auto & t = parms.plain_modulus(); // plaintext module should be a power of 2
    uint64_t mod_mask = t.value() - 1;
    std::transform(mask.data(), mask.data() + mask.coeff_count(), mask.data(), [mod_mask](uint64_t u) { return u & mod_mask; });

    coeffs_buff.resize(N);
    memcpy(coeffs_buff.data(), mask.data(), N * sizeof(uint64_t));
}

void send_publickey(const PublicKey & publicKey, NetIO & IO) {
    std::stringstream tmp_os;
    publicKey.save(tmp_os);
    uint32_t len = tmp_os.str().length();
    IO.send_data(&len, sizeof(uint32_t));
    IO.send_data(tmp_os.str().c_str(), len);
}

void recv_publickey(const SEALContext & context, PublicKey & publicKey, NetIO & IO) {
    uint32_t len;
    IO.recv_data(&len, sizeof(uint32_t));
    vector<char> serialized_pk(len);
    IO.recv_data(serialized_pk.data(), len);
    std::stringstream tmp_os;
    tmp_os.write(serialized_pk.data(), len);
    publicKey.load(context, tmp_os);
}

void flood_ciphertext(seal::Ciphertext & ct,
                      std::shared_ptr<seal::UniformRandomGenerator> prng,
                      const seal::SEALContext & context,
                      const seal::PublicKey & pk,
                      const seal::Evaluator & evaluator) {


    seal::Ciphertext zero;
    asymmetric_encrypt_zero(context, pk, ct.parms_id(), ct.is_ntt_form(), prng, zero);
    evaluator.add_inplace(ct, zero);
    if (ct.is_ntt_form()) {
        evaluator.transform_from_ntt_inplace(ct);
    }
}

void asymmetric_encrypt_zero(
        const seal::SEALContext & context,
        const seal::PublicKey & public_key,
        const seal::parms_id_type parms_id,
        bool is_ntt_form,
        std::shared_ptr<seal::UniformRandomGenerator> prng,
        seal::Ciphertext &destination) {
    using namespace seal;
    using namespace seal::util;
    // We use a fresh memory pool with `clear_on_destruction' enabled
    MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

    auto &context_data = *context.get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.poly_modulus_degree();
    auto ntt_tables = context_data.small_ntt_tables();
    size_t encrypted_size = public_key.data().size();

    // Make destination have right size and parms_id
    // Ciphertext (c_0,c_1, ...)
    destination.resize(context, parms_id, encrypted_size);
    destination.is_ntt_form() = is_ntt_form;
    destination.scale() = 1.0;

    // Generate u <-- R_3
    auto u(allocate_poly(coeff_count, coeff_modulus_size, pool));
    sample_poly_ternary(prng, parms, u.get());

    // c[j] = u * public_key[j]
    for (size_t i = 0; i < coeff_modulus_size; i++) {
        ntt_negacyclic_harvey_lazy(u.get() + i * coeff_count, ntt_tables[i]);
        for (size_t j = 0; j < encrypted_size; j++) {
            dyadic_product_coeffmod(u.get() + i * coeff_count,
                                    public_key.data().data(j) + i * coeff_count,
                                    coeff_count, coeff_modulus[i],
                                    destination.data(j) + i * coeff_count);

            // Addition with e_0, e_1 is in non-NTT form
            if (!is_ntt_form) {
                inverse_ntt_negacyclic_harvey(destination.data(j) + i * coeff_count,
                                              ntt_tables[i]);
            }
        }
    }

    // Generate e_j <-- chi
    // c[j] = public_key[j] * u + e[j]
    for (size_t j = 0; j < encrypted_size; j++) {
        SEAL_NOISE_SAMPLER(prng, parms, u.get());
        for (size_t i = 0; i < coeff_modulus_size; i++) {
            // Addition with e_0, e_1 is in NTT form
            if (is_ntt_form) {
                ntt_negacyclic_harvey(u.get() + i * coeff_count, ntt_tables[i]);
            }
            add_poly_coeffmod(
                    u.get() + i * coeff_count, destination.data(j) + i * coeff_count,
                    coeff_count, coeff_modulus[i], destination.data(j) + i * coeff_count);
        }
    }
}

void sub_poly_inplace(seal::Ciphertext & ct,
                      const seal::Plaintext & pt,
                      const seal::SEALContext & context,
                      const seal::Evaluator & evaluator) {
    if (ct.size() != 2) {
        std::cerr << "sub_poly_inplace: invalid ct.size()" << endl;
        return;
    }

    if (pt.parms_id() == seal::parms_id_zero) {
        if (pt.coeff_count() != ct.poly_modulus_degree()) {
            std::cerr << "sub_poly_inplace: invalid pt.coeff_count()";
            return;
        }
        evaluator.sub_plain_inplace(ct, pt);
        return;
    }

    auto n = ct.poly_modulus_degree();
    auto L = ct.coeff_modulus_size();
    if (pt.coeff_count() != n * L) {
        std::cerr << "sub_poly_inplace: invalid pt.coeff_count()" << endl;
        return;
    }

    auto cntxt = context.get_context_data(ct.parms_id());
    if (!cntxt) {
        std::cerr << "sub_poly_inplace: invalid ct.parms_id()" << endl;
    }

    auto &coeff_modulus = cntxt->parms().coeff_modulus();
    auto src_ptr = pt.data();
    auto dst_ptr = ct.data(0);
    for (size_t l = 0; l < L; ++l) {
        seal::util::sub_poly_coeffmod(dst_ptr, src_ptr, n, coeff_modulus[l], dst_ptr);
        dst_ptr += n;
        src_ptr += n;
    }
}

void rotate_ciphertext_inplace(const SEALContext & context, Ciphertext & ciphertext, const uint32_t offset) {
    auto parms = context.get_context_data(ciphertext.parms_id())->parms();

    auto polynomial_degree = parms.poly_modulus_degree();
    auto coeff_mod_count = parms.coeff_modulus().size();
    auto encrypted_count = ciphertext.size();

    assert(offset < polynomial_degree);

    vector<uint64_t> tmp(polynomial_degree);

    for (int i = 0; i < encrypted_count; i++) {
        for (int j = 0; j < coeff_mod_count; j++) {
            const uint64_t mod = parms.coeff_modulus()[j].value();
            memcpy(tmp.data(), ciphertext.data(i) + (j * polynomial_degree), polynomial_degree * sizeof(uint64_t));
            memcpy(ciphertext.data(i) + (j * polynomial_degree), tmp.data() + (polynomial_degree - offset), offset * sizeof(uint64_t));
            memcpy(ciphertext.data(i) + (j * polynomial_degree) + offset, tmp.data(), (polynomial_degree - offset) * sizeof(uint64_t));
            for (uint32_t k = 0; k < offset; k++)
                ciphertext.data(i)[j * polynomial_degree + k] = mod - ciphertext.data(i)[j * polynomial_degree + k];
        }
    }
}

void encrypt_then_send(const SEALContext & context, const Plaintext & plaintext, Encryptor & encryptor, NetIO & IO) {
    EncryptionParameters first_parms = context.first_context_data()->parms();
    auto N = first_parms.poly_modulus_degree();
    auto coeff_mod_count = first_parms.coeff_modulus().size();
    auto coeff_mod = first_parms.coeff_modulus();
    vector<uint32_t> coeff_mod_byte_count(coeff_mod_count);
    uint32_t coeff_sum_bytes = 0;
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        uint32_t tmp = ceil(log2(coeff_mod[i].value()) / 8.0);
        coeff_sum_bytes += tmp;
        coeff_mod_byte_count[i] = tmp;
    }
    const uint32_t seed_size = 64;
    vector<uint8_t> send_data(N * coeff_sum_bytes + seed_size);

    Serializable<Ciphertext> send_cipher = encryptor.encrypt_symmetric(plaintext);
    auto cipher_ptr = ((Ciphertext*) &send_cipher)->data();
    auto send_data_ptr = send_data.data();
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        for (uint32_t j = 0; j < N; j++) {
            memcpy(send_data_ptr, cipher_ptr, coeff_mod_byte_count[i]);
            send_data_ptr += coeff_mod_byte_count[i];
            cipher_ptr++;
        }
    }
    uint8_t * prng_seed_ptr = (uint8_t *)((Ciphertext*) &send_cipher)->data(1);
    memcpy(send_data.data() + N * coeff_sum_bytes, prng_seed_ptr + 8 + 16 + 1, seed_size);
    IO.send_data(send_data.data(), N * coeff_sum_bytes + seed_size);
}

void recv_cipher_then_expand(const SEALContext &context, Ciphertext & ciphertext, NetIO & IO) {
    EncryptionParameters first_parms = context.first_context_data()->parms();
    auto N = first_parms.poly_modulus_degree();
    auto coeff_mod_count = first_parms.coeff_modulus().size();
    auto coeff_mod = first_parms.coeff_modulus();
    vector<uint32_t> coeff_mod_byte_count(coeff_mod_count);
    uint32_t coeff_sum_bytes = 0;
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        uint32_t tmp = ceil(log2(coeff_mod[i].value()) / 8.0);
        coeff_sum_bytes += tmp;
        coeff_mod_byte_count[i] = tmp;
    }
    const uint32_t seed_size = 64;
    vector<uint8_t> recv_data(N * coeff_sum_bytes + seed_size);
    IO.recv_data(recv_data.data(), N * coeff_sum_bytes + seed_size);

    ciphertext.resize(context, first_parms.parms_id(), 2);
    auto cipher_ptr = ciphertext.data();
    auto recv_data_ptr = recv_data.data();
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        for (uint32_t j = 0; j < N; j++) {
            uint64_t tmp = 0;
            memcpy(&tmp, recv_data_ptr, coeff_mod_byte_count[i]);
            *cipher_ptr = tmp;
            recv_data_ptr += coeff_mod_byte_count[i];
            cipher_ptr++;
        }
    }
    UniformRandomGeneratorInfo prng_info;
    prng_info.type_ = prng_type::blake2xb;
    memcpy(prng_info.seed_.data(), recv_data_ptr, seed_size);
    auto prng = prng_info.make_prng();
    seal::util::sample_poly_uniform(prng, first_parms, ciphertext.data(1));
}

void encrypt_then_send(const SEALContext & context, const vector<Plaintext> & plaintext_vct, Encryptor & encryptor, NetIO & IO) {
    uint32_t vct_size = plaintext_vct.size();
    IO.send_data(&vct_size, sizeof(uint32_t));
    EncryptionParameters first_parms = context.first_context_data()->parms();
    auto N = first_parms.poly_modulus_degree();
    auto coeff_mod_count = first_parms.coeff_modulus().size();
    auto coeff_mod = first_parms.coeff_modulus();
    vector<uint32_t> coeff_mod_byte_count(coeff_mod_count);
    uint32_t coeff_sum_bytes = 0;
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        uint32_t tmp = ceil(log2(coeff_mod[i].value()) / 8.0);
        coeff_sum_bytes += tmp;
        coeff_mod_byte_count[i] = tmp;
    }
    const uint32_t seed_size = 64;
    vector<uint8_t> send_data(vct_size * (N * coeff_sum_bytes + seed_size));
    auto send_data_ptr = send_data.data();
    for (uint32_t i = 0; i < vct_size; i++) {
        Serializable<Ciphertext> send_cipher = encryptor.encrypt_symmetric(plaintext_vct[i]);
        auto cipher_ptr = ((Ciphertext*) &send_cipher)->data();
        for (uint32_t j = 0; j < coeff_mod_count; j++) {
            for (uint32_t k = 0; k < N; k++) {
                memcpy(send_data_ptr, cipher_ptr, coeff_mod_byte_count[j]);
                send_data_ptr += coeff_mod_byte_count[j];
                cipher_ptr++;
            }
        }
        uint8_t * prng_seed_ptr = (uint8_t *)((Ciphertext*) &send_cipher)->data(1);
        memcpy(send_data_ptr, prng_seed_ptr + 8 + 16 + 1, seed_size);
        send_data_ptr += seed_size;
    }
    IO.send_data(send_data.data(), vct_size * (N * coeff_sum_bytes + seed_size));
}

void recv_cipher_then_expand(const SEALContext &context, vector<Ciphertext> & ciphertext_vct, NetIO & IO) {
    uint32_t vct_size;
    IO.recv_data(&vct_size, sizeof(uint32_t));
    ciphertext_vct.resize(vct_size);

    EncryptionParameters first_parms = context.first_context_data()->parms();
    auto N = first_parms.poly_modulus_degree();
    auto coeff_mod_count = first_parms.coeff_modulus().size();
    auto coeff_mod = first_parms.coeff_modulus();
    vector<uint32_t> coeff_mod_byte_count(coeff_mod_count);
    uint32_t coeff_sum_bytes = 0;
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        uint32_t tmp = ceil(log2(coeff_mod[i].value()) / 8.0);
        coeff_sum_bytes += tmp;
        coeff_mod_byte_count[i] = tmp;
    }
    const uint32_t seed_size = 64;
    vector<uint8_t> recv_data(vct_size * (N * coeff_sum_bytes + seed_size));
    IO.recv_data(recv_data.data(), vct_size * (N * coeff_sum_bytes + seed_size));

    auto recv_data_ptr = recv_data.data();
    for (uint32_t i = 0; i < vct_size; i++) {
        ciphertext_vct[i].resize(context, context.first_parms_id(), 2);
        auto cipher_ptr = ciphertext_vct[i].data();
        for (uint32_t j = 0; j < coeff_mod_count; j++) {
            for (uint32_t k = 0; k < N; k++) {
                uint64_t tmp = 0;
                memcpy(&tmp, recv_data_ptr, coeff_mod_byte_count[j]);
                *cipher_ptr = tmp;
                recv_data_ptr += coeff_mod_byte_count[j];
                cipher_ptr++;
            }
        }
        UniformRandomGeneratorInfo prng_info;
        prng_info.type_ = prng_type::blake2xb;
        memcpy(prng_info.seed_.data(), recv_data_ptr, seed_size);
        recv_data_ptr += seed_size;
        auto prng = prng_info.make_prng();
        seal::util::sample_poly_uniform(prng, first_parms, ciphertext_vct[i].data(1));
    }
}

void send_ciphertext(const Ciphertext & ciphertext, NetIO & IO) {
    std::stringstream tmp_os;
    ciphertext.save(tmp_os);
    uint32_t len = tmp_os.str().length();
//    cout << "send ct size = " << tmp_os.str().length() << endl;
    IO.send_data(&len, sizeof(uint32_t));
    IO.send_data(tmp_os.str().c_str(), len);
}

void recv_ciphertext(const SEALContext &context, Ciphertext & ciphertext, NetIO & IO) {
    uint32_t len;
    IO.recv_data(&len, sizeof(uint32_t));
    vector<char> serialized_ciphertext(len);
    IO.recv_data(serialized_ciphertext.data(), len);
    std::stringstream tmp_os;
    tmp_os.write(serialized_ciphertext.data(), len);
    ciphertext.load(context, tmp_os);
}

void send_ciphertext(const vector<Ciphertext> & ciphertext_vct, NetIO & IO) {
    uint32_t vct_size = ciphertext_vct.size();
    IO.send_data(&vct_size, sizeof(uint32_t));
    vector<stringstream> os_vct(vct_size);
    for (uint32_t i = 0; i < vct_size; i++) {
        ciphertext_vct[i].save(os_vct[i]);
    }
    for (uint32_t i = 0; i < vct_size; i++) {
        uint32_t len = os_vct[i].str().length();
        IO.send_data(&len, sizeof(uint32_t));
        IO.send_data(os_vct[i].str().c_str(), len);
    }
}

void recv_ciphertext(const SEALContext & context, vector<Ciphertext> & ciphertext, NetIO & IO) {
    uint32_t vct_size;
    IO.recv_data(&vct_size, sizeof(uint32_t));
    ciphertext.resize(vct_size);
    vector<stringstream> os_vct(vct_size);
    for (uint32_t i = 0; i < vct_size; i++) {
        uint32_t len;
        IO.recv_data(&len, sizeof(uint32_t));
        vector<char> tmp_data(len);
        IO.recv_data(tmp_data.data(), len);
        os_vct[i].write(tmp_data.data(), len);
    }
    for (uint32_t i = 0; i < vct_size; i++) {
        ciphertext[i].load(context, os_vct[i]);
    }
}

void send_final_ciphertext(const SEALContext & context, const Ciphertext & ciphertext, const vector<uint32_t> & used_coefficient_index, NetIO & IO) {
    EncryptionParameters last_parms = context.last_context_data()->parms();
    auto N = last_parms.poly_modulus_degree();
    auto coeff_mod_count = last_parms.coeff_modulus().size();
    auto coeff_mod = last_parms.coeff_modulus();
    vector<uint32_t> coeff_mod_byte_count(coeff_mod_count);
    uint32_t coeff_sum_bytes = 0;
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        uint32_t tmp = ceil(log2(coeff_mod[i].value()) / 8.0);
        coeff_sum_bytes += tmp;
        coeff_mod_byte_count[i] = tmp;
    }

    vector<uint8_t> send_data((used_coefficient_index.size() + N) * coeff_sum_bytes);
    auto send_data_ptr = send_data.data();

    auto cipher_ptr = ciphertext.data();
    for (uint32_t j = 0; j < coeff_mod_count; j++) {
        for (uint32_t k = 0; k < used_coefficient_index.size(); k++) {
            memcpy(send_data_ptr, cipher_ptr + used_coefficient_index[k], coeff_mod_byte_count[j]);
            send_data_ptr += coeff_mod_byte_count[j];
        }
        cipher_ptr += N;
    }
    for (uint32_t j = 0; j < coeff_mod_count; j++) {
        for (uint32_t k = 0; k < N; k++) {
            memcpy(send_data_ptr, cipher_ptr, coeff_mod_byte_count[j]);
            send_data_ptr += coeff_mod_byte_count[j];
            cipher_ptr++;
        }
    }

    IO.send_data(send_data.data(), (used_coefficient_index.size() + N) * coeff_sum_bytes);
}

void recv_final_ciphertext(const SEALContext & context, Ciphertext & ciphertext, const vector<uint32_t> & used_coefficient_index, NetIO & IO) {
    EncryptionParameters last_parms = context.last_context_data()->parms();
    auto N = last_parms.poly_modulus_degree();
    auto coeff_mod_count = last_parms.coeff_modulus().size();
    auto coeff_mod = last_parms.coeff_modulus();
    vector<uint32_t> coeff_mod_byte_count(coeff_mod_count);
    uint32_t coeff_sum_bytes = 0;
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        uint32_t tmp = ceil(log2(coeff_mod[i].value()) / 8.0);
        coeff_sum_bytes += tmp;
        coeff_mod_byte_count[i] = tmp;
    }

    vector<uint8_t> recv_data((used_coefficient_index.size() + N) * coeff_sum_bytes);
    IO.recv_data(recv_data.data(), (used_coefficient_index.size() + N) * coeff_sum_bytes);

    ciphertext.resize(context, context.last_parms_id(), 2);
    auto cipher_ptr = ciphertext.data();
    auto recv_data_ptr = recv_data.data();
    for (uint32_t j = 0; j < coeff_mod_count; j++) {
        for (uint32_t k = 0; k < used_coefficient_index.size(); k++) {
            uint64_t tmp = 0;
            memcpy(&tmp, recv_data_ptr, coeff_mod_byte_count[j]);
            *(cipher_ptr + used_coefficient_index[k]) = tmp;
            recv_data_ptr += coeff_mod_byte_count[j];
        }
        cipher_ptr += N;
    }
    for (uint32_t j = 0; j < coeff_mod_count; j++) {
        for (uint32_t k = 0; k < N; k++) {
            uint64_t tmp = 0;
            memcpy(&tmp, recv_data_ptr, coeff_mod_byte_count[j]);
            *cipher_ptr = tmp;
            recv_data_ptr += coeff_mod_byte_count[j];
            cipher_ptr++;
        }
    }
}

void send_final_ciphertext(const SEALContext & context, const vector<Ciphertext> & ciphertext_vct, const vector<uint32_t> & used_coefficient_index, NetIO & IO) {
    uint32_t vct_size = ciphertext_vct.size();
    IO.send_data(&vct_size, sizeof(uint32_t));

    EncryptionParameters last_parms = context.last_context_data()->parms();
    auto N = last_parms.poly_modulus_degree();
    auto coeff_mod_count = last_parms.coeff_modulus().size();
    auto coeff_mod = last_parms.coeff_modulus();
    vector<uint32_t> coeff_mod_byte_count(coeff_mod_count);
    uint32_t coeff_sum_bytes = 0;
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        uint32_t tmp = ceil(log2(coeff_mod[i].value()) / 8.0);
        coeff_sum_bytes += tmp;
        coeff_mod_byte_count[i] = tmp;
    }

    vector<uint8_t> send_data(vct_size * ((used_coefficient_index.size() + N) * coeff_sum_bytes));
    auto send_data_ptr = send_data.data();

    for (uint32_t i = 0; i < vct_size; i++) {
        auto cipher_ptr = ciphertext_vct[i].data();
        for (uint32_t j = 0; j < coeff_mod_count; j++) {
            for (uint32_t k = 0; k < used_coefficient_index.size(); k++) {
                memcpy(send_data_ptr, cipher_ptr + used_coefficient_index[k], coeff_mod_byte_count[j]);
                send_data_ptr += coeff_mod_byte_count[j];
            }
            cipher_ptr += N;
        }
        for (uint32_t j = 0; j < coeff_mod_count; j++) {
            for (uint32_t k = 0; k < N; k++) {
                memcpy(send_data_ptr, cipher_ptr, coeff_mod_byte_count[j]);
                send_data_ptr += coeff_mod_byte_count[j];
                cipher_ptr++;
            }
        }
    }
    IO.send_data(send_data.data(), vct_size * ((used_coefficient_index.size() + N) * coeff_sum_bytes));
}

void recv_final_ciphertext(const SEALContext & context, vector<Ciphertext> & ciphertext_vct, const vector<uint32_t> & used_coefficient_index, NetIO & IO) {
    uint32_t vct_size;
    IO.recv_data(&vct_size, sizeof(uint32_t));
    ciphertext_vct.resize(vct_size);

    EncryptionParameters last_parms = context.last_context_data()->parms();
    auto N = last_parms.poly_modulus_degree();
    auto coeff_mod_count = last_parms.coeff_modulus().size();
    auto coeff_mod = last_parms.coeff_modulus();
    vector<uint32_t> coeff_mod_byte_count(coeff_mod_count);
    uint32_t coeff_sum_bytes = 0;
    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        uint32_t tmp = ceil(log2(coeff_mod[i].value()) / 8.0);
        coeff_sum_bytes += tmp;
        coeff_mod_byte_count[i] = tmp;
    }

    vector<uint8_t> recv_data(vct_size * ((used_coefficient_index.size() + N) * coeff_sum_bytes));
    IO.recv_data(recv_data.data(), vct_size * ((used_coefficient_index.size() + N) * coeff_sum_bytes));

    auto recv_data_ptr = recv_data.data();
    for (uint32_t i = 0; i < vct_size; i++) {
        ciphertext_vct[i].resize(context, context.last_parms_id(), 2);
        auto cipher_ptr = ciphertext_vct[i].data();
        for (uint32_t j = 0; j < coeff_mod_count; j++) {
            for (uint32_t k = 0; k < used_coefficient_index.size(); k++) {
                uint64_t tmp = 0;
                memcpy(&tmp, recv_data_ptr, coeff_mod_byte_count[j]);
                *(cipher_ptr + used_coefficient_index[k]) = tmp;
                recv_data_ptr += coeff_mod_byte_count[j];
            }
            cipher_ptr += N;
        }
        for (uint32_t j = 0; j < coeff_mod_count; j++) {
            for (uint32_t k = 0; k < N; k++) {
                uint64_t tmp = 0;
                memcpy(&tmp, recv_data_ptr, coeff_mod_byte_count[j]);
                *cipher_ptr = tmp;
                recv_data_ptr += coeff_mod_byte_count[j];
                cipher_ptr++;
            }
        }
    }
}

void remove_unused_coeffient(Ciphertext & ciphertext, const vector<uint32_t> & used_coefficient_index) {
    auto N = ciphertext.poly_modulus_degree();
    auto coeff_mod_count = ciphertext.coeff_modulus_size();

    vector<uint8_t> tag(N, 0);
    for (auto p : used_coefficient_index)
        tag[p] = 1;

    for (uint32_t i = 0; i < coeff_mod_count; i++) {
        for (uint32_t k = 0; k < N; k++) {
            if (!tag[k]) {
                ciphertext.data()[i * N + k] = 0;
            }
        }
    }
}

void remove_unused_coeffient(vector<Ciphertext> & ciphertext_vct, const vector<uint32_t> & used_coefficient_index) {
    auto N = ciphertext_vct.front().poly_modulus_degree();
    auto coeff_mod_count = ciphertext_vct.front().coeff_modulus_size();

    vector<uint8_t> tag(N, 0);
    for (auto p : used_coefficient_index)
        tag[p] = 1;

    for (auto & cur_ciphertext : ciphertext_vct) {
        for (uint32_t i = 0; i < coeff_mod_count; i++) {
            for (uint32_t k = 0; k < N; k++) {
                if (!tag[k]) {
                    cur_ciphertext.data()[i * N + k] = 0;
                }
            }
        }
    }
}