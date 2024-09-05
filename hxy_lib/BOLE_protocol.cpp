#include "BOLE_protocol.h"
#include "FHE_Common.h"

BOLE_protocol::BOLE_protocol(uint32_t _party_id, NetIO * _IO, const uint32_t _bole_num) {
    party = _party_id;
    IO = _IO;
    bole_num = _bole_num;

    parms0 = make_shared<EncryptionParameters>(scheme_type::bfv);
    parms1 = make_shared<EncryptionParameters>(scheme_type::bfv);

    parms0->set_n_special_primes(0);
    parms1->set_n_special_primes(0);

    parms0->set_poly_modulus_degree(POLYNOMIAL_DEGREE);
    parms1->set_poly_modulus_degree(POLYNOMIAL_DEGREE);

    parms0->set_coeff_modulus(CoeffModulus::Create(POLYNOMIAL_DEGREE, moduli_bits));
    parms1->set_coeff_modulus(CoeffModulus::Create(POLYNOMIAL_DEGREE, moduli_bits));

    parms0->set_plain_modulus(p0);
    parms1->set_plain_modulus(p1);

    context0 = make_shared<SEALContext>(*parms0, true, sec_level_type::tc128);
    context1 = make_shared<SEALContext>(*parms1, true, sec_level_type::tc128);

    auto qualifiers0 = context0->first_context_data()->qualifiers();
    auto qualifiers1 = context1->first_context_data()->qualifiers();
    assert(qualifiers0.using_batching);
    assert(qualifiers1.using_batching);
//    cout << "p0 Batching enabled: " << boolalpha << qualifiers0.using_batching << endl;
//    cout << "p1 Batching enabled: " << boolalpha << qualifiers1.using_batching << endl;

    evaluator0 = make_shared<Evaluator>(*context0);
    evaluator1 = make_shared<Evaluator>(*context1);

    encoder0 = make_shared<BatchEncoder>(*context0);
    encoder1 = make_shared<BatchEncoder>(*context1);

    KeyGenerator keygen0(*context0), keygen1(*context1);
    SecretKey secretKey0 = keygen0.secret_key();
    SecretKey secretKey1 = keygen1.secret_key();
    PublicKey cur_publicKey0, cur_publicKey1;
    keygen0.create_public_key(cur_publicKey0);
    keygen1.create_public_key(cur_publicKey1);

    encryptor0 = make_shared<seal::Encryptor>(*context0, cur_publicKey0, secretKey0);
    encryptor1 = make_shared<seal::Encryptor>(*context1, cur_publicKey1, secretKey1);

    decryptor0 = make_shared<seal::Decryptor>(*context0, secretKey0);
    decryptor1 = make_shared<seal::Decryptor>(*context1, secretKey1);

    PublicKey tmp_publicKey0, tmp_publicKey1;
    if (party == hxy::SERVER_ID) {
        send_publickey(cur_publicKey0, *IO);
        send_publickey(cur_publicKey1, *IO);
        recv_publickey(*context0, tmp_publicKey0, *IO);
        recv_publickey(*context1, tmp_publicKey1, *IO);

    }
    if (party == hxy::CLIENT_ID) {
        recv_publickey(*context0, tmp_publicKey0, *IO);
        recv_publickey(*context1, tmp_publicKey1, *IO);
        send_publickey(cur_publicKey0, *IO);
        send_publickey(cur_publicKey1, *IO);
    }
    publicKey0 = make_shared<PublicKey>(tmp_publicKey0);
    publicKey1 = make_shared<PublicKey>(tmp_publicKey1);

    if (bole_num != 0) {
//        fake_init();
        init();
        offline_check();
    }
}

BOLE_protocol::~BOLE_protocol() {
    if (party == hxy::SERVER_ID) {
        cout << "bole used number = " << used_bole_num << ", offline num = " << bole_num << endl;
    }
}

void BOLE_protocol::offline_check() {
    const auto bw = hxy::bit_width;
    if (party == hxy::SERVER_ID) {
        vector<uint64_t> a0(bole_num), x0(bole_num);
        recv_u64_vct(a0.data(), bole_num, bw, IO);
        recv_u64_vct(x0.data(), bole_num, bw, IO);
        elementwise_addmod_inplace(bole_num, a0.data(), offline_a.data(), hxy::MOD_MASK);
        elementwise_mulmod_inplace(bole_num, x0.data(), offline_x.data(), hxy::MOD_MASK);
        bool flag = true;
        for (uint32_t i = 0; i < bole_num && flag; i++) {
            flag &= (a0[i] == x0[i] || a0[i] + 1 == x0[i] || a0[i] == x0[i] + 1);
            if (!flag) {
                cout << "error at " << i << endl;
            }
        }
        cout << "offline check result = " << boolalpha << flag << endl;
    } else {
        send_u64_vct(offline_a.data(), bole_num, bw, IO);
        send_u64_vct(offline_x.data(), bole_num, bw, IO);
    }
}

void BOLE_protocol::init() {
    IO->sync();
    uint64_t before_comm = IO->counter;
    auto before_time = high_resolution_clock::now();
    offline_a.resize(bole_num, 0);
    offline_x.resize(bole_num, 0);

    const uint32_t cipher_num = ceil(1.0 * bole_num / POLYNOMIAL_DEGREE);

    PRG prg;
    prg.random_data(offline_x.data(), bole_num * sizeof(uint64_t));
    elementwise_and_inplace(bole_num, offline_x.data(), hxy::MOD_MASK);

    vector<Plaintext> plain_x0(cipher_num), plain_x1(cipher_num);
    vector<Plaintext> plain_a0(cipher_num), plain_a1(cipher_num);
    vector<Ciphertext> cipher_a0(cipher_num), cipher_a1(cipher_num);

    for (uint32_t i = 0, cur = 0; i < cipher_num; i++) {
        vector<uint64_t> tmp_vct(POLYNOMIAL_DEGREE, 0);
        memcpy(tmp_vct.data(), offline_x.data() + cur, min(POLYNOMIAL_DEGREE, bole_num - cur) * sizeof(uint64_t));
        encoder0->encode(tmp_vct, plain_x0[i]);
        encoder1->encode(tmp_vct, plain_x1[i]);
        cur += POLYNOMIAL_DEGREE;
    }

    if (party == hxy::SERVER_ID) { // Server
//        cout << "send ciphers" << endl;
        encrypt_then_send(*context0, plain_x0, *encryptor0, *IO);
        encrypt_then_send(*context1, plain_x1, *encryptor1, *IO);

//        cout << "recv ciphers" << endl;
        recv_ciphertext(*context0, cipher_a0, *IO);
        recv_ciphertext(*context1, cipher_a1, *IO);

        cout << "noise budget = " << get_noise_budget(*decryptor0, cipher_a0) << " " << get_noise_budget(*decryptor1, cipher_a1) << endl;

        vector<uint64_t> a0(POLYNOMIAL_DEGREE), a1(POLYNOMIAL_DEGREE);
        for (uint32_t i = 0, cur = 0; i < cipher_num; i++) {
            decryptor0->decrypt(cipher_a0[i], plain_a0[i]);
            decryptor1->decrypt(cipher_a1[i], plain_a1[i]);
            encoder0->decode(plain_a0[i], a0);
            encoder1->decode(plain_a1[i], a1);
            for (uint32_t j = 0; j < min(POLYNOMIAL_DEGREE, bole_num - cur); j++) {
                offline_a[cur + j] = CRT(a0[j], a1[j]) & hxy::MOD_MASK;
            }
            cur += POLYNOMIAL_DEGREE;
        }
    } else { // Client
        prg.random_data(offline_a.data(), bole_num * sizeof(uint64_t));
        elementwise_and_inplace(bole_num, offline_a.data(), hxy::MOD_MASK);

        for (uint32_t i = 0, cur = 0; i < cipher_num; i++) {
            vector<uint64_t> tmp_vct(POLYNOMIAL_DEGREE, 0);

            memcpy(tmp_vct.data(), offline_a.data() + cur, min(POLYNOMIAL_DEGREE, bole_num - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_vct, plain_a0[i]);
            encoder1->encode(tmp_vct, plain_a1[i]);

            memcpy(tmp_vct.data(), offline_x.data() + cur, min(POLYNOMIAL_DEGREE, bole_num - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_vct, plain_x0[i]);
            encoder1->encode(tmp_vct, plain_x1[i]);

            cur += POLYNOMIAL_DEGREE;
        }

        vector<Ciphertext> cipher_x0(cipher_num), cipher_x1(cipher_num);
        recv_cipher_then_expand(*context0, cipher_x0, *IO);
        recv_cipher_then_expand(*context1, cipher_x1, *IO);
//        cout << "recv ciphers" << endl;
        for (uint32_t i = 0; i < cipher_num; i++) {
            evaluator0->multiply_plain(cipher_x0[i], plain_x0[i], cipher_a0[i]);
            evaluator0->sub_plain_inplace(cipher_a0[i], plain_a0[i]);
            evaluator0->mod_switch_to_inplace(cipher_a0[i], context0->last_parms_id());

            evaluator1->multiply_plain(cipher_x1[i], plain_x1[i], cipher_a1[i]);
            evaluator1->sub_plain_inplace(cipher_a1[i], plain_a1[i]);
            evaluator1->mod_switch_to_inplace(cipher_a1[i], context1->last_parms_id());
        }
        send_ciphertext(cipher_a0, *IO);
        send_ciphertext(cipher_a1, *IO);
//        cout << "send ciphers" << endl;
    }
    uint64_t after_comm = IO->counter;
    IO->sync();
    auto after_time = high_resolution_clock::now();
    uint64_t server_comm, client_comm;
    if (party == hxy::SERVER_ID) {
        server_comm = after_comm - before_comm;
        IO->recv_data(&client_comm, sizeof(uint64_t));
        offline_comm = client_comm + server_comm;
        offline_time = duration_cast<microseconds>(after_time - before_time).count() / 1000; // ms
        cout << "offline BOLE time = " << (double) offline_time / 1000.0 << "ms" << endl;
        cout << "offline BOLE ALL communication = " << (double) offline_comm / 1024.0 / 1024.0 << "MB" << endl;
        cout << "average BOLE comm = " << (double) offline_comm / bole_num << "Byte" << endl;
    } else {
        client_comm = after_comm - before_comm;
        IO->send_data(&client_comm, sizeof(uint64_t));
    }
}


void BOLE_protocol::BOLE_online(const uint32_t N, const uint32_t bw, const uint64_t * x, const uint64_t * y, uint64_t * z) {
    assert(bw <= hxy::bit_width);
    const uint64_t MOD_MASK = (bw == 64) ? -1ULL : (1ULL << bw) - 1;

    IO->sync();
    uint64_t before_comm = IO->counter;
    auto before_time = high_resolution_clock::now();

    const uint32_t cipher_num = ceil(1.0 * N / POLYNOMIAL_DEGREE);

    // z = (x0 * y0 + x1 * y1) + (x0 * y1 + x1 * y0)
    elementwise_mulmod(N, x, y, z, MOD_MASK); // x0 * y0 + x1 * y1

    if (party == hxy::SERVER_ID) { // Server
        vector<Plaintext> plain_x0(cipher_num), plain_x1(cipher_num);
        vector<Plaintext> plain_y0(cipher_num), plain_y1(cipher_num);
        for (uint32_t i = 0, cur = 0; i < cipher_num; i++) { // encode x_S, y_S to SIMD plaintext
            vector<uint64_t> tmp_x_vct(POLYNOMIAL_DEGREE, 0);
            memcpy(tmp_x_vct.data(), x + cur, min(POLYNOMIAL_DEGREE, N - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_x_vct, plain_x0[i]);
            encoder1->encode(tmp_x_vct, plain_x1[i]);

            vector<uint64_t> tmp_y_vct(POLYNOMIAL_DEGREE, 0);
            memcpy(tmp_y_vct.data(), y + cur, min(POLYNOMIAL_DEGREE, N - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_y_vct, plain_y0[i]);
            encoder1->encode(tmp_y_vct, plain_y1[i]);

            cur += POLYNOMIAL_DEGREE;
        }
        cout << "encoded" << endl;

        encrypt_then_send(*context0, plain_x0, *encryptor0, *IO);
        encrypt_then_send(*context1, plain_x1, *encryptor1, *IO);
        encrypt_then_send(*context0, plain_y0, *encryptor0, *IO);
        encrypt_then_send(*context1, plain_y1, *encryptor1, *IO);
        cout << "send ciphers over" << endl;

        vector<Ciphertext> cipher_z0(cipher_num), cipher_z1(cipher_num);

        recv_ciphertext(*context0, cipher_z0, *IO);
        recv_ciphertext(*context1, cipher_z1, *IO);
        cout << "recv ciphers over" << endl;

        cout << "noise budget = " << get_noise_budget(*decryptor0, cipher_z0) << " " << get_noise_budget(*decryptor1, cipher_z1) << endl;

        vector<Plaintext> plain_z0(cipher_num), plain_z1(cipher_num);
        vector<uint64_t> z0(POLYNOMIAL_DEGREE), z1(POLYNOMIAL_DEGREE);
        for (uint32_t i = 0, cur = 0; i < cipher_num; i++) {
            decryptor0->decrypt(cipher_z0[i], plain_z0[i]);
            decryptor1->decrypt(cipher_z1[i], plain_z1[i]);
            encoder0->decode(plain_z0[i], z0);
            encoder1->decode(plain_z1[i], z1);
            for (uint32_t j = 0; j < min(POLYNOMIAL_DEGREE, N - cur); j++) {
                z[cur + j] = (z[cur + j] + CRT(z0[j], z1[j])) & MOD_MASK;
            }
            cur += POLYNOMIAL_DEGREE;
        }
    } else { // Client
        vector<uint64_t> c(N);
        PRG prg;
        prg.random_data(c.data(), N * sizeof(uint64_t));
        elementwise_and_inplace(N, c.data(), MOD_MASK);
        elementwise_addmod_inplace(N, z, c.data(), MOD_MASK);

        vector<Plaintext> plain_x0(cipher_num), plain_x1(cipher_num);
        vector<Plaintext> plain_y0(cipher_num), plain_y1(cipher_num);
        vector<Plaintext> plain_c0(cipher_num), plain_c1(cipher_num);
        for (uint32_t i = 0, cur = 0; i < cipher_num; i++) { // encode x_S, y_S to SIMD plaintext
            vector<uint64_t> tmp_x_vct(POLYNOMIAL_DEGREE, 0);
            memcpy(tmp_x_vct.data(), x + cur, min(POLYNOMIAL_DEGREE, N - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_x_vct, plain_x0[i]);
            encoder1->encode(tmp_x_vct, plain_x1[i]);

            vector<uint64_t> tmp_y_vct(POLYNOMIAL_DEGREE, 0);
            memcpy(tmp_y_vct.data(), y + cur, min(POLYNOMIAL_DEGREE, N - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_y_vct, plain_y0[i]);
            encoder1->encode(tmp_y_vct, plain_y1[i]);

            vector<uint64_t> tmp_c_vct(POLYNOMIAL_DEGREE, 0);
            memcpy(tmp_c_vct.data(), c.data() + cur, min(POLYNOMIAL_DEGREE, N - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_c_vct, plain_c0[i]);
            encoder1->encode(tmp_c_vct, plain_c1[i]);

            cur += POLYNOMIAL_DEGREE;
        }
        cout << "encoded" << endl;

        vector<Ciphertext> cipher_x0(cipher_num), cipher_x1(cipher_num);
        vector<Ciphertext> cipher_y0(cipher_num), cipher_y1(cipher_num);
        vector<Ciphertext> cipher_z0(cipher_num), cipher_z1(cipher_num);
        recv_cipher_then_expand(*context0, cipher_x0, *IO);
        recv_cipher_then_expand(*context1, cipher_x1, *IO);
        recv_cipher_then_expand(*context0, cipher_y0, *IO);
        recv_cipher_then_expand(*context1, cipher_y1, *IO);
        cout << "recv ciphers over" << endl;

        for (uint32_t i = 0; i < cipher_num; i++) {
            evaluator0->multiply_plain_inplace(cipher_x0[i], plain_y0[i]); // x_S * y_C
            evaluator1->multiply_plain_inplace(cipher_x1[i], plain_y1[i]);

            evaluator0->multiply_plain_inplace(cipher_y0[i], plain_x0[i]); // y_S * s_C
            evaluator1->multiply_plain_inplace(cipher_y1[i], plain_x1[i]);

            evaluator0->add(cipher_x0[i], cipher_y0[i], cipher_z0[i]);
            evaluator0->sub_plain_inplace(cipher_z0[i], plain_c0[i]);
            evaluator0->mod_switch_to_inplace(cipher_z0[i], context0->last_parms_id());

            evaluator1->add(cipher_x1[i], cipher_y1[i], cipher_z1[i]);
            evaluator1->sub_plain_inplace(cipher_z1[i], plain_c1[i]);
            evaluator1->mod_switch_to_inplace(cipher_z1[i], context1->last_parms_id());
        }
        send_ciphertext(cipher_z0, *IO);
        send_ciphertext(cipher_z1, *IO);
        cout << "send ciphers over" << endl;
    }
    uint64_t after_comm = IO->counter;
    IO->sync();
    auto after_time = high_resolution_clock::now();
    uint64_t server_comm, client_comm;
    if (party == hxy::SERVER_ID) {
        server_comm = after_comm - before_comm;
        IO->recv_data(&client_comm, sizeof(uint64_t));
        uint64_t online_comm = client_comm + server_comm;
        uint64_t online_time = duration_cast<microseconds>(after_time - before_time).count() / 1000; // ms
        cout << "online BOLE batch size = " << N << endl;
        cout << "online BOLE time = " << (double) online_time << "ms" << endl;
        cout << "online BOLE ALL communication = " << (double) online_comm / 1024.0 / 1024.0 << "MB" << endl;
        cout << "average BOLE comm = " << (double) online_comm / N << " bytes" << endl;
    } else {
        client_comm = after_comm - before_comm;
        IO->send_data(&client_comm, sizeof(uint64_t));
    }
}


void BOLE_protocol::BOLE_square_online(const uint32_t N, const uint32_t bw, const uint64_t * x, uint64_t * z) {
    assert(bw <= hxy::bit_width);
    const uint64_t MOD_MASK = (bw == 64) ? -1ULL : (1ULL << bw) - 1;

    IO->sync();
    uint64_t before_comm = IO->counter;
    auto before_time = high_resolution_clock::now();

    const uint32_t cipher_num = ceil(1.0 * N / POLYNOMIAL_DEGREE);

    // x^2 = (x_S * x_S + x_C * x_C) + 2 * (x_S * x_C)
    elementwise_mulmod(N, x, x, z, MOD_MASK);

    if (party == hxy::SERVER_ID) { // Server
        vector<Plaintext> plain_x0(cipher_num), plain_x1(cipher_num);
        for (uint32_t i = 0, cur = 0; i < cipher_num; i++) { // encode x_S, y_S to SIMD plaintext
            vector<uint64_t> tmp_x_vct(POLYNOMIAL_DEGREE, 0);
            memcpy(tmp_x_vct.data(), x + cur, min(POLYNOMIAL_DEGREE, N - cur) * sizeof(uint64_t));
            elementwise_mulmod_inplace(POLYNOMIAL_DEGREE, tmp_x_vct.data(), (uint64_t) 2, MOD_MASK);
            // 2 * x_S
            encoder0->encode(tmp_x_vct, plain_x0[i]);
            encoder1->encode(tmp_x_vct, plain_x1[i]);

            cur += POLYNOMIAL_DEGREE;
        }
//        cout << "encoded" << endl;

        encrypt_then_send(*context0, plain_x0, *encryptor0, *IO);
        encrypt_then_send(*context1, plain_x1, *encryptor1, *IO);
//        cout << "send ciphers over" << endl;

        vector<Ciphertext> cipher_z0(cipher_num), cipher_z1(cipher_num);

        recv_ciphertext(*context0, cipher_z0, *IO);
        recv_ciphertext(*context1, cipher_z1, *IO);
//        cout << "recv ciphers over" << endl;

//        cout << "noise budget = " << get_noise_budget(*decryptor0, cipher_z0) << " " << get_noise_budget(*decryptor1, cipher_z1) << endl;

        vector<Plaintext> plain_z0(cipher_num), plain_z1(cipher_num);
        vector<uint64_t> z0(POLYNOMIAL_DEGREE), z1(POLYNOMIAL_DEGREE);
        for (uint32_t i = 0, cur = 0; i < cipher_num; i++) {
            decryptor0->decrypt(cipher_z0[i], plain_z0[i]);
            decryptor1->decrypt(cipher_z1[i], plain_z1[i]);
            encoder0->decode(plain_z0[i], z0);
            encoder1->decode(plain_z1[i], z1);
            for (uint32_t j = 0; j < min(POLYNOMIAL_DEGREE, N - cur); j++) {
                z[cur + j] = (z[cur + j] + CRT(z0[j], z1[j])) & MOD_MASK;
            }
            cur += POLYNOMIAL_DEGREE;
        }
    } else { // Client
        vector<uint64_t> c(N);
        PRG prg;
        prg.random_data(c.data(), N * sizeof(uint64_t));
        elementwise_and_inplace(N, c.data(), MOD_MASK);
        elementwise_addmod_inplace(N, z, c.data(), MOD_MASK);

        vector<Plaintext> plain_x0(cipher_num), plain_x1(cipher_num);
        vector<Plaintext> plain_c0(cipher_num), plain_c1(cipher_num);
        for (uint32_t i = 0, cur = 0; i < cipher_num; i++) { // encode x_S, y_S to SIMD plaintext
            vector<uint64_t> tmp_x_vct(POLYNOMIAL_DEGREE, 0);
            memcpy(tmp_x_vct.data(), x + cur, min(POLYNOMIAL_DEGREE, N - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_x_vct, plain_x0[i]);
            encoder1->encode(tmp_x_vct, plain_x1[i]);

            vector<uint64_t> tmp_c_vct(POLYNOMIAL_DEGREE, 0);
            memcpy(tmp_c_vct.data(), c.data() + cur, min(POLYNOMIAL_DEGREE, N - cur) * sizeof(uint64_t));
            encoder0->encode(tmp_c_vct, plain_c0[i]);
            encoder1->encode(tmp_c_vct, plain_c1[i]);

            cur += POLYNOMIAL_DEGREE;
        }
//        cout << "encoded" << endl;

        vector<Ciphertext> cipher_x0(cipher_num), cipher_x1(cipher_num);
        vector<Ciphertext> cipher_z0(cipher_num), cipher_z1(cipher_num);
        recv_cipher_then_expand(*context0, cipher_x0, *IO);
        recv_cipher_then_expand(*context1, cipher_x1, *IO);
//        cout << "recv ciphers over" << endl;

        for (uint32_t i = 0; i < cipher_num; i++) {
            evaluator0->multiply_plain(cipher_x0[i], plain_x0[i], cipher_z0[i]); // 2 * x_S * x_C
            evaluator1->multiply_plain(cipher_x1[i], plain_x1[i], cipher_z1[i]);

            evaluator0->sub_plain_inplace(cipher_z0[i], plain_c0[i]);
            evaluator0->mod_switch_to_inplace(cipher_z0[i], context0->last_parms_id());

            evaluator1->sub_plain_inplace(cipher_z1[i], plain_c1[i]);
            evaluator1->mod_switch_to_inplace(cipher_z1[i], context1->last_parms_id());
        }
        send_ciphertext(cipher_z0, *IO);
        send_ciphertext(cipher_z1, *IO);
//        cout << "send ciphers over" << endl;
    }
    uint64_t after_comm = IO->counter;
    IO->sync();
    auto after_time = high_resolution_clock::now();
    uint64_t server_comm, client_comm;
    if (party == hxy::SERVER_ID) {
        server_comm = after_comm - before_comm;
        IO->recv_data(&client_comm, sizeof(uint64_t));
        uint64_t online_comm = client_comm + server_comm;
        uint64_t online_time = duration_cast<microseconds>(after_time - before_time).count() / 1000; // ms
//        cout << "online BOLE square batch size = " << N << endl;
//        cout << "online BOLE square time = " << (double) online_time << "ms" << endl;
//        cout << "online BOLE square ALL communication = " << (double) online_comm / 1024.0 / 1024.0 << "MB" << endl;
//        cout << "average BOLE square comm = " << fixed << setprecision(2) << (double) online_comm / N << " byte" << endl;
    } else {
        client_comm = after_comm - before_comm;
        IO->send_data(&client_comm, sizeof(uint64_t));
    }
}