#include "SPLUT.h"

SPLUT_protocol::SPLUT_protocol(uint32_t _party_id, NetIO * _IO, AND_protocol * _and_protocol, uint64_t _ROT_number) {
    this->party = _party_id;
    this->IO = _IO;
    this->and_protocol = _and_protocol;
    this->ROT_number = _ROT_number;
    this->used_ROT_num = 0;
    block aes_key;
    if (party == hxy::SERVER_ID) {
        PRG prg;
        prg.random_block(&hash_key, 1);
        IO->send_block(&hash_key, 1);

        prg.random_block(&aes_key, 1);
        IO->send_block(&aes_key, 1);
    } else {
        IO->recv_block(&hash_key, 1);
        IO->recv_block(&aes_key, 1);
        IO->flush();
    }
    AES_set_encrypt_key(aes_key, &common_AES);
    if (ROT_number != 0) {
        offline_LUT();
    }
}

SPLUT_protocol::~SPLUT_protocol() {
    if (ROT_number == 0 && used_ROT_num == 0)
        return;
    if (party == hxy::SERVER_ID) {
        cout << "-----------SPLUT_protocol-----------" << endl;
        if (ROT_number < used_ROT_num) cout << "Too less!" << endl;
        else cout << "OK" << endl;
        cout << "SPLUT ROT used = " << used_ROT_num << ", offline ROT num = " << ROT_number << endl;
        cout << "----------------------------------" << endl;
    }
}

void SPLUT_protocol::offline_LUT() {
    IO->sync();
    auto before_offline_comm = IO->counter;
    auto before_offline_time = high_resolution_clock::now();

    MITCCRH<ot_bsize> mitccrh;
    mitccrh.setS(hash_key);
    std::array<block, ot_bsize * 2> pad;

    if (party == hxy::SERVER_ID) {
        OT_messages0.resize(ROT_number);
        OT_messages1.resize(ROT_number);
    } else {
        ROT_received_msg.resize(ROT_number);
        choice.resize(ROT_number);
    }

    auto data0 = (block *) OT_messages0.data();
    auto data1 = (block *) OT_messages1.data();
    auto data = ROT_received_msg.data();

    if (party == hxy::SERVER_ID) {
        auto * ferretcot_send = new FerretCOT<emp::NetIO>(ALICE, 1, (emp::NetIO**)(&IO), false, true, ferret_b13, "server_send.txt");
        ferretcot_send->rcot(data0, ROT_number);
        block Delta = ferretcot_send->Delta;
        for (int64_t i = 0; i < ROT_number; i += ot_bsize) {
            for (int64_t j = i; j < min((uint64_t)i + ot_bsize, ROT_number); ++j) {
                pad[2*(j-i)] = data0[j];
                pad[2*(j-i)+1] = data0[j] ^ Delta;
            }
            mitccrh.hash<ot_bsize, 2> (pad.data());
            for (int64_t j = i; j < min((uint64_t)i + ot_bsize, ROT_number); ++j) {
                data0[j] = pad[2*(j-i)];
                data1[j] = pad[2*(j-i)+1];
            }
        }
        delete ferretcot_send;

//        system("rm -f server_send.txt");
    } else {
        auto * ferretcot_receive = new FerretCOT<emp::NetIO>(BOB, 1, (emp::NetIO**)(&IO), false, true, ferret_b13, "client_receive.txt");
        ferretcot_receive->rcot(data, ROT_number);
        for (uint32_t i = 0; i < ROT_number; i++)
            choice[i] = emp::getLSB(data[i]);
        for (int64_t i = 0; i < ROT_number; i += ot_bsize) {
            memcpy(pad.data(), data+i, min((uint64_t)ot_bsize, ROT_number - i) * sizeof(block));
            mitccrh.hash<ot_bsize, 1>(pad.data());
            memcpy(data+i, pad.data(), min((uint64_t)ot_bsize, ROT_number - i) * sizeof(block));
        }
        delete ferretcot_receive;

//        system("rm -f client_receive.txt");
    }
    auto after_offline_comm = IO->counter;
    IO->sync();
    auto after_offline_time = high_resolution_clock::now();

    uint64_t server_comm, client_comm;
    if (party == hxy::SERVER_ID) {
        server_comm = after_offline_comm - before_offline_comm;
        IO->recv_data(&client_comm, sizeof(uint64_t));
        this->offline_comm = client_comm + server_comm;
        this->offline_time = duration_cast<microseconds>(after_offline_time - before_offline_time).count() / 1000;
    } else {
        client_comm = after_offline_comm - before_offline_comm;
        IO->send_data(&client_comm, sizeof(uint64_t));
    }
}

void SPLUT_protocol::mill_and_equal_test_1_bit(const uint32_t dim, const uint8_t * x, uint8_t * mill_res, uint8_t * equal_test_res) {
    vector<uint8_t> and_input(dim), zero_vct(dim, 0);
    memcpy(and_input.data(), x, dim);
    // (x_S > x_C) <-> (x_S and (1 xor x_C))
    if (party == hxy::SERVER_ID) {
        and_protocol->AND(dim, and_input.data(), zero_vct.data(), mill_res);
    } else {
        elementwise_xor_inplace(dim, and_input.data(), (uint8_t)1);
        and_protocol->AND(dim, zero_vct.data(), and_input.data(), mill_res);
    }
    // (x_S == x_C) <-> (x_S xor x_C xor 1)
    memcpy(equal_test_res, x, dim);
    if (party == hxy::SERVER_ID)
        elementwise_xor_inplace(dim, equal_test_res, (uint8_t)1);
}

void SPLUT_protocol::fake_lookup_table(const uint32_t len, const uint32_t input_bw, const uint32_t output_bw,
                                       const uint64_t * public_table, const uint8_t * x, uint64_t * res) {
    const uint32_t table_size = (1 << input_bw);
    const uint8_t index_MASK = (input_bw == 8) ? -1u : (1u << input_bw) - 1;
    const uint64_t MOD_MASK = (output_bw == 64) ? -1ULL : (1ULL << output_bw) - 1;

    vector<uint8_t> masked_index(len);
    vector<uint64_t> masked_value(len * table_size);
    if (party == hxy::SERVER_ID) { // Server
        recv_uint8_vct(masked_index.data(), len, input_bw, IO);

        PRG prg;
        prg.random_data(masked_value.data(), len * table_size * sizeof(uint64_t));
        elementwise_and_inplace(len * table_size, masked_value.data(), MOD_MASK);
        send_u64_vct(masked_value.data(), len * table_size, output_bw, IO);

        for (uint32_t i = 0; i < len; i++)
            res[i] = public_table[(x[i] + masked_index[i]) & index_MASK] & MOD_MASK;
    } else { // Client
        memcpy(masked_index.data(), x, len);
        send_uint8_vct(masked_index.data(), len, input_bw, IO);
        recv_u64_vct(masked_value.data(), len * table_size, output_bw, IO);

        memset(res, 0, len * sizeof(uint64_t));
    } // Client Over
    used_ROT_num += len * input_bw;
}

void SPLUT_protocol::lookup_table(const uint32_t len, const uint32_t input_bw, const uint32_t output_bw,
                                  const uint64_t * public_table, const uint8_t * x, uint64_t * res) {
    assert(2 <= input_bw && input_bw <= 8);
    assert(1 <= output_bw && output_bw <= 64);

    if (used_ROT_num + len * input_bw > ROT_number) {
        fake_lookup_table(len, input_bw, output_bw, public_table, x, res);
        return;
    }

    const uint32_t table_size = (1 << input_bw);
    const uint8_t index_MASK = (input_bw == 8) ? -1u : (1u << input_bw) - 1;
    const uint64_t MOD_MASK = (output_bw == 64) ? -1ULL : (1ULL << output_bw) - 1;

    vector<uint8_t> masked_index(len, 0);
    vector<uint64_t> masked_value(len * table_size, 0);
    vector<block> server_mask, client_mask;

    if (party == hxy::SERVER_ID) { // Server
        server_mask.resize(len * table_size, zero_block);
        for (uint32_t i = 0; i < len; i++) {
            for (uint32_t j = 0; j < input_bw; j++) {
                if (j != 0)
                    for (uint32_t k = 0; k < (1 << j); k++)
                        server_mask[i * table_size + (1 << j) + k] = server_mask[i * table_size + k];
                for (uint32_t k = 0; k < (1 << j); k++)
                    server_mask[i * table_size + k] ^= OT_messages0[used_ROT_num + i * input_bw + j];
                for (uint32_t k = 0; k < (1 << j); k++)
                    server_mask[i * table_size + (1 << j) + k] ^= OT_messages1[used_ROT_num + i * input_bw + j];
            }
            for (uint32_t j = 0; j < table_size; j++)
                CCR_function_H_inplace(server_mask[i * table_size + j], common_AES);
        }
        for (uint32_t i = 0; i < table_size; i++)
            cout << i << " : " << server_mask[i] << endl;
        cout << endl;
    } else { // Client
        client_mask.resize(len, zero_block);
        for (uint32_t i = 0; i < len; i++) {
            for (uint32_t j = 0; j < input_bw; j++) {
                client_mask[i] ^= ROT_received_msg[used_ROT_num + i * input_bw + j];
                masked_value[i] = ((masked_value[i] << 1) | choice[used_ROT_num + i * input_bw + (input_bw - j - 1)]);
            }
            CCR_function_H_inplace(client_mask[i], common_AES);
        }
        cout << "choice = " << masked_value[0] << ", value mask = " << client_mask[0] << endl;
    } // Client Over

    if (party == hxy::SERVER_ID) { // Server
        PRG prg;
        prg.random_data(res, len * sizeof(uint64_t));
        elementwise_and_inplace(len, res, MOD_MASK);

    } else { // Client

    } // Client Over
    used_ROT_num += len * input_bw;
}