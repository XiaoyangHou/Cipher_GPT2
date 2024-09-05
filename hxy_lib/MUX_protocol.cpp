#include "MUX_protocol.h"

MUX_protocol::MUX_protocol(uint32_t _party_id, NetIO * _IO, int64_t _ROT_number) {
    party = _party_id;
    IO = _IO;
    ROT_number = _ROT_number;
    MUX_used = 0;
    PRG prg = PRG();
    if (party == hxy::SERVER_ID) {
        prg.random_block(&hash_key, 1);
        IO->send_block(&hash_key, 1);
    } else {
        IO->recv_block(&hash_key, 1);
        IO->flush();
    }
    if (ROT_number != 0)
        offline_MUX();
}

MUX_protocol::~MUX_protocol() {
    if (party == hxy::SERVER_ID) {
        cout << "-----------MUX_protocol-----------" << endl;
        if (ROT_number < MUX_used) cout << "Too less!" << endl;
        if (MUX_used <= ROT_number) cout << "OK" << endl;
        cout << "MUX used = " << MUX_used << ", offline num = " << ROT_number << endl;
        cout << "----------------------------------" << endl;
    }
}

uint64_t MUX_protocol::offline_MUX() {
    IO->sync();
    auto before_offline_MUX_comm = IO->counter;
    auto before_offline_MUX_time = high_resolution_clock::now();

    rot_msg0.resize(ROT_number);
    rot_msg1.resize(ROT_number);
    rot_recv_msg.resize(ROT_number);
    rot_choice.resize(ROT_number);

    vector<uint8_t> choice(ROT_number);
    vector<block> ROT_received_msg(ROT_number);
    vector<block> OT_messages0(ROT_number);
    vector<block> OT_messages1(ROT_number);
    MITCCRH<ot_bsize> mitccrh;
    mitccrh.setS(hash_key);
    std::array<block, ot_bsize * 2> pad;
    auto data0 = (block *) OT_messages0.data();
    auto data1 = (block *) OT_messages1.data();
    auto data = ROT_received_msg.data();

    if (party == hxy::SERVER_ID) {
        auto * ferretcot_send = new FerretCOT<emp::NetIO>(ALICE, 1, (emp::NetIO**)(&IO), false, true, ferret_b13, "server_send.txt");
        ferretcot_send->rcot(data0, ROT_number);
        block Delta = ferretcot_send->Delta;
        for (int64_t i = 0; i < ROT_number; i += ot_bsize) {
            for (int64_t j = i; j < min(i + ot_bsize, ROT_number); ++j) {
                pad[2*(j-i)] = data0[j];
                pad[2*(j-i)+1] = data0[j] ^ Delta;
            }
            mitccrh.hash<ot_bsize, 2> (pad.data());
            for (int64_t j = i; j < min(i + ot_bsize, ROT_number); ++j) {
                data0[j] = pad[2*(j-i)];
                data1[j] = pad[2*(j-i)+1];
            }
        }
        delete ferretcot_send;

        auto * ferretcot_receive = new FerretCOT<emp::NetIO>(BOB, 1, (emp::NetIO**)(&IO), false, true, ferret_b13, "server_receive.txt");
        ferretcot_receive->rcot(data, ROT_number);
        for (uint32_t i = 0; i < ROT_number; i++)
            choice[i] = emp::getLSB(data[i]);
        for (int64_t i = 0; i < ROT_number; i += ot_bsize) {
            memcpy(pad.data(), data+i, min(ot_bsize, ROT_number - i) * sizeof(block));
            mitccrh.hash<ot_bsize, 1>(pad.data());
            memcpy(data+i, pad.data(), min(ot_bsize, ROT_number - i) * sizeof(block));
        }
        delete ferretcot_receive;

//        system("rm -f server_send.txt");
//        system("rm -f server_receive.txt");
    } else {
        auto * ferretcot_receive = new FerretCOT<emp::NetIO>(BOB, 1, (emp::NetIO**)(&IO), false, true, ferret_b13, "client_receive.txt");
        ferretcot_receive->rcot(data, ROT_number);
        for (uint32_t i = 0; i < ROT_number; i++)
            choice[i] = emp::getLSB(data[i]);
        for (int64_t i = 0; i < ROT_number; i += ot_bsize) {
            memcpy(pad.data(), data+i, min(ot_bsize, ROT_number - i) * sizeof(block));
            mitccrh.hash<ot_bsize, 1>(pad.data());
            memcpy(data+i, pad.data(), min(ot_bsize, ROT_number - i) * sizeof(block));
        }
        delete ferretcot_receive;

        auto * ferretcot_send = new FerretCOT<emp::NetIO>(ALICE, 1, (emp::NetIO**)(&IO), false, true, ferret_b13, "client_send.txt");
        ferretcot_send->rcot(data0, ROT_number);
        block Delta = ferretcot_send->Delta;
        for (int64_t i = 0; i < ROT_number; i += ot_bsize) {
            for (int64_t j = i; j < min(i + ot_bsize, ROT_number); ++j) {
                pad[2*(j-i)] = data0[j];
                pad[2*(j-i)+1] = data0[j] ^ Delta;
            }
            mitccrh.hash<ot_bsize, 2> (pad.data());
            for (int64_t j = i; j < min(i + ot_bsize, ROT_number); ++j) {
                data0[j] = pad[2*(j-i)];
                data1[j] = pad[2*(j-i)+1];
            }
        }
        delete ferretcot_send;

//        system("rm -f client_send.txt");
//        system("rm -f client_receive.txt");
    }
    for (uint32_t i = 0; i < ROT_number; i++) {
        rot_msg0[i] = *(uint64_t*)&data0[i];
        rot_msg1[i] = *(uint64_t*)&data1[i];
        rot_recv_msg[i] = *(uint64_t*)&data[i];
        rot_choice[i] = choice[i];
    }
    auto after_offline_MUX_comm = IO->counter;
    IO->sync();
    auto after_offline_MUX_time = high_resolution_clock::now();

    uint64_t client_comm;
    if (party == hxy::SERVER_ID) {
        uint64_t server_comm = after_offline_MUX_comm - before_offline_MUX_comm;
        IO->recv_data(&client_comm, sizeof(uint64_t));
//        cout << "offline MUX time = " << (double)duration_cast<microseconds>(after_offline_MUX_time - before_offline_MUX_time).count() / 1000.0 << "ms" << endl;
//        cout << "offline MUX ALL send = " << (double)(client_comm + server_comm) / 1024.0 / 1024.0 << "MB" << endl;
        offline_comm = client_comm + server_comm;
        offline_time = duration_cast<microseconds>(after_offline_MUX_time - before_offline_MUX_time).count() / 1000;
    } else {
        client_comm = after_offline_MUX_comm - before_offline_MUX_comm;
        IO->send_data(&client_comm, sizeof(uint64_t));
    }
#ifdef CHECK
    if (party == hxy::SERVER_ID) {
        vector<uint64_t> client_send_msg0(ROT_number), client_send_msg1(ROT_number), client_recv_msg(ROT_number);
        vector<uint8_t> client_recv_choice(ROT_number);
        IO->recv_data(client_send_msg0.data(), ROT_number * sizeof(uint64_t));
        IO->recv_data(client_send_msg1.data(), ROT_number * sizeof(uint64_t));
        IO->recv_data(client_recv_msg.data(), ROT_number * sizeof(uint64_t));
        recv_bool_vct((bool *)client_recv_choice.data(), ROT_number, IO);
        bool flag = true;
        for (uint32_t i = 0; i < ROT_number; i++) {
            flag &= (client_recv_msg[i] == (client_recv_choice[i] ? rot_msg1[i] : rot_msg0[i]));
            flag &= (rot_recv_msg[i] == (rot_choice[i] ? client_send_msg1[i] : client_send_msg0[i]));
        }
        cout << "offline MUX check result = " << boolalpha << flag << endl;
    } else {
        IO->send_data(rot_msg0.data(), ROT_number * sizeof(uint64_t));
        IO->send_data(rot_msg1.data(), ROT_number * sizeof(uint64_t));
        IO->send_data(rot_recv_msg.data(), ROT_number * sizeof(uint64_t));
        send_bool_vct((bool *)rot_choice.data(), ROT_number, IO);
    }
#endif
    return duration_cast<microseconds>(after_offline_MUX_time - before_offline_MUX_time).count();
}

void MUX_protocol::online_MUX(const uint32_t batch_size, const uint8_t *choice, const uint64_t *x, uint64_t *res, const uint32_t output_bw) {
    vector<uint64_t> zero_shares(batch_size, 0);
    if (MUX_used + batch_size <= ROT_number)
        MUX(batch_size, choice, zero_shares.data(), x, res, output_bw);
    else
        _fake_MUX(batch_size, choice, zero_shares.data(), x, res, output_bw);

}

void MUX_protocol::online_MUX(const uint32_t batch_size, const uint8_t *choice, const uint64_t *x, const uint64_t *y, uint64_t *res, const uint32_t output_bw) {
    if (MUX_used + batch_size <= ROT_number)
        MUX(batch_size, choice, x, y, res, output_bw);
    else
        _fake_MUX(batch_size, choice, x, y, res, output_bw);

#ifdef CHECK
    const uint64_t MOD_MASK = (output_bw == 64 ? -1ULL : (1ULL << output_bw) - 1);
    if (party == hxy::SERVER_ID) {
        vector<uint64_t> x0(ROT_number), y0(ROT_number), res0(ROT_number);
        vector<uint8_t> choice0(ROT_number);
        IO->recv_data(x0.data(), batch_size * sizeof(uint64_t));
        IO->recv_data(y0.data(), batch_size * sizeof(uint64_t));
        IO->recv_data(res0.data(), batch_size * sizeof(uint64_t));
        recv_bool_vct((bool *)choice0.data(), batch_size, IO);
        bool flag = true;
        for (uint32_t i = 0; i < batch_size && flag; i++) {
            x0[i] = (x0[i] + x[i]) & MOD_MASK;
            y0[i] = (y0[i] + y[i]) & MOD_MASK;
            res0[i] = (res[i] + res0[i]) & MOD_MASK;
            choice0[i] = (choice0[i] ^ choice[i]);
            flag &= (res0[i] == (choice0[i] ? y0[i] : x0[i]));
            if (!flag) {
                cout << "error at " << i << endl;
                cout <<  "x = " << x0[i] << ", y = " << y0[i] << endl;
                cout << "choice = " << (uint32_t)choice0[i] << endl;
                cout << "MUX res = " << res0[i] << endl;
            }
        }
        cout << "online MUX check result = " << boolalpha << flag << endl;
    } else {
        IO->send_data(x, batch_size * sizeof(uint64_t));
        IO->send_data(y, batch_size * sizeof(uint64_t));
        IO->send_data(res, batch_size * sizeof(uint64_t));
        send_bool_vct((bool *)choice, batch_size, IO);
    }
#endif
}

//void MUX_protocol::MUX(const uint32_t batch_size, const uint8_t *choice, const uint64_t *x, const uint64_t *y, uint64_t *res, const uint32_t output_bw) {
//    // 1-out-of-2 ROT based
//    IO->sync();
//    auto before_online_MUX_comm = IO->counter;
//    auto before_online_MUX_time = high_resolution_clock::now();
//
//    const uint64_t MOD_MASK = (output_bw == 64 ? -1ULL : (1ULL << output_bw) - 1);
//
//    vector<uint8_t> send_masked_index(batch_size), recv_masked_index(batch_size);
//    vector<uint64_t> send_OT_msg(batch_size * 2), recv_OT_msg(batch_size * 2);
//
//    PRG prg;
//    prg.random_data(res, batch_size * sizeof(uint64_t));
//
//    for (uint32_t i = 0; i < batch_size; i++) {
//        send_masked_index[i] = choice[i] ^ rot_choice[i + MUX_used];
//    }
//
//    if (party == hxy::SERVER_ID) {
//        send_bool_vct((bool *)send_masked_index.data(), batch_size, IO);
//        recv_bool_vct((bool *)recv_masked_index.data(), batch_size, IO);
//    } else {
//        recv_bool_vct((bool *)recv_masked_index.data(), batch_size, IO);
//        send_bool_vct((bool *)send_masked_index.data(), batch_size, IO);
//    }
//
//    auto send_OT_ptr = send_OT_msg.data();
//    for (uint32_t i = 0; i < batch_size; i++) {
//        if (recv_masked_index[i]) std::swap(rot_msg0[i + MUX_used], rot_msg1[i + MUX_used]);
//        send_OT_ptr[0] = send_OT_ptr[1] = -res[i];
//        (choice[i] ? send_OT_ptr[1] : send_OT_ptr[0]) += x[i] - y[i];
//        send_OT_ptr[0] += rot_msg0[i + MUX_used];
//        send_OT_ptr[1] += rot_msg1[i + MUX_used];
//        send_OT_ptr += 2;
//    }
//    elementwise_and_inplace(2 * batch_size, send_OT_msg.data(), MOD_MASK);
//
//    if (output_bw <= 8) {
//        vector<uint8_t> send_OT_msg_8(batch_size * 2), recv_OT_msg_8(batch_size * 2);
//
//        elementwise_copy(batch_size * 2, send_OT_msg.data(), send_OT_msg_8.data());
//
//        if (party == hxy::SERVER_ID) {
//            send_uint8_vct(send_OT_msg_8.data(), 2 * batch_size, output_bw, IO);
//            recv_uint8_vct(recv_OT_msg_8.data(), 2 * batch_size, output_bw, IO);
//        } else {
//            recv_uint8_vct(recv_OT_msg_8.data(), 2 * batch_size, output_bw, IO);
//            send_uint8_vct(send_OT_msg_8.data(), 2 * batch_size, output_bw, IO);
//        }
//
//        for (uint32_t i = 0; i < batch_size * 2; i++)
//            recv_OT_msg[i] = recv_OT_msg_8[i];
//    } else {
//        if (party == hxy::SERVER_ID) {
//            send_u64_vct(send_OT_msg.data(), 2 * batch_size, output_bw, IO);
//            recv_u64_vct(recv_OT_msg.data(), 2 * batch_size, output_bw, IO);
//        } else {
//            recv_u64_vct(recv_OT_msg.data(), 2 * batch_size, output_bw, IO);
//            send_u64_vct(send_OT_msg.data(), 2 * batch_size, output_bw, IO);
//        }
//    }
//    auto recv_OT_ptr = recv_OT_msg.data();
//    for (uint32_t i = 0; i < batch_size; i++) {
//        res[i] += ((choice[i] ? recv_OT_ptr[1] : recv_OT_ptr[0]) - rot_recv_msg[i + MUX_used] + y[i]);
//        recv_OT_ptr += 2;
//    }
//    elementwise_and_inplace(batch_size, res, MOD_MASK);
//
//    MUX_used += batch_size;
//
//    auto after_online_MUX_comm = IO->counter;
//    IO->sync();
//    auto after_online_MUX_time = high_resolution_clock::now();
//}

void MUX_protocol::MUX(const uint32_t batch_size, const uint8_t *choice, const uint64_t *x, const uint64_t *y, uint64_t *res, const uint32_t output_bw) {
    // COT based
    IO->sync();
    auto before_online_MUX_comm = IO->counter;
    auto before_online_MUX_time = high_resolution_clock::now();

    const uint64_t MOD_MASK = (output_bw == 64 ? -1ULL : (1ULL << output_bw) - 1);

    vector<uint8_t> send_masked_index(batch_size), recv_masked_index(batch_size);
    vector<uint64_t> send_OT_msg(batch_size, 0), recv_OT_msg(batch_size);

    PRG prg;

    elementwise_xor(batch_size, choice, rot_choice.data() + MUX_used, send_masked_index.data());
//    for (uint32_t i = 0; i < batch_size; i++) { 
//        send_masked_index[i] = choice[i] ^ rot_choice[i + MUX_used];
//    }

    if (party == hxy::SERVER_ID) {
        send_bool_vct((bool *)send_masked_index.data(), batch_size, IO);
        recv_bool_vct((bool *)recv_masked_index.data(), batch_size, IO);
    } else {
        recv_bool_vct((bool *)recv_masked_index.data(), batch_size, IO);
        send_bool_vct((bool *)send_masked_index.data(), batch_size, IO);
    }

    elementwise_sub_inplace(batch_size, send_OT_msg.data(), rot_msg0.data() + MUX_used);
    elementwise_sub_inplace(batch_size, send_OT_msg.data(), rot_msg1.data() + MUX_used);
    for (uint32_t i = 0; i < batch_size; i++) {
        if (recv_masked_index[i]) std::swap(rot_msg0[i + MUX_used], rot_msg1[i + MUX_used]);
        res[i] = rot_msg0[i + MUX_used];
        uint64_t delta = y[i] - x[i];
        if (choice[i] == 0) {
            send_OT_msg[i] += delta;
            res[i] += x[i];
        } else {
            send_OT_msg[i] -= delta;
            res[i] += y[i];
        }
    }
    elementwise_and_inplace(batch_size, send_OT_msg.data(), MOD_MASK);

    if (output_bw <= 8) {
        vector<uint8_t> send_OT_msg_8(batch_size), recv_OT_msg_8(batch_size);

        elementwise_copy(batch_size, send_OT_msg.data(), send_OT_msg_8.data());

        if (party == hxy::SERVER_ID) {
            send_uint8_vct(send_OT_msg_8.data(), batch_size, output_bw, IO);
            recv_uint8_vct(recv_OT_msg_8.data(), batch_size, output_bw, IO);
        } else {
            recv_uint8_vct(recv_OT_msg_8.data(), batch_size, output_bw, IO);
            send_uint8_vct(send_OT_msg_8.data(), batch_size, output_bw, IO);
        }

        elementwise_copy(batch_size, recv_OT_msg.data(), recv_OT_msg_8.data());
    } else {
        if (party == hxy::SERVER_ID) {
            send_u64_vct(send_OT_msg.data(), batch_size, output_bw, IO);
            recv_u64_vct(recv_OT_msg.data(), batch_size, output_bw, IO);
        } else {
            recv_u64_vct(recv_OT_msg.data(), batch_size, output_bw, IO);
            send_u64_vct(send_OT_msg.data(), batch_size, output_bw, IO);
        }
    }
    for (uint32_t i = 0; i < batch_size; i++) {
        if (choice[i] == 0) {
            res[i] -= rot_recv_msg[i + MUX_used];
        } else {
            res[i] += recv_OT_msg[i] + rot_recv_msg[i + MUX_used];
        }
    }
    elementwise_and_inplace(batch_size, res, MOD_MASK);

    MUX_used += batch_size;

    auto after_online_MUX_comm = IO->counter;
    IO->sync();
    auto after_online_MUX_time = high_resolution_clock::now();
}

void MUX_protocol::_fake_MUX(const uint32_t batch_size, const uint8_t *choice, const uint64_t *x, uint64_t *res, const uint32_t output_bw) {
    if (party == hxy::SERVER_ID) cout << "fake MUX" << endl;
    const uint64_t MOD_MASK = (output_bw == 64 ? -1ULL : (1ULL << output_bw) - 1);
    if (party == hxy::SERVER_ID) { // SERVER
        vector<uint8_t> choice_bit0(batch_size);
        vector<uint64_t> x0(batch_size), res0(batch_size);
        recv_bool_vct((bool *)choice_bit0.data(), batch_size, IO);
        recv_u64_vct(x0.data(), batch_size, output_bw, IO);
        recv_u64_vct(res0.data(), batch_size, output_bw, IO);
        elementwise_xor_inplace(batch_size, choice_bit0.data(), choice);
        elementwise_addmod_inplace(batch_size, x0.data(), x, MOD_MASK);
        for (uint32_t i = 0; i < batch_size; i++) {
            res[i] = ((choice_bit0[i] ? x0[i] : 0) - res0[i]) & MOD_MASK;
        }
    } else { // CLIENT
        send_bool_vct((bool *)choice, batch_size, IO);
        send_u64_vct(x, batch_size, output_bw, IO);
        PRG prg;
        prg.random_data(res, batch_size * sizeof(uint64_t));
        elementwise_and_inplace(batch_size, res, MOD_MASK);
        send_u64_vct(res, batch_size, output_bw, IO);
    }
    MUX_used += batch_size;
}

void MUX_protocol::_fake_MUX(const uint32_t batch_size, const uint8_t *choice, const uint64_t *x, const uint64_t *y, uint64_t *res, const uint32_t output_bw) {
    if (party == hxy::SERVER_ID) cout << "fake MUX" << endl;
    const uint64_t MOD_MASK = (output_bw == 64 ? -1ULL : (1ULL << output_bw) - 1);
    if (party == hxy::SERVER_ID) {
        vector<uint8_t> choice_bit0(batch_size);
        vector<uint64_t> x0(batch_size), y0(batch_size), res0(batch_size);
        recv_bool_vct((bool *)choice_bit0.data(), batch_size, IO);
        recv_u64_vct(x0.data(), batch_size, output_bw, IO);
        recv_u64_vct(y0.data(), batch_size, output_bw, IO);
        recv_u64_vct(res0.data(), batch_size, output_bw, IO);
        elementwise_xor_inplace(batch_size, choice_bit0.data(), choice);
        elementwise_addmod_inplace(batch_size, x0.data(), x, MOD_MASK);
        elementwise_addmod_inplace(batch_size, y0.data(), y, MOD_MASK);
        for (uint32_t i = 0; i < batch_size; i++) {
            res[i] = ((choice_bit0[i] ? y0[i] : x0[i]) - res0[i]) & MOD_MASK;
        }
    } else {
        send_bool_vct((bool *)choice, batch_size, IO);
        send_u64_vct(x, batch_size, output_bw, IO);
        send_u64_vct(y, batch_size, output_bw, IO);
        PRG prg;
        prg.random_data(res, batch_size * sizeof(uint64_t));
        elementwise_and_inplace(batch_size, res, MOD_MASK);
        send_u64_vct(res, batch_size, output_bw, IO);
    }
    MUX_used += batch_size;
}
