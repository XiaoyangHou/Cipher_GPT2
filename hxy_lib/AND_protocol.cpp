#include "AND_protocol.h"

AND_protocol::AND_protocol(uint32_t _party_id, NetIO * _IO, uint64_t _ROT_number) {
    this->party = _party_id;
    this->MT_used = 0;
    this->ROT_number = _ROT_number;
    this->IO = _IO;
    PRG prg;
    if (party == hxy::SERVER_ID) {
        prg.random_block(&hash_key, 1);
        IO->send_block(&hash_key, 1);
    } else {
        IO->recv_block(&hash_key, 1);
        IO->flush();
    }
    if (ROT_number != 0) {
        ROT();
        prepare_MT_from_ROT();
    }
}

AND_protocol::~AND_protocol() {
    if (ROT_number == 0 && MT_used == 0)
        return;
    if (party == hxy::SERVER_ID) {
        cout << "-----------AND_protocol-----------" << endl;
        if (ROT_number < MT_used) cout << "Too less!" << endl;
        if (MT_used <= ROT_number) cout << "OK" << endl;
        cout << "AND used = " << MT_used << ", offline num = " << ROT_number << endl;
        cout << "----------------------------------" << endl;
    }
}

void AND_protocol::ROT() {
    IO->sync();
    uint64_t before_ROT_comm = IO->counter;
    auto before_ROT = high_resolution_clock::now();

    choice.resize(ROT_number);
    ROT_received_msg.resize(ROT_number);
    OT_messages0.resize(ROT_number);
    OT_messages1.resize(ROT_number);

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

        auto * ferretcot_receive = new FerretCOT<emp::NetIO>(BOB, 1, (emp::NetIO**)(&IO), false, true, ferret_b13, "server_receive.txt");
        ferretcot_receive->rcot(data, ROT_number);
        for (uint32_t i = 0; i < ROT_number; i++)
            choice[i] = emp::getLSB(data[i]);
        for (int64_t i = 0; i < ROT_number; i += ot_bsize) {
            memcpy(pad.data(), data+i, min((uint64_t)ot_bsize, ROT_number - i) * sizeof(block));
            mitccrh.hash<ot_bsize, 1>(pad.data());
            memcpy(data+i, pad.data(), min((uint64_t)ot_bsize, ROT_number - i) * sizeof(block));
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
            memcpy(pad.data(), data+i, min((uint64_t)ot_bsize, ROT_number - i) * sizeof(block));
            mitccrh.hash<ot_bsize, 1>(pad.data());
            memcpy(data+i, pad.data(), min((uint64_t)ot_bsize, ROT_number - i) * sizeof(block));
        }
        delete ferretcot_receive;

        auto * ferretcot_send = new FerretCOT<emp::NetIO>(ALICE, 1, (emp::NetIO**)(&IO), false, true, ferret_b13, "client_send.txt");
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

//        system("rm -f client_send.txt");
//        system("rm -f client_receive.txt");
    }
    uint64_t after_ROT_comm = IO->counter;
    IO->sync();
    auto after_ROT = high_resolution_clock::now();

    uint64_t server_client_data, client_send_data;
    if (party == hxy::SERVER_ID) {
        IO->recv_data(&client_send_data, sizeof(uint64_t));
        server_client_data = after_ROT_comm - before_ROT_comm;
        offline_comm = server_client_data + client_send_data;
        offline_time = duration_cast<microseconds>(after_ROT - before_ROT).count() / 1000;
//        cout << "AND ROT number = " << ROT_number << endl;
//        cout << "ROT communication = " << (client_send_data + after_ROT_comm - before_ROT_comm) / 1024.0 / 1024.0 << "MB" << endl;
//        cout << "amortized rOT communication = " << 8.0 * (client_send_data + after_ROT_comm - before_ROT_comm) / 2 / ROT_number << "bits" << endl;
//        cout << "ROT time use = " << (double)duration_cast<microseconds>(after_ROT - before_ROT).count() / 1000 << "ms" << endl;
    } else {
        client_send_data = after_ROT_comm - before_ROT_comm;
        IO->send_data(&client_send_data, sizeof(uint64_t));
    }
}

void AND_protocol::prepare_MT_from_ROT() {
    IO->sync();
    auto before_prepare_MT = high_resolution_clock::now();
    mt_x.resize(ROT_number);
    mt_y.resize(ROT_number);
    mt_z.resize(ROT_number);
    MT_used = 0;
    for (uint32_t i = 0; i < ROT_number; i++) {
        mt_x[i] = choice[i];
        mt_y[i] = getLSB(OT_messages0[i]) ^ getLSB(OT_messages1[i]);
        mt_z[i] = (mt_x[i] & mt_y[i]) ^ getLSB(ROT_received_msg[i]) ^ getLSB(OT_messages0[i]);
    }
    IO->sync();
    auto after_prepare_MT = high_resolution_clock::now();
    if (party == hxy::SERVER_ID) {
//        cout << "prepare MT time use = " << (double)duration_cast<microseconds>(after_prepare_MT - before_prepare_MT).count() / 1000 << "ms" << endl;
        offline_time += duration_cast<microseconds>(after_prepare_MT - before_prepare_MT).count() / 1000;
    }
}

void AND_protocol::AND(const uint32_t dim, const uint8_t * u, const uint8_t * v, uint8_t * z) {
    if (dim + MT_used <= ROT_number)
        F_AND(dim, u, v, z);
    else
        _fake_AND(dim, u, v, z);
}

void AND_protocol::_fake_AND(const uint32_t dim, const uint8_t * u, const uint8_t * v, uint8_t * z) {
    if (party == hxy::SERVER_ID) cout << "fake AND" << endl;
    if (party == hxy::SERVER_ID) {
        vector<uint8_t> u0(dim), v0(dim), z0(dim);
        recv_bool_vct((bool *)u0.data(), dim, IO);
        recv_bool_vct((bool *)v0.data(), dim, IO);
        recv_bool_vct((bool *)z0.data(), dim, IO);
        elementwise_xor_inplace(dim, u0.data(), u);
        elementwise_xor_inplace(dim, v0.data(), v);
        for (uint32_t i = 0; i < dim; i++) {
            z[i] = z0[i] ^ (u0[i] & v0[i]);
        }
    } else {
        PRG prg;
        prg.random_bool((bool *)z, dim);
        send_bool_vct((bool *)u, dim, IO);
        send_bool_vct((bool *)v, dim, IO);
        send_bool_vct((bool *)z, dim, IO);
    }
    MT_used += dim;
}

void AND_protocol::F_AND(const uint32_t dim, const uint8_t * u, const uint8_t * v, uint8_t * z) {
    assert(dim + MT_used <= ROT_number);
    vector<uint8_t> d(dim), e(dim);
    elementwise_xor(dim, u, mt_x.data() + MT_used, d.data());
    elementwise_xor(dim, v, mt_y.data() + MT_used, e.data());
//    elementwise_xor(dim, u, mt_x.data(), d.data());
//    elementwise_xor(dim, v, mt_y.data(), e.data());
    vector<uint8_t> d0(dim), e0(dim);
    IO->sync();
    if (party == hxy::SERVER_ID) {
        send_bool_vct((bool *)d.data(), dim, IO);
        send_bool_vct((bool *)e.data(), dim, IO);
        recv_bool_vct((bool *)d0.data(), dim, IO);
        recv_bool_vct((bool *)e0.data(), dim, IO);
    } else {
        recv_bool_vct((bool *)d0.data(), dim, IO);
        recv_bool_vct((bool *)e0.data(), dim, IO);
        send_bool_vct((bool *)d.data(), dim, IO);
        send_bool_vct((bool *)e.data(), dim, IO);
    }
    const uint8_t id = party - 1;

    elementwise_xor_inplace(dim, d0.data(), d.data());
    elementwise_xor_inplace(dim, e0.data(), e.data());
    get_fand_z(dim, z, id, d0.data(), e0.data(), mt_x.data() + MT_used, mt_y.data() + MT_used, mt_z.data() + MT_used);
    MT_used += dim;
}

void AND_protocol::AND(const uint32_t dim, const uint8_t * u, uint8_t * z) {
    vector<uint8_t> zero_vct(dim, 0);
    if (dim + MT_used <= ROT_number) {
        if (party == hxy::SERVER_ID) F_AND(dim, u, zero_vct.data(), z);
        else F_AND(dim, zero_vct.data(), u, z);
    } else {
        if (party == hxy::SERVER_ID) _fake_AND(dim, u, zero_vct.data(), z);
        else _fake_AND(dim, zero_vct.data(), u, z);
    }
}

void AND_protocol::OR(const uint32_t dim, const uint8_t * u, uint8_t * z) {
    vector<uint8_t> not_u(dim), not_z(dim);
    if (party == hxy::SERVER_ID) {
        elementwise_xor(dim, u, (uint8_t)1, not_u.data()); // not u
        AND(dim, not_u.data(), not_z.data());
        elementwise_xor(dim, not_z.data(), (uint8_t)1, z);
    } else {
        elementwise_xor(dim, u, (uint8_t)1, not_u.data()); // not u
        AND(dim, not_u.data(), z);
    }
}

void AND_protocol::OR(const uint32_t dim, const uint8_t * u, const uint8_t * v, uint8_t * z) {
    vector<uint8_t> not_u(dim), not_v(dim), not_z(dim);
    if (party == hxy::SERVER_ID) {
        elementwise_xor(dim, u, (uint8_t)1, not_u.data());
        elementwise_xor(dim, v, (uint8_t)1, not_v.data());
        AND(dim, not_u.data(), not_v.data(), not_z.data());
        elementwise_xor(dim, not_z.data(), (uint8_t)1, z);
    } else {
        AND(dim, u, v, z);
    }
}
