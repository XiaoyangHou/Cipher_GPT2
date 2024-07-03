#include <bits/stdc++.h>
#include "define.h"
#include "Common.h"
#include "BOLE_protocol.h"

using namespace std;
using namespace std::chrono;

uint32_t party_id;
emp::NetIO * IO;

const uint64_t N = (256 * 3072);

void test_online_BOLE(const uint32_t len, const uint32_t bw, BOLE_protocol & bole_protocol) {
    const uint64_t MOD_MASK = (bw == 64) ? -1ULL : (1ULL << bw) - 1;
    PRG Server_PRG;
    PRG Client_PRG;
    vector<uint64_t> server_x(len), server_y(len), server_z(len);
    vector<uint64_t> client_x(len), client_y(len), client_z(len);

    if (party_id == hxy::SERVER_ID) {
        Server_PRG.random_data(server_x.data(), len * sizeof(uint64_t));
        Server_PRG.random_data(server_y.data(), len * sizeof(uint64_t));
        elementwise_and_inplace(len, server_x.data(), MOD_MASK);
        elementwise_and_inplace(len, server_y.data(), MOD_MASK);
    } else {
        Client_PRG.random_data(client_x.data(), len * sizeof(uint64_t));
        Client_PRG.random_data(client_y.data(), len * sizeof(uint64_t));
        elementwise_and_inplace(len, client_x.data(), MOD_MASK);
        elementwise_and_inplace(len, client_y.data(), MOD_MASK);
    }

    if (party_id == hxy::SERVER_ID) {
        bole_protocol.BOLE_online(len, bw, server_x.data(), server_y.data(), server_z.data());
        recv_u64_vct(client_x.data(), len, bw, IO);
        recv_u64_vct(client_y.data(), len, bw, IO);
        recv_u64_vct(client_z.data(), len, bw, IO);
    } else {
        bole_protocol.BOLE_online(len, bw, client_x.data(), client_y.data(), client_z.data());
        send_u64_vct(client_x.data(), len, bw, IO);
        send_u64_vct(client_y.data(), len, bw, IO);
        send_u64_vct(client_z.data(), len, bw, IO);
    }

    if (party_id == hxy::SERVER_ID) {
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            uint64_t real_res = ((server_x[i] + client_x[i]) * (server_y[i] + client_y[i])) & MOD_MASK;
            uint64_t cal_res = (server_z[i] + client_z[i]) & MOD_MASK;
            bool cur_flag = false;
            if (real_res == cal_res) cur_flag = true;
            if (real_res == cal_res + 1) cur_flag = true;
            flag &= cur_flag;
            if (!flag) {
                cout << "error at" << i << endl;
                cout << "server x = " << server_x[i] << endl;
                cout << "server y = " << server_y[i] << endl;
                cout << "client x = " << client_x[i] << endl;
                cout << "client y = " << client_y[i] << endl;
                cout << "real_res = " << real_res << endl;
                cout << "server z = " << server_z[i] << endl;
                cout << "client z = " << client_z[i] << endl;
                cout << "cal res = " << cal_res << endl;
                break;
            }
        }
        cout << "BOLE online test = " << boolalpha << flag << endl;
    }
}

void test_online_BOLE_square(const uint32_t len, const uint32_t bw, BOLE_protocol & bole_protocol) {
    const uint64_t MOD_MASK = (bw == 64) ? -1ULL : (1ULL << bw) - 1;
    PRG Server_PRG;
    PRG Client_PRG;
    vector<uint64_t> server_x(len), server_z(len);
    vector<uint64_t> client_x(len), client_z(len);

    if (party_id == hxy::SERVER_ID) {
        Server_PRG.random_data(server_x.data(), len * sizeof(uint64_t));
        elementwise_and_inplace(len, server_x.data(), MOD_MASK);
    } else {
        Client_PRG.random_data(client_x.data(), len * sizeof(uint64_t));
        elementwise_and_inplace(len, client_x.data(), MOD_MASK);
    }

    if (party_id == hxy::SERVER_ID) {
        bole_protocol.BOLE_square_online(len, bw, server_x.data(), server_z.data());
        recv_u64_vct(client_x.data(), len, bw, IO);
        recv_u64_vct(client_z.data(), len, bw, IO);
    } else {
        bole_protocol.BOLE_square_online(len, bw, client_x.data(), client_z.data());
        send_u64_vct(client_x.data(), len, bw, IO);
        send_u64_vct(client_z.data(), len, bw, IO);
    }

    if (party_id == hxy::SERVER_ID) {
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            uint64_t real_res = ((server_x[i] + client_x[i]) * (server_x[i] + client_x[i])) & MOD_MASK;
            uint64_t cal_res = (server_z[i] + client_z[i]) & MOD_MASK;
            bool cur_flag = false;
            if (real_res == cal_res) cur_flag = true;
            if (real_res == cal_res + 1) cur_flag = true;
            flag &= cur_flag;
            if (!flag) {
                cout << "error at" << i << endl;
                cout << "server x = " << server_x[i] << endl;
                cout << "client x = " << client_x[i] << endl;
                cout << "real_res = " << real_res << endl;
                cout << "server z = " << server_z[i] << endl;
                cout << "client z = " << client_z[i] << endl;
                cout << "cal res = " << cal_res << endl;
                break;
            }
        }
        cout << "online BOLE square test = " << boolalpha << flag << endl;
    }
}

int main(int argc, char **argv) {
    assert(argc == 2);
    party_id = stoi(argv[1]);
    cout << (party_id == hxy::SERVER_ID ? "Server" : "Client") << endl;

    IO = new emp::NetIO(party_id == hxy::SERVER_ID ? nullptr : hxy::server_ip.c_str(), hxy::port_number);

    IO->sync();

    BOLE_protocol bole_protocol(party_id, IO, 0);

//    test_online_BOLE(N, 37, bole_protocol);

    for (uint32_t i = 0; i < 8; i++) {
        test_online_BOLE(N + i, 37 - i, bole_protocol);
        test_online_BOLE_square(N + i, 37 - i, bole_protocol);
    }

    delete IO;

    return 0;
}