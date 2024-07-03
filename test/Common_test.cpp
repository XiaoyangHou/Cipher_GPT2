#include "define.h"
#include "Common.h"

using namespace std;
using namespace std::chrono;

uint32_t party_id;
emp::NetIO * IO;

const uint64_t N = 10'000;

void send_bool_test(const uint32_t len) {
    block common_seed;
    if (party_id == hxy::SERVER_ID) {
        PRG prg;
        prg.random_block(&common_seed, 1);
        IO->send_block(&common_seed, 1);
    } else {
        IO->recv_block(&common_seed, 1);
    }
    PRG common_prg(&common_seed);

    vector<uint8_t> a(len);
    common_prg.random_bool((bool *)a.data(), len);
    if (party_id == hxy::SERVER_ID) {
        vector<uint8_t> a0(len);
        recv_bool_vct((bool *)a0.data(), len, IO);
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            flag &= (a0[i] == a[i]);
        }
        cout << "send bool test, len = " << len << " : " << boolalpha << flag << endl;
    } else {
        send_bool_vct((bool *)a.data(), len, IO);
    }
}

void send_uint8_test(const uint32_t len, const uint32_t bw) {
    block common_seed;
    if (party_id == hxy::SERVER_ID) {
        PRG prg;
        prg.random_block(&common_seed, 1);
        IO->send_block(&common_seed, 1);
    } else {
        IO->recv_block(&common_seed, 1);
    }
    PRG common_prg(&common_seed);

    vector<uint8_t> a(len);
    const uint8_t MOD_MASK = (bw == 8 ? -1 : (1 << bw) - 1);
    common_prg.random_data(a.data(), len);
    if (bw != 8)
        elementwise_and_inplace(len, a.data(), MOD_MASK);

    if (party_id == hxy::SERVER_ID) {
        vector<uint8_t> a0(len);
        recv_uint8_vct(a0.data(), len, bw, IO);
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            flag &= (a0[i] == a[i]);
        }
        cout << "send uint8_t test, len = " << len << ", bw = " << bw << " : " << boolalpha << flag << endl;
    } else {
        send_uint8_vct(a.data(), len, bw, IO);
    }
}

void send_uint64_test(const uint32_t len, const uint32_t bw) {
    block common_seed;
    if (party_id == hxy::SERVER_ID) {
        PRG prg;
        prg.random_block(&common_seed, 1);
        IO->send_block(&common_seed, 1);
    } else {
        IO->recv_block(&common_seed, 1);
    }
    PRG common_prg(&common_seed);

    vector<uint64_t> a(len);
    const uint64_t MOD_MASK = (bw == 64 ? -1ULL : (1ULL << bw) - 1);
    common_prg.random_data(a.data(), len * sizeof(uint64_t));
    if (bw != 64)
        elementwise_and_inplace(len, a.data(), MOD_MASK);

    if (party_id == hxy::SERVER_ID) {
        vector<uint64_t> a0(len);
        recv_u64_vct(a0.data(), len, bw, IO);
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            flag &= (a0[i] == a[i]);
        }
        cout << "send uint64_t test, len = " << len << ", bw = " << bw << " : " << boolalpha << flag << endl;
    } else {
        send_u64_vct(a.data(), len, bw, IO);
    }
}

int main(int argc, char **argv) {
    assert(argc == 2);
    party_id = stoi(argv[1]);
    cout << (party_id == hxy::SERVER_ID ? "Server" : "Client") << endl;

    IO = new emp::NetIO(party_id == hxy::SERVER_ID ? nullptr : hxy::server_ip.c_str(), hxy::port_number);

    for (uint32_t len = N; len < N + 8; len++) {
        for (uint32_t bw = 1; bw <= 8; bw++) {
            send_uint8_test(len, bw);
        }
    }

    for (uint32_t len = N - 8; len < N; len++) {
        for (uint32_t bw = 1; bw <= 8; bw++) {
            send_uint64_test(len, 32 + bw);
        }
    }

    for (uint32_t len = N - 8; len < N; len++) {
        send_bool_test(len);
    }

    delete IO;

    return 0;
}