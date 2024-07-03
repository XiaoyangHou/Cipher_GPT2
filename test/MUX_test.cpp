#include "define.h"
#include "Common.h"
#include "MUX_protocol.h"

using namespace std;
using namespace std::chrono;

uint32_t party_id;
emp::NetIO * IO;

void test_mux_protocol_1outof2(MUX_protocol & mux_protocol, const uint32_t len, const uint32_t bw) {

    vector<uint8_t> choice_bit(len);
    vector<uint64_t> a(len), b(len), res(len);
    PRG prg;
    prg.random_bool((bool *)choice_bit.data(), len);

    const uint64_t MOD_MASK = (bw == 64 ? -1ULL : (1ULL << bw) - 1);
    prg.random_data(a.data(), len * sizeof(uint64_t));
    prg.random_data(b.data(), len * sizeof(uint64_t));
    elementwise_and_inplace(len, a.data(), MOD_MASK);
    elementwise_and_inplace(len, b.data(), MOD_MASK);

    mux_protocol.online_MUX(len, choice_bit.data(), a.data(), b.data(), res.data(), bw);

    if (party_id == hxy::SERVER_ID) {
        vector<uint8_t> choice_bit0(len);
        vector<uint64_t> a0(len), b0(len), res0(len);
        recv_bool_vct((bool *)choice_bit0.data(), len, IO);
        recv_u64_vct(a0.data(), len, bw, IO);
        recv_u64_vct(b0.data(), len, bw, IO);
        recv_u64_vct(res0.data(), len, bw, IO);
        elementwise_xor_inplace(len, choice_bit0.data(), choice_bit.data());
        elementwise_addmod_inplace(len, a0.data(), a.data(), MOD_MASK);
        elementwise_addmod_inplace(len, b0.data(), b.data(), MOD_MASK);
        elementwise_addmod_inplace(len, res0.data(), res.data(), MOD_MASK);
        bool flag = true;
        for (uint32_t i = 0; i < len && flag; i++) {
            flag &= ((choice_bit0[i] ? b0[i] : a0[i]) == res0[i]);
            if (!flag) {
                cout << "error at " << i << endl;
                cout <<  "x = " << a0[i] << ", y = " << b0[i] << endl;
                cout << "choice = " << (uint32_t)choice_bit0[i] << endl;
                cout << "MUX res = " << res0[i] << endl;
            }
        }
        cout << "MUX len = " << len << ", bw = " << bw << ", test result = " << boolalpha << flag << endl;
    } else {
        send_bool_vct((bool *)choice_bit.data(), len, IO);
        send_u64_vct(a.data(), len, bw, IO);
        send_u64_vct(b.data(), len, bw, IO);
        send_u64_vct(res.data(), len, bw, IO);
    }
}

void test_mux_protocol_1outof1(MUX_protocol & mux_protocol, const uint32_t len, const uint32_t bw) {

    vector<uint8_t> choice_bit(len);
    vector<uint64_t> a(len), res(len);
    PRG prg;
    prg.random_bool((bool *)choice_bit.data(), len);

    const uint64_t MOD_MASK = (bw == 64 ? -1ULL : (1ULL << bw) - 1);
    prg.random_data(a.data(), len * sizeof(uint64_t));
    elementwise_and_inplace(len, a.data(), MOD_MASK);

    mux_protocol.online_MUX(len, choice_bit.data(), a.data(), res.data(), bw);

    if (party_id == hxy::SERVER_ID) {
        vector<uint8_t> choice_bit0(len);
        vector<uint64_t> a0(len), res0(len);
        recv_bool_vct((bool *)choice_bit0.data(), len, IO);
        recv_u64_vct(a0.data(), len, bw, IO);
        recv_u64_vct(res0.data(), len, bw, IO);
        elementwise_xor_inplace(len, choice_bit0.data(), choice_bit.data());
        elementwise_addmod_inplace(len, a0.data(), a.data(), MOD_MASK);
        elementwise_addmod_inplace(len, res0.data(), res.data(), MOD_MASK);
        bool flag = true;
        for (uint32_t i = 0; i < len && flag; i++) {
            flag &= ((choice_bit0[i] ? a0[i] : 0) == res0[i]);
            if (!flag) {
                cout << "error at " << i << endl;
                cout <<  "x = " << a0[i] << endl;
                cout << "choice = " << (uint32_t)choice_bit0[i] << endl;
                cout << "MUX res = " << res0[i] << endl;
            }
        }
        cout << "MUX len = " << len << ", bw = " << bw << ", test result = " << boolalpha << flag << endl;
    } else {
        send_bool_vct((bool *)choice_bit.data(), len, IO);
        send_u64_vct(a.data(), len, bw, IO);
        send_u64_vct(res.data(), len, bw, IO);
    }
}

int main(int argc, char **argv) {
    assert(argc == 2);
    party_id = stoi(argv[1]);
    cout << (party_id == hxy::SERVER_ID ? "Server" : "Client") << endl;

    IO = new emp::NetIO(party_id == hxy::SERVER_ID ? nullptr : hxy::server_ip.c_str(), hxy::port_number);

    const uint64_t N = 10'000;

    MUX_protocol mux_protocol(party_id, IO, N * 17);

    for (uint32_t i = 0; i < 8; i++) {
        test_mux_protocol_1outof1(mux_protocol, N + i, 32 + i);
        test_mux_protocol_1outof2(mux_protocol, N + i, 32 + i);
    }

    delete IO;

    return 0;
}