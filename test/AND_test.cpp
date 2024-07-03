#include "define.h"
#include "Common.h"
#include "AND_protocol.h"

using namespace std;
using namespace std::chrono;

uint32_t party_id;
emp::NetIO * IO;

const uint64_t N = 10'000;

void test_and_protocol1(AND_protocol & and_protocol, const uint32_t len) {
    PRG prg;
    vector<uint8_t> a(len), b(len), c(len);
    prg.random_bool((bool *)a.data(), len);
    prg.random_bool((bool *)b.data(), len);

    and_protocol.AND(len, a.data(), b.data(), c.data());

    if (party_id == hxy::SERVER_ID) {
        vector<uint8_t> a0(len), b0(len), c0(len);
        recv_bool_vct((bool *)a0.data(), len, IO);
        recv_bool_vct((bool *)b0.data(), len, IO);
        recv_bool_vct((bool *)c0.data(), len, IO);
        elementwise_xor_inplace(len, a0.data(), a.data());
        elementwise_xor_inplace(len, b0.data(), b.data());
        elementwise_xor_inplace(len, c0.data(), c.data());
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            flag &= ((a0[i] & b0[i]) == c0[i]);
        }
        cout << "AND test1 , len = " << len << " : " << boolalpha << flag << endl;
    } else {
        send_bool_vct((bool *)a.data(), len, IO);
        send_bool_vct((bool *)b.data(), len, IO);
        send_bool_vct((bool *)c.data(), len, IO);
    }
}

void test_and_protocol2(AND_protocol & and_protocol, const uint32_t len) { // non-sharing
    PRG prg;
    vector<uint8_t> a(len), c(len);
    prg.random_bool((bool *)a.data(), len);

    and_protocol.AND(len, a.data(), c.data());

    if (party_id == hxy::SERVER_ID) {
        vector<uint8_t> client_a(len), c0(len);
        recv_bool_vct((bool *)client_a.data(), len, IO);
        recv_bool_vct((bool *)c0.data(), len, IO);
        elementwise_xor_inplace(len, c0.data(), c.data());
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            flag &= ((client_a[i] & a[i]) == c0[i]);
        }
        cout << "AND test2 , len = " << len << " : " << boolalpha << flag << endl;
    } else {
        send_bool_vct((bool *)a.data(), len, IO);
        send_bool_vct((bool *)c.data(), len, IO);
    }
}

void test_or_protocol1(AND_protocol & and_protocol, const uint32_t len) {
    PRG prg;
    vector<uint8_t> a(len), b(len), c(len);
    prg.random_bool((bool *)a.data(), len);
    prg.random_bool((bool *)b.data(), len);

    and_protocol.OR(len, a.data(), b.data(), c.data());

    if (party_id == hxy::SERVER_ID) {
        vector<uint8_t> a0(len), b0(len), c0(len);
        recv_bool_vct((bool *)a0.data(), len, IO);
        recv_bool_vct((bool *)b0.data(), len, IO);
        recv_bool_vct((bool *)c0.data(), len, IO);
        elementwise_xor_inplace(len, a0.data(), a.data());
        elementwise_xor_inplace(len, b0.data(), b.data());
        elementwise_xor_inplace(len, c0.data(), c.data());
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            flag &= ((a0[i] | b0[i]) == c0[i]);
        }
        cout << "OR test1 , len = " << len << " : " << boolalpha << flag << endl;
    } else {
        send_bool_vct((bool *)a.data(), len, IO);
        send_bool_vct((bool *)b.data(), len, IO);
        send_bool_vct((bool *)c.data(), len, IO);
    }
}

void test_or_protocol2(AND_protocol & and_protocol, const uint32_t len) { // non-sharing
    PRG prg;
    vector<uint8_t> a(len), c(len);
    prg.random_bool((bool *)a.data(), len);

    and_protocol.OR(len, a.data(), c.data());

    if (party_id == hxy::SERVER_ID) {
        vector<uint8_t> client_a(len), c0(len);
        recv_bool_vct((bool *)client_a.data(), len, IO);
        recv_bool_vct((bool *)c0.data(), len, IO);
        elementwise_xor_inplace(len, c0.data(), c.data());
        bool flag = true;
        for (uint32_t i = 0; i < len; i++) {
            flag &= ((client_a[i] | a[i]) == c0[i]);
        }
        cout << "OR test2 , len = " << len << " : " << boolalpha << flag << endl;
    } else {
        send_bool_vct((bool *)a.data(), len, IO);
        send_bool_vct((bool *)c.data(), len, IO);
    }
}


int main(int argc, char **argv) {
    assert(argc == 2);
    party_id = stoi(argv[1]);
    cout << (party_id == hxy::SERVER_ID ? "Server" : "Client") << endl;

    IO = new emp::NetIO(party_id == hxy::SERVER_ID ? nullptr : hxy::server_ip.c_str(), hxy::port_number);

    AND_protocol and_protocol(party_id, IO, N * 33);

    for (uint32_t i = 0; i < 8; i++) {
        test_and_protocol1(and_protocol, N + i);
        test_and_protocol2(and_protocol, N + i);
    }

    for (uint32_t i = 0; i < 8; i++) {
        test_or_protocol1(and_protocol, N + i);
        test_or_protocol2(and_protocol, N + i);
    }

    delete IO;

    return 0;
}