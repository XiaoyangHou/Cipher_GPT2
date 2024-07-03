#include "define.h"
#include "Common.h"
#include "AND_protocol.h"
#include "SPLUT.h"

using namespace std;
using namespace std::chrono;

uint32_t party_id;
emp::NetIO * IO;

const uint64_t N = 10'000;

void test_splut_lut1(SPLUT_protocol & splut_protocol,
                     const uint32_t len,
                     const uint32_t input_bw,
                     const uint32_t output_bw) {

    assert(2 <= input_bw && input_bw <= 8);
    assert(1 <= output_bw && output_bw <= 64);

    const uint8_t index_MASK = (input_bw == 8) ? -1u : (1u << input_bw) - 1;
    const uint64_t MOD_MASK = (output_bw == 64) ? -1ULL : (1ULL << output_bw) - 1;

    PRG prg;
    vector<uint8_t> x(len), x0(len);
    vector<uint64_t> table(1 << input_bw), z(len), z0(len);

    prg.random_data(x.data(), len);
    elementwise_and_inplace(len, x.data(), index_MASK);
    // Server init public table
    if (party_id == hxy::SERVER_ID) {
//        prg.random_data(table.data(), (1 << input_bw) * sizeof(uint64_t));
//        elementwise_and_inplace(1 << input_bw, table.data(), MOD_MASK);
        for (uint32_t i = 0; i < (1 << input_bw); i++)
            table[i] = i;
    }

    splut_protocol.lookup_table(len, input_bw, output_bw, table.data(), x.data(), z.data());

    if (party_id == hxy::SERVER_ID) {
        IO->recv_data(x0.data(), len);
        IO->recv_data(z0.data(), len * sizeof(uint64_t));
        bool flag = true;
        for (uint32_t i = 0; i < len && flag; i++) {
            flag &= (((z[i] + z0[i]) & MOD_MASK) == ((x[i] + x0[i]) & index_MASK));
            if (!flag) {
                cout << "error at " << i << endl;
                cout << "x_S = " << (uint32_t)x[i] << ", x_C = " << (uint32_t)x0[i] << endl;
                cout << "x = " << (uint32_t) ((x[i] + x0[i]) & index_MASK) << endl;
                cout << "z_S = " << (uint32_t)z[i] << ", z_C = " << (uint32_t)z0[i] << endl;
                cout << "z = " << ((z[i] + z0[i]) & MOD_MASK) << endl;
            }
        }
        cout << "SPLUT len = " << len << ", input bw = " << input_bw << ", output bw = " <<
            output_bw << ", res = " << boolalpha << flag << endl;
    } else {
        IO->send_data(x.data(), len);
        IO->send_data(z.data(), len * sizeof(uint64_t));
    }
}

void test_splut_lut2(SPLUT_protocol & splut_protocol,
                     const uint32_t len,
                     const uint32_t input_bw,
                     const uint32_t output_x_bw,
                     const uint32_t output_y_bw) {

    assert(2 <= input_bw && input_bw <= 8);
    assert(1 <= output_x_bw && output_x_bw <= 64);
    assert(1 <= output_y_bw && output_y_bw <= 64);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    party_id = stoi(argv[1]);
    cout << (party_id == hxy::SERVER_ID ? "Server" : "Client") << endl;

    IO = new emp::NetIO(party_id == hxy::SERVER_ID ? nullptr : hxy::server_ip.c_str(), hxy::port_number);

    AND_protocol and_protocol(party_id, IO, 0);
    SPLUT_protocol splut_protocol(party_id, IO, &and_protocol, N * 8);

    test_splut_lut1(splut_protocol, N, 4, 64);
    test_splut_lut1(splut_protocol, N, 4, 64);

    delete IO;

    return 0;
}