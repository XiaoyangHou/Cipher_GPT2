#ifndef HXY_DEFINE_H
#define HXY_DEFINE_H
#include <stdint.h>
#include <vector>
#include <string>
#include <eigen3/Eigen/Dense>

//#define CHECK

namespace hxy {
    const uint64_t bit_width = 37;
    const uint64_t MOD = (1ULL << bit_width);
    const uint64_t MOD_MASK = MOD - 1;
    const uint64_t fix_point_scale = 12;
    const uint64_t scale_up = (1ull << 12);
    const uint64_t MSB = (1ull << (bit_width - 1));

    const uint16_t port_number = 14752;
    const std::string server_ip = "127.0.0.1";

    const uint32_t SECURE_PARAMETER = 128;

// party id : SERVER = 1, CLIENT = 2
    const uint32_t SERVER_ID = 1;
    const uint32_t CLIENT_ID = 2;
}

using Eigen::Matrix;
using Eigen::Dynamic;
typedef Eigen::Matrix<uint64_t, Eigen::Dynamic, Eigen::Dynamic> Matrix_u64xx;

#endif //HXY_DEFINE_H