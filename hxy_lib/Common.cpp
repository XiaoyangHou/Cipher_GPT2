#include "Common.h"

void send_bool_vct(const bool * x, const uint32_t len, NetIO * empIO) {
    const uint32_t a = len / 8;
    const uint32_t b = len % 8;
    if (a != 0) {
        vector<uint8_t> send_data(a);
        compress_bits_into_uint8(x, send_data.data(), a);
        empIO->send_data(send_data.data(), a);
    }
    if (b != 0) {
        empIO->send_data(x + a * 8, b);
    }
}

void recv_bool_vct(bool * x, const uint32_t len, NetIO * empIO) {
    const uint32_t a = len / 8;
    const uint32_t b = len % 8;
    if (a != 0) {
        vector<uint8_t> recv_data(a);
        empIO->recv_data(recv_data.data(), a);
        decompress_bits_from_uint8(recv_data.data(), x, a);
    }
    if (b != 0) {
        empIO->recv_data(x + a * 8, b);
    }
}

void compress_uint8(const uint8_t * __restrict bits_ptr, uint8_t * __restrict data_ptr, uint32_t round_num, uint32_t bw) {
    assert(1 <= bw && bw <= 7);
    uint64_t mask = 0;
    memset(&mask, (1 << bw) - 1, sizeof(uint64_t));
    uint64_t * bits_u64_ptr = (uint64_t *) bits_ptr;
    for (uint32_t i = 0; i < round_num; i++) {
        uint64_t tmp = _pext_u64(bits_u64_ptr[i], mask);
        memcpy(data_ptr, &tmp, bw);
        data_ptr += bw;
    }
}

void decompress_uint8(const uint8_t * __restrict data_ptr, uint8_t * __restrict bits_ptr, uint32_t round_num, uint32_t bw) {
    assert(1 <= bw && bw <= 7);
    uint64_t mask = 0;
    memset(&mask, (1 << bw) - 1, sizeof(uint64_t));
    uint64_t * bits_u64_ptr = (uint64_t *) bits_ptr;
    const uint8_t * cur_data_ptr = data_ptr;
    for (uint32_t i = 0; i < round_num; i++) {
        uint64_t tmp = 0;
        memcpy(&tmp, cur_data_ptr, bw);
        bits_u64_ptr[i] = _pdep_u64(tmp, mask);
        cur_data_ptr += bw;
    }
}

void send_u64_vct(const uint64_t * x, const uint32_t len, const uint32_t bw, NetIO * empIO) {
    uint32_t num_in_bytes = ceil(bw / 8.0);
    vector<uint8_t> send_data(len * num_in_bytes);
    uint8_t * cur_ptr = send_data.data();
    for (uint32_t i = 0; i < len; i++) {
        memcpy(cur_ptr, x + i, num_in_bytes);
        cur_ptr += num_in_bytes;
    }
    empIO->send_data(send_data.data(), len * num_in_bytes);
}

void recv_u64_vct(uint64_t * x, const uint32_t len, const uint32_t bw, NetIO * empIO) {
    uint32_t num_in_bytes = ceil(bw / 8.0);
    vector<uint8_t> recv_data(len * num_in_bytes);
    empIO->recv_data(recv_data.data(), len * num_in_bytes);
    uint8_t * cur_ptr = recv_data.data();
    for (uint32_t i = 0; i < len; i++) {
        uint64_t tmp = 0;
        memcpy(&tmp, cur_ptr, num_in_bytes);
        x[i] = tmp;
        cur_ptr += num_in_bytes;
    }
}

void send_uint8_vct(const uint8_t * x, const uint32_t len, const uint32_t bw, NetIO * IO) {
    if (bw == 8) {
        IO->send_data(x, len);
        return;
    }
    uint32_t round_num = len / 8;
    uint32_t extra_len = len % 8;
    vector<uint8_t> send_data(round_num * bw + extra_len);
    compress_uint8(x, send_data.data(), round_num, bw);
    if (extra_len != 0) {
        memcpy(send_data.data() + round_num * bw, x + round_num * 8, extra_len);
    }
    IO->send_data(send_data.data(), send_data.size());
}

void recv_uint8_vct(uint8_t * x, const uint32_t len, const uint32_t bw, NetIO * IO) {
    if (bw == 8) {
        IO->recv_data(x, len);
        return;
    }
    uint32_t round_num = len / 8;
    uint32_t extra_len = len % 8;
    vector<uint8_t> recv_data(round_num * bw + extra_len);
    IO->recv_data(recv_data.data(), recv_data.size());
    decompress_uint8(recv_data.data(), x, round_num, bw);
    if (extra_len != 0) {
        memcpy(x + round_num * 8, recv_data.data() + round_num * bw, extra_len);
    }
}

void fake_matmul(const uint32_t party_id, const uint32_t M, const uint32_t N, const uint32_t K,
            const uint64_t * __restrict x, const uint64_t * __restrict y, uint64_t * __restrict z, NetIO * IO) {
    Matrix_u64xx matrix_x(N, M), matrix_y(K, N), matrix_z;
    memcpy(matrix_x.data(), x, M * N * sizeof(uint64_t));
    memcpy(matrix_y.data(), y, N * K * sizeof(uint64_t));
    matrix_x.transposeInPlace();
    matrix_y.transposeInPlace();
    Matrix_u64xx matrix_x0(M, N);
    if (party_id == hxy::SERVER_ID) {
        IO->send_data(matrix_x.data(), M * N * sizeof(uint64_t));
        IO->recv_data(matrix_x0.data(), M * N * sizeof(uint64_t));
    } else {
        IO->recv_data(matrix_x0.data(), M * N * sizeof(uint64_t));
        IO->send_data(matrix_x.data(), M * N * sizeof(uint64_t));
    }
    matrix_x += matrix_x0;
    matrix_z = matrix_x * matrix_y;
#ifdef CHECK
    if (party_id == hxy::SERVER_ID) {
        Matrix_u64xx matrix_y0(N, K), matrix_z0(M, K);
        IO->recv_data(matrix_y0.data(), N * K * sizeof(uint64_t));
        IO->recv_data(matrix_z0.data(), M * K * sizeof(uint64_t));
        matrix_z0 += matrix_z;
        matrix_y += matrix_y0;
        Matrix_u64xx correct_res = matrix_x * matrix_y;
        bool flag = true;
        for (uint32_t i = 0; i < M * K; i++) {
            flag &= (matrix_z0.data()[i] == correct_res.data()[i]);
        }
        cout << "MatMul check result = " << boolalpha << flag << endl;
    } else {
        IO->send_data(matrix_y.data(), N * K * sizeof(uint64_t));
        IO->send_data(matrix_z.data(), N * K * sizeof(uint64_t));
    }
#endif
    matrix_z.transposeInPlace();
    memcpy(z, matrix_z.data(), M * K * sizeof(uint64_t));
}

void fake_bole(const uint32_t party_id, const uint32_t N, const uint64_t * __restrict x, const uint64_t * __restrict y, uint64_t * __restrict z, NetIO * IO) {
    vector<uint64_t> x0(N);
    if (party_id == hxy::SERVER_ID) {
        IO->send_data(x, N * sizeof(uint64_t));
        IO->recv_data(x0.data(), N * sizeof(uint64_t));
    } else {
        IO->recv_data(x0.data(), N * sizeof(uint64_t));
        IO->send_data(x, N * sizeof(uint64_t));
    }
    for (uint32_t i = 0; i < N; i++)
        z[i] = (x[i] + x0[i]) * y[i];
}

uint64_t mulmod(uint64_t x, uint64_t y, uint64_t mod) {
    uint64_t cur = x % mod;
    uint64_t res = 0;
    while (y) {
        if (y & 1) {
            res += cur;
            if (mod <= res)
                res -= mod;
        }
        y >>= 1;
        cur += cur;
        if (mod <= cur)
            cur -= mod;
    }
    return res;
}

uint64_t fast_pow(uint64_t base, uint64_t times, uint64_t mod) {
    uint64_t res = 1;
    uint64_t cur = base % mod;
    while (times) {
        if (times & 1) {
            res = mulmod(res, cur, mod);
        }
        times >>= 1;
        cur = mulmod(cur, cur, mod);
    }
    return res % mod;
}

uint64_t get_error(uint64_t x, uint64_t y) {
    uint64_t a = x - y;
    uint64_t b = y - x;
    return min(a, b);
}