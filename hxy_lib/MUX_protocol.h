#ifndef HXY_MUX_protocol_H
#define HXY_MUX_protocol_H
#include "define.h"
#include "Common.h"

class MUX_protocol{
private:
    uint32_t party;
    NetIO * IO;
    vector<uint64_t> rot_msg0, rot_msg1, rot_recv_msg;
    vector<uint8_t> rot_choice;
    int64_t ROT_number, MUX_used;
    block hash_key;
    uint64_t offline_MUX();
    void _fake_MUX(const uint32_t batch_size, const uint8_t * choice, const uint64_t * x, uint64_t * res, const uint32_t output_bw);
    void _fake_MUX(const uint32_t batch_size, const uint8_t * choice, const uint64_t * x, const uint64_t * y, uint64_t * res, const uint32_t output_bw);
    void MUX(const uint32_t batch_size, const uint8_t * choice, const uint64_t * x, const uint64_t * y, uint64_t * res, const uint32_t output_bw);
public:
    MUX_protocol(uint32_t _party_id, NetIO * _IO, int64_t _ROT_number);
    ~MUX_protocol();
    void online_MUX(const uint32_t batch_size, const uint8_t * choice, const uint64_t * x, const uint64_t * y, uint64_t * res, const uint32_t output_bw);
    void online_MUX(const uint32_t batch_size, const uint8_t * choice, const uint64_t * x, uint64_t * res, const uint32_t output_bw);
    uint64_t offline_time = 0, offline_comm = 0;
};

#endif