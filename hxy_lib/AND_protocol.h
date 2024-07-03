#ifndef HXY_AND_protocol_H
#define HXY_AND_protocol_H
#include "define.h"
#include "Common.h"

class AND_protocol{
private:
    uint32_t party;
    NetIO * IO = nullptr;
    block hash_key;
    vector<uint8_t> mt_x, mt_y, mt_z;
    vector<uint8_t> choice;
    vector<block> ROT_received_msg, OT_messages0, OT_messages1;
    uint64_t ROT_number = 0, MT_used = 0;
    void ROT();
    void prepare_MT_from_ROT();
    void F_AND(const uint32_t dim, const uint8_t * u, const uint8_t * v, uint8_t * z);
    void _fake_AND(const uint32_t dim, const uint8_t * u, const uint8_t * v, uint8_t * z);
public:
    AND_protocol(uint32_t _party_id, NetIO * _IO, uint64_t _ROT_number);
    ~AND_protocol();
    void AND(const uint32_t dim, const uint8_t * u, const uint8_t * v, uint8_t * z);
    void AND(const uint32_t dim, const uint8_t * u, uint8_t * z);
    void OR(const uint32_t dim, const uint8_t * u, const uint8_t * v, uint8_t * z);
    void OR(const uint32_t dim, const uint8_t * u, uint8_t * z);
    uint64_t offline_time = 0, offline_comm = 0;
};

#endif
