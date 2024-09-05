#ifndef HXY_SPLUT_protocol_H
#define HXY_SPLUT_protocol_H
#include "define.h"
#include "Common.h"
#include "AND_protocol.h"

class SPLUT_protocol{
private:
    uint32_t party;
    NetIO * IO;
    AND_protocol * and_protocol;
    block hash_key;
    uint64_t ROT_number, used_ROT_num;
    AES_KEY common_AES;
    vector<uint8_t> choice;
    vector<block> ROT_received_msg, OT_messages0, OT_messages1;
    void _fake_mill_and_equal(uint32_t len, const uint8_t * x, uint8_t * mill_res, uint8_t * equal_res, const uint32_t bw);
    void _fake_lookup_table(const uint32_t len, const uint32_t input_bw, const uint32_t output_bw,
                           const uint64_t * public_table, const uint8_t * x, uint64_t * res);
    void _fake_lookup_table(const uint32_t len, const uint32_t input_bw,
                           const uint32_t output_bw_x, const uint32_t output_bw_y,
                           const uint64_t * public_table_x, const uint64_t * public_table_y,
                           const uint8_t * x, uint64_t * res_x, uint64_t * res_y);
    void mill_and_equal_1_bit(const uint32_t len, const uint8_t * x, uint8_t * mill_res, uint8_t * equal_res);
public:
    SPLUT_protocol(uint32_t _party_id, NetIO * _IO, AND_protocol * _and_protocol, uint64_t _used_ROT_num);
    ~SPLUT_protocol();
    void offline_LUT();
    void mill_and_equal(uint32_t len, const uint8_t * x, uint8_t * mill_res, uint8_t * equal_test_res, const uint32_t bw);
    void lookup_table(const uint32_t len, const uint32_t input_bw, const uint32_t output_bw,
                      const uint64_t * public_table, const uint8_t * x, uint64_t * res);
    void lookup_table(const uint32_t len, const uint32_t input_bw,
                      const uint32_t output_bw_x, const uint32_t output_bw_y,
                      const uint64_t * public_table_x, const uint64_t * public_table_y,
                      const uint8_t * x, uint64_t * res_x, uint64_t * res_y);
    uint64_t offline_time = 0, offline_comm = 0; // ms and byte
};

#endif