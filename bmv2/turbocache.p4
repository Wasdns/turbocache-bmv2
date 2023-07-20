#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t
{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
    bit<120> payload;
}

// const PortId query_resevered_portId = 3000

const bit<16> GET = 0; 
const bit<16> PUT = 1; 
const bit<16> DELETE = 2; 
const bit<32> SLOT_NUMS = 1;
// const bit<8> QUERYSIZE = 256;  
const bit<32> TIME_VALUE = 111;
const bit<9> EGRESS_SPEC_NODES_PORT = 2;
// const bit<32> EGRESS_SPEC_SOURCE_PORT = 1;
const bit<32> HOT_KEY_THRESHOLD = 50;
const bit<32> HOT_KV_PAIR_THRESHOLD = 60;
// const bit<32> 100 = 100;
// const bit<32> 100 = 100;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

header pair_t{
   bit<32> key;
   bit<32> value;
   bit<32> cnt;
}
  
header op_t{
    bit<8> operate;
}

header seq_t{
    bit<8> sequence;
}

struct headers {
	ethernet_t	ethernet;
	ipv4_t 		ipv4;
    tcp_t       tcp;
    // 0:get, 1:put, 3:delete
    op_t op;
    seq_t seq;
    pair_t pair;
}

struct metadata {
	// ethernet_t	ethernet;
	// ipv4_t 		ipv4;
    // tcp_t       tcp;
    // op_t op;
    // seq_t seq;
    // pair_t pair;
}

parser MyParser(packet_in packet,out headers hdr,inout metadata meta,inout standard_metadata_t standard_metadata) {
    state start{
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr,inout metadata meta) {
    apply {  }
}

control MyIngress(inout headers hdr,inout metadata meta,inout standard_metadata_t standard_metadata) {

    bit<32> pos_1; 
    bit<32> pos_2; 
    bit<32> pos_3; 
    bit<32> pos_4; 

    bit<32> key1;
    bit<32> key2;
  
    bit<32> query_old_pair_key;
    bit<32> query_old_pair_value;
    bit<32> query_old_pair_cnt;

    bit<32> query_get_pair_key;
    bit<32> query_get_pair_value;
    bit<32> query_get_pair_cnt;

    bit<32> bucket_key_result;
    bit<32> bucket_pos_result;
    bit<32> bucket_neg_result;
    bit<32> stack_top_result;


    bit<32> stack_pair_keys_res;
    bit<32> stack_pair_values_res;
    bit<32> stack_pair_cnts_res;

    bit<2> marks;
    bit<32> times;
    bit<32> bucket_index;
    bit<32> cnt_tmp;

    register<bit<32>>(16) slot_registers_key_1;
    register<bit<32>>(16) slot_registers_value_1;
    register<bit<32>>(16) slot_registers_cnt_1;
    register<bit<2>>(16) registers_marks_1;
    register<bit<32>>(16) registers_time_1;

    register<bit<32>>(100) buckets_keys;
    register<bit<32>>(100) buckets_pos;
    register<bit<32>>(100) buckets_neg;

    register<bit<32>>(100) stack_pair_keys;
    register<bit<32>>(100) stack_pair_values;
    register<bit<32>>(100) stack_pair_cnts;
    register<bit<32>>(1) stack_top; //这个需要在最开始时置为-1


    action add_to_queue(){

    }

    action send_to_nodes(){
        standard_metadata.egress_spec = EGRESS_SPEC_NODES_PORT;
    }

    action send_to_source(){
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action compute_hashes(bit<32> key) {
        hash(pos_1, HashAlgorithm.crc16, (bit<32>)0, {key}, (bit<32>)1);
        hash(pos_2, HashAlgorithm.crc16, (bit<32>)0, {key}, (bit<32>)16);
    }

    action compute_hash_bucket(bit<32> key) {
        hash(bucket_index, HashAlgorithm.crc16, (bit<32>)0, {key}, (bit<32>)100);
    }

    action process_new_hot_key(bit<32> key) {
        hdr.pair.key = key;
        hdr.pair.value = 32w0;
        hdr.op.operate = 8w0;
        send_to_nodes();
    }

    action process_response() {
        send_to_source();
        stack_top.read(stack_top_result,(bit<32>)32w0);
        stack_top_result = stack_top_result + 32w1;
        stack_top.write((bit<32>)32w0,stack_top_result);

        stack_pair_cnts.write((bit<32>)stack_top_result,hdr.pair.cnt);
        stack_pair_keys.write((bit<32>)stack_top_result,hdr.pair.key);
        stack_pair_values.write((bit<32>)stack_top_result,hdr.pair.value);
    }

    action insert_query() {
        slot_registers_key_1.write((bit<32>)pos_2,hdr.pair.key);
        slot_registers_value_1.write((bit<32>)pos_2,hdr.pair.value);
        slot_registers_cnt_1.write((bit<32>)pos_2,hdr.pair.cnt);
        registers_time_1.write((bit<32>)pos_2,32w0);
        registers_marks_1.write((bit<32>)pos_2,2w0);
    }

    action cache_update(){
        if (hdr.pair.cnt < HOT_KV_PAIR_THRESHOLD) {
            stack_top.read(stack_top_result,(bit<32>)32w0);
            if (stack_top_result >= 0) {
                stack_pair_cnts.read(stack_pair_cnts_res,(bit<32>)stack_top_result);
                stack_pair_keys.read(stack_pair_keys_res,(bit<32>)stack_top_result);
                stack_pair_values.read(stack_pair_values_res,(bit<32>)stack_top_result);

                hdr.pair.cnt = HOT_KV_PAIR_THRESHOLD;
                hdr.pair.key = stack_pair_keys_res;
                hdr.pair.value = stack_pair_values_res;
            }
        }
    }
    action set_recirculate(){
        recirculate<headers>(hdr);
    }

    apply { 
        if (hdr.ipv4.isValid()) { 
            if (hdr.op.operate == 8w1 || hdr.op.operate == 8w2) {
                send_to_nodes(); 
                mark_to_drop(standard_metadata); 
            }else{
                compute_hashes(hdr.pair.key);
                if (pos_1 == 32w1) {
                    slot_registers_key_1.read(query_old_pair_key,(bit<32>)pos_2);
                    slot_registers_value_1.read(query_old_pair_value,(bit<32>)pos_2);
                    slot_registers_cnt_1.read(query_old_pair_cnt,(bit<32>)pos_2);
                    if (query_old_pair_key == 32w0) { 
                        slot_registers_key_1.write((bit<32>)pos_2,hdr.pair.key);
                        slot_registers_value_1.write((bit<32>)pos_2,hdr.pair.value);
                        slot_registers_cnt_1.write((bit<32>)pos_2,hdr.pair.cnt);
                    } else { 
                        registers_marks_1.read(marks,(bit<32>)pos_2);
                        if (marks == 2w0) {
                            registers_time_1.read(times,(bit<32>)pos_2);
                            if (times > TIME_VALUE) {
                                compute_hash_bucket(query_old_pair_key);
                                buckets_keys.read(bucket_key_result,(bit<32>)bucket_index);
                                if (bucket_key_result == 32w0) {
                                    buckets_keys.write((bit<32>)bucket_index,query_old_pair_key);
                                    buckets_pos.write((bit<32>)bucket_index,32w1);
                                    buckets_neg.write((bit<32>)bucket_index,32w0);
                                } else if (bucket_key_result == query_old_pair_key) {
                                    buckets_pos.read(bucket_pos_result,(bit<32>)bucket_index);
                                    bucket_pos_result = bucket_pos_result + 32w1;
                                    buckets_pos.write((bit<32>)bucket_index,bucket_pos_result);
                                    if (bucket_pos_result >= HOT_KEY_THRESHOLD) {
                                        process_new_hot_key(bucket_key_result);
                                        buckets_keys.write((bit<32>)bucket_index,32w0);
                                        buckets_pos.write((bit<32>)bucket_index,32w0);
                                        buckets_neg.write((bit<32>)bucket_index,32w0);
                                    }
                                } else if (bucket_key_result != query_old_pair_key) {
                                    buckets_neg.read(bucket_neg_result,(bit<32>)bucket_index);
                                    bucket_neg_result = bucket_neg_result + 32w1;
                                    buckets_neg.write((bit<32>)bucket_index,bucket_neg_result);
                                    buckets_pos.read(bucket_pos_result,(bit<32>)bucket_index);
                                    if (bucket_neg_result > bucket_pos_result) {
                                        buckets_keys.write((bit<32>)bucket_index,query_old_pair_key);
                                        buckets_pos.write((bit<32>)bucket_index,32w1);
                                        buckets_neg.write((bit<32>)bucket_index,32w0);
                                    }
                                }
                                send_to_nodes();
                                process_response();
                                insert_query();
                            } else {
                                add_to_queue();
                            }
                        } else {
                            insert_query();
                        }
                    }
                }
            }
        } else { 
            compute_hashes(hdr.pair.key);
            if (pos_1 == 1) {
                slot_registers_key_1.read(query_get_pair_key,(bit<32>)pos_2);
                slot_registers_value_1.read(query_get_pair_value,(bit<32>)pos_2);
                slot_registers_cnt_1.read(query_get_pair_cnt,(bit<32>)pos_2);
                if (query_get_pair_key != 32w0) { 
                    registers_marks_1.read(marks,(bit<32>)pos_2);
                    if (marks == 2w0) {
                        if (hdr.pair.key == query_get_pair_key) {
                            registers_marks_1.write((bit<32>)pos_2,2w1);
                            hdr.pair.key = 32w0;
                            hdr.pair.value = query_get_pair_value;
                            send_to_source();
                            cnt_tmp = query_get_pair_cnt + 32w1;
                            slot_registers_cnt_1.write((bit<32>)pos_2,cnt_tmp);
                        }
                    }
                }
            }
            compute_hashes(hdr.pair.key);
            slot_registers_cnt_1.read(cnt_tmp,(bit<32>)pos_2);
            if (cnt_tmp < HOT_KV_PAIR_THRESHOLD) {
                stack_top.read(stack_top_result,(bit<32>)32w0);
                if (stack_top_result >= 0) {
                    stack_pair_cnts.read(stack_pair_cnts_res,(bit<32>)stack_top_result);
                    stack_pair_keys.read(stack_pair_keys_res,(bit<32>)stack_top_result);
                    stack_pair_values.read(stack_pair_values_res,(bit<32>)stack_top_result);

                    hdr.pair.cnt = HOT_KV_PAIR_THRESHOLD;
                    hdr.pair.key = stack_pair_keys_res;
                    hdr.pair.value = stack_pair_values_res;
                }
            }
            add_to_queue();
        }
       
    }
} 


control MyEgress(inout headers hdr,inout metadata meta,inout standard_metadata_t standard_metadata){
    apply { }
}
control MyComputeChecksum(inout headers hdr,inout metadata meta) {
    apply {}
}
control MyDeparser(packet_out packet,in headers hdr) {
    apply {}
}


V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
