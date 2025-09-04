/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_CUSTOM = 16w0x8888; // 新增自定义以太网类型用于CPU头部

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const bit<8> TCP_FLAGS_SYN = 0x2;

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1

const bit<16> CUSTOM_ETHER_TYPE = 0x8888;
const bit<32> CPU_HEADER_LENGTH = 178; // 以太网头部(14字节) + cpu_h(144字节)

#define Flow_PACKETS 2

register<bit<32>>(1) link_utilization; // 链路利用寄存器
register<bit<32>>(1) Hash_collision; 

// 以太网头部
header ethernet_t
{
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv4头部
header ipv4_t
{
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv; // tos
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

// TCP头部
header tcp_t
{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> reserved;
    bit<9> tcp_flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// UDP头部
header udp_t
{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

// 上报cpu的特征数据包
header cpu_h
{
    // mac_addr_t src_mac_addr;     // 原有字段：源MAC地址
    // bit<16> ingress_port;        // 原有字段：入口端口
    //  五元组
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<32> srcPort;
    bit<32> dstPort;
    bit<32> ipProtocol;

    // 第一组14个特征
    bit<32> ip_len1;
    bit<32> ip_ttl1;
    bit<32> ip_proto1;
    bit<32> ip_tos1;
    bit<32> ip_payload1;
    bit<32> ip_ihl1;
    bit<32> ip_flags1;
    bit<32> ip_id1;
    bit<32> ip_frag1;
    bit<32> ip_chksum1;
    bit<32> tcp_flags1;
    bit<32> tcp_window1;
    bit<32> tcp_optlen1;
    bit<32> tcp_dataofs1;
    bit<32> udp_len1;
    bit<32> udp_chksum1;
    bit<64> ingress_timestamp1;

    // 第二组14个特征
    bit<32> ip_len2;
    bit<32> ip_ttl2;
    bit<32> ip_proto2;
    bit<32> ip_tos2;
    bit<32> ip_payload2;
    bit<32> ip_ihl2;
    bit<32> ip_flags2;
    bit<32> ip_id2;
    bit<32> ip_frag2;
    bit<32> ip_chksum2;
    bit<32> tcp_flags2;
    bit<32> tcp_window2;
    bit<32> tcp_optlen2;
    bit<32> tcp_dataofs2;
    bit<32> udp_len2;
    bit<32> udp_chksum2;
    bit<64> ingress_timestamp2;
}

// 头部结构
struct headers
{
    ethernet_t ethernet;
    cpu_h cpu;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

// 元数据结构
struct metadata
{
    @field_list(0)
        bit<32> hash_index; // 指定在克隆时保留的字段
    // bit<9> ingress_port;
    //  IP层特征
    bit<16> ip_len;
    bit<8> ip_ttl;
    bit<8> ip_proto;
    bit<8> ip_tos;
    bit<16> ip_payload;
    bit<4> ip_ihl;
    bit<3> ip_flags;
    bit<16> ip_id;
    bit<13> ip_frag;
    bit<16> ip_chksum;
    // 传输层特征
    bit<9> tcp_flags;
    bit<16> tcp_window;
    bit<8> tcp_optlen;
    bit<4> tcp_dataofs;
    bit<16> udp_len;
    bit<16> udp_chksum;
    // 时间特征
    bit<48> ingress_timestamp;
    // 五元组用于流标识
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8> ipProtocol;
    // 哈希索引
    // bit<32> hash_index;
    bit<32> hash_index_32;

    bit<32> entry_value; // 表项中的值
    bit<32> reg_value;   // 寄存器中的值
}

typedef bit<9> egressSpec_t;
// 寄存器定义
const bit<32> HASH_SIZE = 32w65536;              // 2^16个槽位
register<bit<8>>(HASH_SIZE) counter_reg;         // 记录每个流的包数量（最多2）
register<bit<32>>(HASH_SIZE) hash_index_crc32;   // 记录crc_32哈希值
register<bit<64>>(HASH_SIZE) last_timestamp_reg; // 记录流中最后一个包的时间戳

// 特征寄存器（每个寄存器大小为 HASH_SIZE * 2，支持2个数据包）
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_len_reg;     // IP总长度
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_ttl_reg;     // TTL
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_proto_reg;   // 协议类型
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_tos_reg;     // 服务类型
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_payload_reg; // 负载长度
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_ihl_reg;     // 头部长度（4字节单位）
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_flags_reg;   // 标志位
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_id_reg;      // 标识
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_frag_reg;    // 分片偏移
register<bit<32>>(HASH_SIZE *Flow_PACKETS) ip_chksum_reg;  // 校验和

register<bit<32>>(HASH_SIZE *Flow_PACKETS) tcp_flags_reg;   // TCP标志位
register<bit<32>>(HASH_SIZE *Flow_PACKETS) tcp_window_reg;  // 窗口大小
register<bit<32>>(HASH_SIZE *Flow_PACKETS) tcp_optlen_reg;  // 选项长度
register<bit<32>>(HASH_SIZE *Flow_PACKETS) tcp_dataofs_reg; // 数据偏移

register<bit<32>>(HASH_SIZE *Flow_PACKETS) udp_len_reg;           // UDP长度
register<bit<32>>(HASH_SIZE *Flow_PACKETS) udp_chksum_reg;        // UDP校验和
register<bit<64>>(HASH_SIZE *Flow_PACKETS) ingress_timestamp_reg; // 48位

// 五元组寄存器（每个寄存器大小为 HASH_SIZE * 2）
register<bit<32>>(HASH_SIZE *Flow_PACKETS) src_ip_reg;   // 32位 源IP
register<bit<32>>(HASH_SIZE *Flow_PACKETS) dst_ip_reg;   // 32位 目的IP
register<bit<32>>(HASH_SIZE *Flow_PACKETS) src_port_reg; // 16位 源端口
register<bit<32>>(HASH_SIZE *Flow_PACKETS) dst_port_reg; // 16位 目的端口
register<bit<32>>(HASH_SIZE *Flow_PACKETS) protocol_reg; // 8位 协议

// 解析器
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    state start
    {
        transition parse_ethernet;
    }

    state parse_ethernet
    {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType)
        {
            0x800 : parse_ipv4;
        default:
            accept;
        }
    }

    state parse_ipv4
    {
        packet.extract(hdr.ipv4);
        // 提取IP层特征
        meta.ip_len = hdr.ipv4.totalLen;
        meta.ip_ttl = hdr.ipv4.ttl;
        meta.ip_proto = hdr.ipv4.protocol;
        meta.ip_tos = hdr.ipv4.diffserv;
        meta.ip_ihl = hdr.ipv4.ihl;
        meta.ip_flags = hdr.ipv4.flags;
        meta.ip_id = hdr.ipv4.identification;
        meta.ip_frag = hdr.ipv4.fragOffset;
        meta.ip_chksum = hdr.ipv4.hdrChecksum;
        // 提取五元组字段
        meta.srcAddr = hdr.ipv4.srcAddr;
        meta.dstAddr = hdr.ipv4.dstAddr;
        meta.ipProtocol = hdr.ipv4.protocol;
        meta.srcPort = 16w0;
        meta.dstPort = 16w0;
        // 初始化传输层特征为0
        meta.tcp_flags = 9w0;
        meta.tcp_window = 16w0;
        meta.tcp_optlen = 8w0;
        meta.tcp_dataofs = 4w0;
        meta.udp_len = 16w0;
        meta.udp_chksum = 16w0;
        // 提取时间特征
        meta.ingress_timestamp = standard_metadata.ingress_global_timestamp;
        transition select(hdr.ipv4.protocol)
        {
            8w0x6 : parse_tcp;
            8w0x11 : parse_udp;
        default:
            accept;
        }
    }

    state parse_tcp
    {
        packet.extract(hdr.tcp);
        meta.srcPort = hdr.tcp.srcPort;
        meta.dstPort = hdr.tcp.dstPort;
        meta.tcp_flags = hdr.tcp.tcp_flags;
        meta.tcp_window = hdr.tcp.window;
        meta.tcp_dataofs = hdr.tcp.dataOffset;
        // Calculate TCP option length
        if (hdr.tcp.dataOffset > 5)
        {
            meta.tcp_optlen = ((bit<8>)hdr.tcp.dataOffset - 8w5) << 2;
        }
        else
        {
            meta.tcp_optlen = 8w0;
        }
        // Calculate payload length
        bit<16> ip_header_len = ((bit<16>)hdr.ipv4.ihl) << 2;
        bit<16> tcp_header_len = ((bit<16>)hdr.tcp.dataOffset) << 2;
        meta.ip_payload = hdr.ipv4.totalLen - ip_header_len - tcp_header_len;
        transition accept;
    }

    state parse_udp
    {
        packet.extract(hdr.udp);
        meta.srcPort = hdr.udp.srcPort;
        meta.dstPort = hdr.udp.dstPort;
        meta.udp_len = hdr.udp.udplen;
        meta.udp_chksum = hdr.udp.udpchk;
        meta.ip_payload = hdr.udp.udplen - 16w8; // UDP负载长度
        transition accept;
    }
}

// 校验和验证
control MyVerifyChecksum(inout headers hdr, inout metadata meta)
{
    apply {}
}

// 入口控制
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{

    counter(1, CounterType.bytes) bytes_counter;

    action drop()
    {
        mark_to_drop(standard_metadata);
    }

    action set_output_port(egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
    }

    action send_to_cpu()
    {
        // meta.ingress_port = standard_metadata.ingress_port;
        clone_preserving_field_list(CloneType.I2E, 100, 0); // 克隆并保留field_list 0
    }

    // 动作：从表项中获取值并存储到元数据
    action set_entry_value(bit<32> value)
    {
        meta.entry_value = value;
    }

    // 定义表：基于五元组匹配
    table my_table
    {
        key = {
            hdr.ipv4.srcAddr : exact;
        hdr.ipv4.dstAddr : exact;
        hdr.ipv4.protocol : exact;
        hdr.tcp.srcPort : exact; // TCP 源端口
        hdr.tcp.dstPort : exact; // TCP 目的端口
    }
    actions = {
        set_entry_value;
    NoAction;
}
default_action = NoAction;
size = 10000000;
}

table my_table_udp
{
    key = {
        hdr.ipv4.srcAddr : exact;
    hdr.ipv4.dstAddr : exact;
    hdr.ipv4.protocol : exact;
    hdr.udp.srcPort : exact; // UDP 源端口
    hdr.udp.dstPort : exact; // UDP 目的端口
}
actions = {
    set_entry_value;
NoAction;
}
size = 10000000;
default_action = NoAction;
}

apply
{
    bytes_counter.count(0);
    if (hdr.ipv4.isValid())
    {
        if (my_table.apply().hit || my_table_udp.apply().hit)
        {
            // 匹配成功，读取寄存器值
            link_utilization.read(meta.reg_value, 0);
            // 比较表项值和寄存器值
            if (meta.entry_value > meta.reg_value)
            {
                standard_metadata.egress_spec = 2; // 转发到端口2
            }
            else
            {
                mark_to_drop(standard_metadata); // 丢弃
            }
        }
        else
        {
            // 失配，特征收集

            // change_switch_output_port.apply();
            //  计算哈希索引
            hash(meta.hash_index, HashAlgorithm.crc16, 32w0,
                 {meta.srcAddr, meta.srcPort, meta.dstAddr, meta.dstPort, meta.ipProtocol},
                 HASH_SIZE);
            hash(meta.hash_index_32, HashAlgorithm.crc32, 32w0,
                 {meta.srcAddr, meta.srcPort, meta.dstAddr, meta.dstPort, meta.ipProtocol},
                 32w65535);

            bit<32> flow_hash_check;
            hash_index_crc32.read(flow_hash_check, meta.hash_index);

            bit<8> flow_counter;
            counter_reg.read(flow_counter, (bit<32>)meta.hash_index);

            // 获取流中最后数据包的时间戳
            //  bit<64> flow_last_time_1;
            //  ingress_timestamp_reg.read(flow_last_time_1,meta.hash_index);
            //  bit<64> flow_last_time_2;
            //  ingress_timestamp_reg.read(flow_last_time_2,meta.hash_index+HASH_SIZE);
            //  bit<64> flow_last_time_max;
            //  flow_last_time_max=flow_last_time_1;
            //  if(flow_last_time_2>flow_last_time_1)
            //  {
            //      flow_last_time_max=flow_last_time_2;
            //  }
            //  bit<64> timeout = (bit<64>)meta.ingress_timestamp-flow_last_time_max;
            bit<64> flow_last_time;
            last_timestamp_reg.read(flow_last_time, meta.hash_index);
            bit<64> timeout = (bit<64>)meta.ingress_timestamp - flow_last_time;

            if (flow_hash_check == 0)
            {
                // crc32校验位为空执行写入
                hash_index_crc32.write(meta.hash_index, meta.hash_index_32);
                if (flow_counter < Flow_PACKETS)
                {
                    // 读取流计数器

                    // 如果包数少于2，存储特征和五元组
                    // bit<32> reg_index = ((bit<32>)meta.hash_index << 1) + (bit<32>)flow_counter;
                    bit<32> reg_index = (bit<32>)meta.hash_index + (bit<32>)flow_counter * HASH_SIZE;
                    // 存储五元组
                    src_ip_reg.write(reg_index, meta.srcAddr);
                    dst_ip_reg.write(reg_index, meta.dstAddr);
                    src_port_reg.write(reg_index, (bit<32>)meta.srcPort);
                    dst_port_reg.write(reg_index, (bit<32>)meta.dstPort);
                    protocol_reg.write(reg_index, (bit<32>)meta.ipProtocol);
                    // 存储特征
                    ip_len_reg.write(reg_index, (bit<32>)meta.ip_len);
                    ip_ttl_reg.write(reg_index, (bit<32>)meta.ip_ttl);
                    ip_proto_reg.write(reg_index, (bit<32>)meta.ip_proto);
                    ip_tos_reg.write(reg_index, (bit<32>)meta.ip_tos);
                    ip_payload_reg.write(reg_index, (bit<32>)meta.ip_payload);
                    ip_ihl_reg.write(reg_index, (bit<32>)meta.ip_ihl);
                    ip_flags_reg.write(reg_index, (bit<32>)meta.ip_flags);
                    ip_id_reg.write(reg_index, (bit<32>)meta.ip_id);
                    ip_frag_reg.write(reg_index, (bit<32>)meta.ip_frag);
                    ip_chksum_reg.write(reg_index, (bit<32>)meta.ip_chksum);
                    tcp_flags_reg.write(reg_index, (bit<32>)meta.tcp_flags);
                    tcp_window_reg.write(reg_index, (bit<32>)meta.tcp_window);
                    tcp_optlen_reg.write(reg_index, (bit<32>)meta.tcp_optlen);
                    tcp_dataofs_reg.write(reg_index, (bit<32>)meta.tcp_dataofs);
                    udp_len_reg.write(reg_index, (bit<32>)meta.udp_len);
                    udp_chksum_reg.write(reg_index, (bit<32>)meta.udp_chksum);
                    ingress_timestamp_reg.write(reg_index, (bit<64>)meta.ingress_timestamp);
                    // 增加计数器
                    counter_reg.write((bit<32>)meta.hash_index, flow_counter + 8w1);
                    // 记录最后包的时间戳
                    last_timestamp_reg.write((bit<32>)meta.hash_index, (bit<64>)meta.ingress_timestamp);
                }
            }
            else if (meta.hash_index_32 == flow_hash_check)
            {
                if(flow_counter==0)
                {
                    set_output_port(2);
                    exit;
                }

                // 索引处流crc32校验与当前数据包一致
                if (flow_counter < Flow_PACKETS)
                {
                    // 读取流计数器

                    // 如果包数少于2，存储特征和五元组
                    // bit<32> reg_index = ((bit<32>)meta.hash_index << 1) + (bit<32>)flow_counter;
                    bit<32> reg_index = (bit<32>)meta.hash_index + (bit<32>)flow_counter * HASH_SIZE;
                    // 存储五元组
                    src_ip_reg.write(reg_index, meta.srcAddr);
                    dst_ip_reg.write(reg_index, meta.dstAddr);
                    src_port_reg.write(reg_index, (bit<32>)meta.srcPort);
                    dst_port_reg.write(reg_index, (bit<32>)meta.dstPort);
                    protocol_reg.write(reg_index, (bit<32>)meta.ipProtocol);
                    // 存储特征
                    ip_len_reg.write(reg_index, (bit<32>)meta.ip_len);
                    ip_ttl_reg.write(reg_index, (bit<32>)meta.ip_ttl);
                    ip_proto_reg.write(reg_index, (bit<32>)meta.ip_proto);
                    ip_tos_reg.write(reg_index, (bit<32>)meta.ip_tos);
                    ip_payload_reg.write(reg_index, (bit<32>)meta.ip_payload);
                    ip_ihl_reg.write(reg_index, (bit<32>)meta.ip_ihl);
                    ip_flags_reg.write(reg_index, (bit<32>)meta.ip_flags);
                    ip_id_reg.write(reg_index, (bit<32>)meta.ip_id);
                    ip_frag_reg.write(reg_index, (bit<32>)meta.ip_frag);
                    ip_chksum_reg.write(reg_index, (bit<32>)meta.ip_chksum);
                    tcp_flags_reg.write(reg_index, (bit<32>)meta.tcp_flags);
                    tcp_window_reg.write(reg_index, (bit<32>)meta.tcp_window);
                    tcp_optlen_reg.write(reg_index, (bit<32>)meta.tcp_optlen);
                    tcp_dataofs_reg.write(reg_index, (bit<32>)meta.tcp_dataofs);
                    udp_len_reg.write(reg_index, (bit<32>)meta.udp_len);
                    udp_chksum_reg.write(reg_index, (bit<32>)meta.udp_chksum);
                    ingress_timestamp_reg.write(reg_index, (bit<64>)meta.ingress_timestamp);
                    // 增加计数器
                    counter_reg.write((bit<32>)meta.hash_index, flow_counter + 8w1);
                    // 记录最后包的时间戳
                    last_timestamp_reg.write((bit<32>)meta.hash_index, (bit<64>)meta.ingress_timestamp);
                }
                bit<8> flow_counter_now;
                counter_reg.read(flow_counter_now, (bit<32>)meta.hash_index);
                if (flow_counter_now == Flow_PACKETS)
                {
                    send_to_cpu();
                    set_output_port(2);
                    //hash_index_crc32.write(meta.hash_index,0);
                    counter_reg.write(meta.hash_index,0);
                    exit;
                }
            }
            // 发生hash冲突
            else if ((bit<64>)meta.ingress_timestamp != timeout)
            {
                if (timeout > 100000||flow_counter == 0)
                {

                    // 到达流超时时间
                    counter_reg.write(meta.hash_index, 0);
                    hash_index_crc32.write(meta.hash_index, meta.hash_index_32);
                    flow_counter = 8w0;
                    // 读取流计数器

                    // 如果包数少于2，存储特征和五元组
                    // bit<32> reg_index = ((bit<32>)meta.hash_index << 1) + (bit<32>)flow_counter;
                    bit<32> reg_index = (bit<32>)meta.hash_index + (bit<32>)flow_counter * HASH_SIZE;
                    // 存储五元组
                    src_ip_reg.write(reg_index, meta.srcAddr);
                    dst_ip_reg.write(reg_index, meta.dstAddr);
                    src_port_reg.write(reg_index, (bit<32>)meta.srcPort);
                    dst_port_reg.write(reg_index, (bit<32>)meta.dstPort);
                    protocol_reg.write(reg_index, (bit<32>)meta.ipProtocol);
                    // 存储特征
                    ip_len_reg.write(reg_index, (bit<32>)meta.ip_len);
                    ip_ttl_reg.write(reg_index, (bit<32>)meta.ip_ttl);
                    ip_proto_reg.write(reg_index, (bit<32>)meta.ip_proto);
                    ip_tos_reg.write(reg_index, (bit<32>)meta.ip_tos);
                    ip_payload_reg.write(reg_index, (bit<32>)meta.ip_payload);
                    ip_ihl_reg.write(reg_index, (bit<32>)meta.ip_ihl);
                    ip_flags_reg.write(reg_index, (bit<32>)meta.ip_flags);
                    ip_id_reg.write(reg_index, (bit<32>)meta.ip_id);
                    ip_frag_reg.write(reg_index, (bit<32>)meta.ip_frag);
                    ip_chksum_reg.write(reg_index, (bit<32>)meta.ip_chksum);
                    tcp_flags_reg.write(reg_index, (bit<32>)meta.tcp_flags);
                    tcp_window_reg.write(reg_index, (bit<32>)meta.tcp_window);
                    tcp_optlen_reg.write(reg_index, (bit<32>)meta.tcp_optlen);
                    tcp_dataofs_reg.write(reg_index, (bit<32>)meta.tcp_dataofs);
                    udp_len_reg.write(reg_index, (bit<32>)meta.udp_len);
                    udp_chksum_reg.write(reg_index, (bit<32>)meta.udp_chksum);
                    ingress_timestamp_reg.write(reg_index, (bit<64>)meta.ingress_timestamp);
                    // 增加计数器
                    counter_reg.write((bit<32>)meta.hash_index, flow_counter + 8w1);
                    // 记录最后包的时间戳
                    last_timestamp_reg.write((bit<32>)meta.hash_index, (bit<64>)meta.ingress_timestamp);
                }
                            else
            {
                                bit<32> hash_coll;
                    Hash_collision.read(hash_coll,0);
                    Hash_collision.write(0, hash_coll+32w1);
                // 默认动作
                set_output_port(2);
            }
                
            }
            else
            {

                // 默认动作
                set_output_port(2);
            }

            set_output_port(2);
            // bit<8> flow_counter_now;
            // counter_reg.read(flow_counter_now, (bit<32>)meta.hash_index);
            // if (flow_counter_now == Flow_PACKETS)
            // {
            //     // 执行上报
            //     // log_msg("meta.hash_value:{},{},{},{},{},{}",{meta.hash_index,meta.srcAddr, meta.srcPort, meta.dstAddr, meta.dstPort, meta.ipProtocol});
            //     send_to_cpu();
            //     // hash_index_crc32.write(meta.hash_index,0);
            //     // counter_reg.write(meta.hash_index,0);
            // }
        }
    }
}
}

// 出口控制
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    apply
    {
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE)
        {
            hdr.cpu.setValid();
            // hdr.cpu.src_mac_addr = hdr.ethernet.srcAddr;

            // hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;

            // hash(meta.hash_index, HashAlgorithm.crc16, 32w0,
            //      {hdr.ipv4.srcAddr, hdr.udp.srcPort, hdr.ipv4.dstAddr, hdr.udp.dstPort, IP_PROTOCOLS_UDP},
            //      HASH_SIZE);

            // log_msg("meta.hash_value:{},{},{},{},{},{}",{hdr.ipv4.srcAddr,hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, IP_PROTOCOLS_UDP,meta.hash_index});
            src_ip_reg.read(hdr.cpu.srcAddr, (bit<32>)meta.hash_index);
            dst_ip_reg.read(hdr.cpu.dstAddr, (bit<32>)meta.hash_index);
            src_port_reg.read(hdr.cpu.srcPort, (bit<32>)meta.hash_index);
            dst_port_reg.read(hdr.cpu.dstPort, (bit<32>)meta.hash_index);
            protocol_reg.read(hdr.cpu.ipProtocol, (bit<32>)meta.hash_index);

            ip_len_reg.read(hdr.cpu.ip_len1, (bit<32>)meta.hash_index);
            ip_ttl_reg.read(hdr.cpu.ip_ttl1, (bit<32>)meta.hash_index);
            ip_proto_reg.read(hdr.cpu.ip_proto1, (bit<32>)meta.hash_index);
            ip_tos_reg.read(hdr.cpu.ip_tos1, (bit<32>)meta.hash_index);
            ip_payload_reg.read(hdr.cpu.ip_payload1, (bit<32>)meta.hash_index);
            ip_ihl_reg.read(hdr.cpu.ip_ihl1, (bit<32>)meta.hash_index);
            ip_flags_reg.read(hdr.cpu.ip_flags1, (bit<32>)meta.hash_index);
            ip_id_reg.read(hdr.cpu.ip_id1, (bit<32>)meta.hash_index);
            ip_frag_reg.read(hdr.cpu.ip_frag1, (bit<32>)meta.hash_index);
            ip_chksum_reg.read(hdr.cpu.ip_chksum1, (bit<32>)meta.hash_index);

            tcp_flags_reg.read(hdr.cpu.tcp_flags1, (bit<32>)meta.hash_index);
            tcp_window_reg.read(hdr.cpu.tcp_window1, (bit<32>)meta.hash_index);
            tcp_optlen_reg.read(hdr.cpu.tcp_optlen1, (bit<32>)meta.hash_index);
            tcp_dataofs_reg.read(hdr.cpu.tcp_dataofs1, (bit<32>)meta.hash_index);
            udp_len_reg.read(hdr.cpu.udp_len1, (bit<32>)meta.hash_index);
            udp_chksum_reg.read(hdr.cpu.udp_chksum1, (bit<32>)meta.hash_index);
            ingress_timestamp_reg.read(hdr.cpu.ingress_timestamp1, (bit<32>)meta.hash_index);

            ip_len_reg.read(hdr.cpu.ip_len2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_ttl_reg.read(hdr.cpu.ip_ttl2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_proto_reg.read(hdr.cpu.ip_proto2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_tos_reg.read(hdr.cpu.ip_tos2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_payload_reg.read(hdr.cpu.ip_payload2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_ihl_reg.read(hdr.cpu.ip_ihl2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_flags_reg.read(hdr.cpu.ip_flags2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_id_reg.read(hdr.cpu.ip_id2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_frag_reg.read(hdr.cpu.ip_frag2, (bit<32>)meta.hash_index + HASH_SIZE);
            ip_chksum_reg.read(hdr.cpu.ip_chksum2, (bit<32>)meta.hash_index + HASH_SIZE);

            tcp_flags_reg.read(hdr.cpu.tcp_flags2, (bit<32>)meta.hash_index + HASH_SIZE);
            tcp_window_reg.read(hdr.cpu.tcp_window2, (bit<32>)meta.hash_index + HASH_SIZE);
            tcp_optlen_reg.read(hdr.cpu.tcp_optlen2, (bit<32>)meta.hash_index + HASH_SIZE);
            tcp_dataofs_reg.read(hdr.cpu.tcp_dataofs2, (bit<32>)meta.hash_index + HASH_SIZE);
            udp_len_reg.read(hdr.cpu.udp_len2, (bit<32>)meta.hash_index + HASH_SIZE);
            udp_chksum_reg.read(hdr.cpu.udp_chksum2, (bit<32>)meta.hash_index + HASH_SIZE);
            ingress_timestamp_reg.read(hdr.cpu.ingress_timestamp2, (bit<32>)meta.hash_index + HASH_SIZE);

            // 设置自定义以太网类型
            hdr.ethernet.etherType = CUSTOM_ETHER_TYPE;
            // 截断数据包到指定长度
            truncate(CPU_HEADER_LENGTH);
        }
    }
}

// 校验和计算
control MyComputeChecksum(inout headers hdr, inout metadata meta)
{
    apply
    {
        update_checksum(
            hdr.ipv4.isValid(),
            {hdr.ipv4.version,
             hdr.ipv4.ihl,
             hdr.ipv4.diffserv,
             hdr.ipv4.totalLen,
             hdr.ipv4.identification,
             hdr.ipv4.flags,
             hdr.ipv4.fragOffset,
             hdr.ipv4.ttl,
             hdr.ipv4.protocol,
             hdr.ipv4.srcAddr,
             hdr.ipv4.dstAddr},
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// 反解析器
control MyDeparser(packet_out packet, in headers hdr)
{
    apply
    {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

// 主程序
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()) main;
