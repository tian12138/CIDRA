#!/usr/bin/python3
import threading
import queue
import time
import torch
import numpy as np
import pandas as pd
from scapy.all import *
from sklearn.preprocessing import StandardScaler
import joblib
import os
import sys
import logging
import subprocess
from Model import TemporalModel
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../utils/'))
import p4runtime_sh.shell as sh

# 日志配置
log_file = 'p4runtime_log.txt'
logging.basicConfig(
    level=logging.INFO,  # 可切换为 DEBUG 以进行调试
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# 常量配置
FEATURE_DIM = 14
WINDOW_SIZE = 2
TIME_DIM = 2
MODEL_PATH = "/data/tianxiao/P4/tutorials/exercises/ceshi/model_old/transformer_lstm32-14-time-3.pth"
SCALER_PATH = "/data/tianxiao/P4/tutorials/exercises/ceshi/model_old/scaler1-time-3.pkl"
BATCH_SIZE = 4096  # 批量下发的表项数量
conf.bufsize=1048576000
# 自定义 CPU 头部定义
class CustomCpuHeader(Packet):
    name = 'CustomCpuPacket'
    fields_desc = [
        IPField('src_ip', '0.0.0.0'), IPField('dst_ip', '0.0.0.0'), IntField('src_port', 0), IntField('dst_port', 0),
        IntField('protocol', 0), *[IntField(f'feature{i}', 0) for i in range(1, 17)],
        LongField('timestamp1', 0), *[IntField(f'feature{i}', 0) for i in range(17, 33)],
        LongField('timestamp2', 0)
    ]

# 全局计数器
capture_count = 0
prediction_count = 0
insertion_count = 0
dropped_count = 0
processed_count = 0  # 已处理的五元组数量
duplicate_count = 0  # 重复项计数

# 混淆矩阵
tp, tn, fp, fn = 0, 0, 0, 0  # True Positive, True Negative, False Positive, False Negative

# 队列
capture_queue = queue.Queue(maxsize=100000000)
insertion_queue = queue.Queue(maxsize=100000000)

# 锁
lock = threading.Lock()

# 特征名称
feature_names = [f'pkt{i}_f{j}' for i in range(WINDOW_SIZE) for j in range(FEATURE_DIM)] + \
                [f'time{i+1}' for i in range(TIME_DIM)]

# 加载模型和 scaler
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = torch.load(MODEL_PATH, map_location=device).double()
model.to(device).eval()
scaler = joblib.load(SCALER_PATH)

# 已下发的五元组集合
inserted_tuples = set()

# 获取表项数量的函数
def get_table_entry_count(table_name):
    command = f"simple_switch_CLI <<EOF\ntable_num_entries {table_name}\nEOF"
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        for line in output.splitlines():
            if line.startswith("RuntimeCmd:"):
                return int(line.split()[-1])
        return 0
    except subprocess.CalledProcessError as e:
        logging.error(f"获取表项数量失败: {e}")
        return None

# 数据包捕获线程
def capture_thread1(iface):
    def packet_callback(packet):
        global capture_count, dropped_count
        packet = Ether(raw(packet))
        #if packet.type == 0x8888:
        with lock:
            capture_count += 1
        try:
            capture_queue.put_nowait(packet)
            logging.debug(f"捕获数据包，队列大小: {capture_queue.qsize()}")
        except queue.Full:
            with lock:
                dropped_count += 1
            logging.warning(f"捕获队列已满，丢弃数据包，总丢弃数: {dropped_count}")
    logging.info(f"启动捕获线程，接口: {iface}")
    sniff(iface=iface, prn=packet_callback, filter="ether proto 0x8888", store=0)  # 持续捕获
    
def capture_thread2(iface):
    global capture_count, dropped_count
    # 使用 tcpdump 捕获并保存到文件
    p = subprocess.Popen(["tcpdump", "-i", iface, "-w", "capture.pcap"], stderr=subprocess.PIPE)
    time.sleep(20)  # 捕获一段时间
    p.terminate()
    
    # 读取 pcap 文件
    packets = rdpcap("capture.pcap")
    for packet in packets:
        with lock:
            capture_count += 1
        try:
            capture_queue.put(packet, timeout=0.1)
        except queue.Full:
            with lock:
                dropped_count += 1
            logging.warning("捕获队列已满，丢弃数据包")    
# 捕获线程（使用 tcpdump 实时模式）
def capture_thread(iface):
    logging.info(f"启动捕获线程，接口: {iface}")
    global capture_count, dropped_count
    try:
        # 启动 tcpdump，实时输出到管道
        cmd = [
            "tcpdump",
            "-i", iface,
            "-l",          # 行缓冲模式，确保实时输出
            "-w", "-",     # 输出到 stdout
            "ether proto 0x8888"  # 过滤器
        ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 使用 PcapReader 从管道读取数据包
        pcap_reader = PcapReader(process.stdout)        
        for packet in pcap_reader:
            with lock:
                capture_count += 1
            try:
                # 将数据包放入队列
                capture_queue.put(packet, timeout=0.1)
            except queue.Full:
                with lock:
                    dropped_count += 1
                logging.warning(f"捕获队列已满，丢弃数据包，总丢弃数: {dropped_count}")
        # 处理 tcpdump 退出
        process.wait()
        if process.returncode != 0:
            error = process.stderr.read().decode()
            logging.error(f"tcpdump 退出，错误: {error}")
    except Exception as e:
        logging.error(f"捕获线程错误: {e}")
    
# 用于计算平均延迟的全局变量
total_processing_time = 0.0  # 总处理时间
total_flow_count = 0         # 总流数量
# 概率预测线程
def prediction_thread(batch_size=64):
    global prediction_count, processed_count, tp, tn, fp, fn, duplicate_count,total_processing_time, total_flow_count
    logging.info("启动预测线程")
    while True:
        packets = []
        try:
            # 阻塞等待一个数据包
            packet = capture_queue.get(timeout=1)
            packets.append(packet)
            logging.debug(f"从捕获队列中获取到一个数据包，当前捕获队列大小: {capture_queue.qsize()}")
            
            # 非阻塞获取更多数据包组成批量
            for _ in range(batch_size - 1):
                try:
                    packet = capture_queue.get_nowait()
                    packets.append(packet)
                except queue.Empty:
                    break
        except queue.Empty:
            logging.debug("捕获队列为空，预测线程等待")
            continue
        except Exception as e:
            logging.error(f"预测线程在获取数据包时发生错误: {e}")
            continue

        if not packets:
            continue

        features_list, timestamps_list, protocols, packets_to_process = [], [], [], []
        for packet in packets:
            try:
                cpu_header = CustomCpuHeader(bytes(packet.load))
                five_tuple = (str(cpu_header.src_ip), str(cpu_header.dst_ip), cpu_header.protocol, 
                              cpu_header.src_port, cpu_header.dst_port)
                if five_tuple in inserted_tuples:
                    with lock:
                        duplicate_count += 1
                    continue
                pkt1_features = [getattr(cpu_header, f'feature{i}') for i in range(1, 17)]
                pkt2_features = [getattr(cpu_header, f'feature{i}') for i in range(17, 33)]
                features = [pkt1_features, pkt2_features]
                timestamps = [0, 0]
                #timestamps = [cpu_header.timestamp1, cpu_header.timestamp2]

                features_list.append(features)
                timestamps_list.append(timestamps)
                protocols.append(cpu_header.protocol)
                packets_to_process.append((five_tuple, cpu_header))
            except Exception as e:
                logging.error(f"处理数据包时发生错误: {e}")
                continue

        if not features_list:
            logging.warning("没有有效的数据包需要预测")
            continue

        try:
            combined_list = []
            for features, timestamps, protocol in zip(features_list, timestamps_list, protocols):
                pkt1_features, pkt2_features = features[0], features[1]
                if protocol == 6:  # TCP
                    pkt1_features = pkt1_features[:14]
                    pkt2_features = pkt2_features[:14]
                elif protocol == 17:  # UDP
                    pkt1_features = pkt1_features[:10] + pkt1_features[14:16] + [0, 0]
                    pkt2_features = pkt2_features[:10] + pkt2_features[14:16] + [0, 0]
                else:
                    continue
                flat_features = pkt1_features + pkt2_features
                combined_list.append(flat_features + timestamps)

            if not combined_list:
                logging.warning("没有有效的数据包需要预测")
                continue

            df = pd.DataFrame(combined_list, columns=feature_names)
            scaled = scaler.transform(df)
            features = scaled[:, :WINDOW_SIZE * FEATURE_DIM].reshape(-1, WINDOW_SIZE, FEATURE_DIM)
            timestamps = scaled[:, WINDOW_SIZE * FEATURE_DIM:]

            features_tensor = torch.FloatTensor(features).to(device)
            ts_tensor = torch.FloatTensor(timestamps).to(device)

            with torch.no_grad():
                start_time = time.time()
                features_tensor = features_tensor.permute(1, 0, 2)
                ts_tensor = ts_tensor.squeeze(1)
                logits, _ = model(features_tensor, ts_tensor)
                end_time = time.time()
                probabilities = torch.sigmoid(logits).cpu().numpy()
            # 计算本次批量预测的处理时间和流数量
            processing_time = end_time - start_time
            batch_flow_count = len(packets)
            # 确保 probabilities 是一维数组
            if probabilities.ndim == 0:
                probabilities = np.array([probabilities])
            elif probabilities.ndim > 1:
                probabilities = probabilities.flatten()  # 如果是多维数组，展平为一维

            for prob, (five_tuple, cpu_header) in zip(probabilities, packets_to_process):
                pred_label = 'Attack' if prob > 0.5 else 'Benign'
                true_label = 'Attack' if (str(cpu_header.src_ip) in {'172.16.0.5'} and 
                                         str(cpu_header.dst_ip) in {'192.168.50.1', '192.168.50.4'}) else 'Benign'
                #true_label = 'Attack' if (str(cpu_header.src_ip) in {'172.16.0.1'} and 
                                         #str(cpu_header.dst_ip) in {'192.168.10.50'}) else 'Benign'
                with lock:
                    if pred_label == true_label:
                        if true_label == 'Attack':
                            tp += 1
                        else:
                            tn += 1
                    else:
                        if true_label == 'Attack':
                            fn += 1
                        else:
                            fp += 1
                    prob_value = int((1 - prob) * 100)
                    insertion_queue.put((five_tuple, prob_value))
                    prediction_count += 1
                    processed_count += 1
                    total_processing_time += processing_time
                    total_flow_count += batch_flow_count
                logging.debug(f"预测完成，insertion_queue 大小: {insertion_queue.qsize()}")
        except Exception as e:
            logging.error(f"预测线程在处理数据包时发生错误: {e}")
            continue

# 表项下发线程（批量下发）
def insertion_thread():
    global insertion_count
    logging.info("启动表项下发线程")
    while True:
        batch = []
        try:
            # 阻塞等待第一个表项
            item = insertion_queue.get(block=True, timeout=0.1)
            if item[0] not in inserted_tuples:
                batch.append(item)
            # 非阻塞获取更多表项组成批量
            for _ in range(BATCH_SIZE - 1):
                try:
                    item = insertion_queue.get_nowait()
                    if item[0] not in inserted_tuples:
                        batch.append(item)
                except queue.Empty:
                    break
        except queue.Empty:
            if not batch:  # 如果没有累积到任何数据，则等待
                logging.debug("下发队列为空，等待新数据")
                continue
            # 如果有数据，则处理已有批次

        if batch:
            for five_tuple, prob_value in batch:
                src_ip, dst_ip, protocol, src_port, dst_port = five_tuple
                try:
                    if protocol == 17:  # UDP
                        te = sh.TableEntry('my_table_udp')(action='set_entry_value')
                        te.match['ipv4.srcAddr'] = src_ip
                        te.match['ipv4.dstAddr'] = dst_ip
                        te.match['ipv4.protocol'] = str(protocol)
                        te.match['udp.srcPort'] = str(src_port)
                        te.match['udp.dstPort'] = str(dst_port)
                        te.action['value'] = str(prob_value)
                        te.insert()
                    elif protocol == 6:  # TCP
                        te = sh.TableEntry('my_table')(action='set_entry_value')
                        te.match['ipv4.srcAddr'] = src_ip
                        te.match['ipv4.dstAddr'] = dst_ip
                        te.match['ipv4.protocol'] = str(protocol)
                        te.match['tcp.srcPort'] = str(src_port)
                        te.match['tcp.dstPort'] = str(dst_port)
                        te.action['value'] = str(prob_value)
                        te.insert()
                    with lock:
                        insertion_count += 1
                        inserted_tuples.add(five_tuple)
                    logging.debug(f"表项下发成功: {five_tuple}")
                except Exception as e:
                    logging.error(f"表项下发错误: {e}")
                    continue

# 监控线程
def monitor_thread():
    logging.info("启动监控线程")
    while True:
        time.sleep(10)
        with lock:
            table_names = ["MyIngress.my_table", "MyIngress.my_table_udp"]
            for table_name in table_names:
                count = get_table_entry_count(table_name)
                if count is not None:
                    logging.info(f"表 {table_name} 当前表项数量: {count}")
                else:
                    logging.error(f"获取表 {table_name} 表项数量失败")

            if processed_count > 0:
                accuracy = (tp + tn) / processed_count
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                avg_delay = total_processing_time / total_flow_count
                avg_delay_ns = avg_delay * 1e9
                logging.info(f"捕获: {capture_count}, 预测: {prediction_count}, 下发: {insertion_count}, "
                             f"准确率: {accuracy:.4f}, F1分数: {f1:.4f}, 混淆矩阵: TP={tp}, TN={tn}, FP={fp}, FN={fn}, "
                             f"丢弃: {dropped_count}, 重复项: {duplicate_count}, "
                             f"捕获队列大小: {capture_queue.qsize()}, 下发队列大小: {insertion_queue.qsize()},"
                             f"当前预测流总数的平均延迟: {avg_delay_ns:.4f} 纳秒")
            else:
                logging.info(f"捕获: {capture_count}, 预测: {prediction_count}, 下发: {insertion_count}, "
                             f"准确率: N/A, F1分数: N/A, 混淆矩阵: N/A, 丢弃: {dropped_count}, 重复项: {duplicate_count}, "
                             f"捕获队列大小: {capture_queue.qsize()}, 下发队列大小: {insertion_queue.qsize()}")

# 主函数
if __name__ == "__main__":
    sh.setup(device_id=0, grpc_addr='localhost:9559', election_id=(0, 1), 
             config=sh.FwdPipeConfig('test.p4.p4info.txt', 'test.json'))
    logging.info("已连接到 P4Runtime gRPC 服务器！")

    cse = sh.CloneSessionEntry(100)
    cse.add(255, 100)
    cse.insert()
    logging.info("克隆会话 100 已配置。")

    capture_device = "veth6"
    logging.info(f"在 {capture_device} 上启动数据包嗅探...")

    # 启动线程
    threading.Thread(target=capture_thread, args=(capture_device,), daemon=True).start()
    threading.Thread(target=prediction_thread, daemon=True).start()
    threading.Thread(target=insertion_thread, daemon=True).start()
    threading.Thread(target=monitor_thread, daemon=True).start()

    # 主线程保持运行
    while True:
        time.sleep(1)
