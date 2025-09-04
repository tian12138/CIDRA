#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep
import subprocess
import numpy as np
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


# 全局变量
last_byte_count = 0

MAX_BANDWIDTH = 40 * 10**6  
MAXtableudp=100000
MAXtabletcp=100000
# 示例用法
gamma1 = 20
gamma2 = 80
alpha = 10
w = [0.5,0.5]        # 流表权重
cost = [0,0]     
capacity = [MAXtableudp,MAXtabletcp] # 流表最大容量




# 连接到交换机的函数
def connect_to_switch(thrift_port, thrift_ip):
    """
    连接到 Thrift 交换机。

    :param thrift_port: Thrift 端口
    :param thrift_ip: Thrift IP 地址
    :return: 交换机连接对象
    """
    sw = SimpleSwitchThriftAPI(thrift_port, thrift_ip)
    return sw

# 读取计数器的函数
def read_counter(sw, counter_name, index):
    """
    从交换机读取指定计数器的值。

    :param sw: 交换机连接对象
    :param counter_name: 计数器名称
    :param index: 计数器索引
    :return: 字节计数
    """
    counter_value = sw.counter_read(counter_name, index)
    return counter_value

def write_register(sw, register_name, index, value):
    """
    向交换机写入寄存器。

    :param sw: 交换机连接对象
    :param register_name: 寄存器名称
    :param index: 寄存器索引
    :param value: 要写入的值
    """
    sw.register_write(register_name, index, value)
    print(index)
    print(value)
    print(sw.register_read(register_name, index))
    
def calculate_c_min(gamma1, gamma2, alpha, w, cost, capacity, link_utilization):
    """
    计算最小置信度 C_min。
    
    参数：
    gamma1 (float): 流表存储资源部分的权重
    gamma2 (float): 链路利用率部分的权重
    alpha (float): sigmoid 函数的敏感度参数
    w (list): 每张流表的权重列表
    cost (list): 每张流表已用存储资源的累计开销列表
    capacity (list): 每张流表的最大容量列表

    
    返回：
    c_min (float): 最小置信度值，范围 0-100
    """
    n = len(w)
    # 计算流表存储资源利用率的加权和
    sum_weighted_utilization = sum(w[i] * (cost[i] / capacity[i]) for i in range(n))
    # 计算链路利用率
    # 计算 sigmoid 项
    sigmoid_term = 1 / (1 + np.exp(-alpha * link_utilization))
    # 计算 C_min
    c_min = gamma1 * sum_weighted_utilization + gamma2 * sigmoid_term
    return c_min
    
# 计算并更新链路利用率的函数
def calculate_and_update_utilization(sw):
    """
    定期读取计数器，计算链路利用率，并写入寄存器。

    :param sw: 交换机连接对象
    """
    global last_byte_count
    counter_name = "MyIngress.bytes_counter"  # 的计数器名称，需与 P4 程序一致
    register_name = "link_utilization"  # 的寄存器名称，需与 P4 程序一致
    index = 0  # 监控第一个链路

    while True:
        sleep(1)  # 每 1 秒更新一次
        current_byte_count = read_counter(sw, counter_name, index)[0]
        byte_increment = current_byte_count - last_byte_count
        if byte_increment < 0:  # 处理计数器重置的情况
            byte_increment = current_byte_count
        last_byte_count = current_byte_count

        # 计算数据速率（bps）和利用率
        data_rate = (byte_increment * 8) / 1.0  # 转换为位每秒
        utilization = data_rate / MAX_BANDWIDTH
        utilization_percent = int(utilization * 100)  # 转换为百分比整数
        utilization_percent = int(50)  # 转换为百分比整数
        
        counttcp = get_table_entry_count("MyIngress.my_table")
        countudp = get_table_entry_count("MyIngress.my_table_udp")
        cost = [counttcp,countudp] 
        c_min = calculate_c_min(gamma1, gamma2, alpha, w, cost, capacity, utilization)
        print(f"C_min: {c_min}")
        utilization_percent = int(c_min)  # 转换为百分比整数
        # 打印结果
        print(f"Current byte count: {current_byte_count}")
        print(f"Byte increment: {byte_increment}")
        print(f"Link utilization: {utilization:.2%}")

        # 写入寄存器
        write_register(sw, register_name, index, utilization_percent)

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
# 主函数
def main(thrift_port, thrift_ip):
    """
    主函数，执行连接、计算和更新操作。

    :param thrift_port: Thrift 端口
    :param thrift_ip: Thrift IP 地址
    """
    # 连接交换机
    sw = connect_to_switch(thrift_port, thrift_ip)
    

    try:
        # 开始计算并更新利用率
        calculate_and_update_utilization(sw)
    except KeyboardInterrupt:
        print("Shutting down.")

# 命令行参数解析
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Thrift Controller')
    parser.add_argument('--thrift-port', help='Thrift server port',
                        type=int, action="store", required=False,
                        default=9090)
    parser.add_argument('--thrift-ip', help='Thrift server IP',
                        type=str, action="store", required=False,
                        default='localhost')
    args = parser.parse_args()

    # 执行主函数
    main(args.thrift_port, args.thrift_ip)
