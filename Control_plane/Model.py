import os
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import numpy as np
from torch.cuda.amp import GradScaler, autocast  # 混合精度训练

# 常量定义
FEATURE_DIM = 14  # 每个数据包的特征维度
NUM_PACKETS = 2   # 每流的数据包数量
TIME_DIM = 2      # 有效时间戳特征维度
HIDDEN_DIM = 128  # 隐藏层维度
BATCH_SIZE = 64   # 批次大小
TIME_FEATURES = 2 
WINDOW_SIZE = 2          # 滑动窗口大小
SAMPLE_INTERVAL = 1  # 抽样间隔

def extract_packet_features(pkt):
    """提取单个数据包的特征（保持与原始代码一致）"""
    features = []
    
    # IP层特征
    if IP in pkt:
        ip = pkt[IP]
        ip_header_len = ip.ihl * 4
        features += [
            ip.len, ip.ttl, ip.proto, ip.tos, 
            len(ip.payload), ip.ihl, ip.flags.value,
            ip.id, ip.frag, ip.chksum
        ]
    else:
        features += [0]*10

    # 传输层特征
    if TCP in pkt:
        tcp = pkt[TCP]
        tcp_header_len = tcp.dataofs * 4  # TCP 首部长度（单位：字节）
        ip_payload = ip.len - ip_header_len - tcp_header_len  # IP 负载长度 - IP 首部长度 - TCP 首部长度
        features[4]=ip_payload
        features += [
            tcp.flags.value, tcp.window, 
            len(tcp.options), tcp.dataofs
        ]
    elif UDP in pkt:
        udp = pkt[UDP]
        udp_header_len = 8  # UDP 首部固定为 8 字节
        ip_payload = udp.len - udp_header_len  # UDP 负载长度 = UDP 总长度 - UDP 首部长度
        features[4]=ip_payload
        features += [
            udp.len, udp.chksum, 0, 0
        ]
    else:
        features += [0]*4

    # 时间特征
    if hasattr(pkt, 'time'):
        features.append(int(pkt.time*1000000))
    else:
        features.append(0)

    return features[:FEATURE_DIM]

class FlowCollector:
    def __init__(self):
        self.attacker_ips = {'172.16.0.5'}
        self.victim_ips = {'192.168.50.1', '192.168.50.4'}
        
        self.flows = defaultdict(lambda: {
            'packet_features': [],
            'timestamps': [],
            'label': 'Benign',  # 默认标签
            'pcap_file': None,
            'src_ip': None,
            'dst_ip': None
        })

    def process_pcap(self, file_path):
        """处理单个pcap文件"""
        packets = rdpcap(file_path)[::SAMPLE_INTERVAL]
        
        for pkt in packets:
            if IP not in pkt:
                continue
                
            ip = pkt[IP]
            proto = ip.proto
            sport, dport = 0, 0
            
            # 提取五元组
            if proto == 6 and TCP in pkt:
                transport = pkt[TCP]
                sport = transport.sport
                dport = transport.dport
            elif proto == 17 and UDP in pkt:
                transport = pkt[UDP]
                sport = transport.sport
                dport = transport.dport
            
            flow_key = (ip.src, ip.dst, sport, dport, proto)
            
            # 获取或创建流记录
            flow = self.flows[flow_key]
            
            # 只在第一次收到包时设置源/目的IP
            if not flow['src_ip']:
                flow.update({
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'pcap_file': os.path.basename(file_path)
                })
                
                # 设置攻击标签规则
                if (flow['src_ip'] in self.attacker_ips and 
                    flow['dst_ip'] in self.victim_ips):
                    flow['label'] = 'Attack'

            # 添加包特征和时间戳
            flow['packet_features'].append(extract_packet_features(pkt))
            flow['timestamps'].append(int(pkt.time*1000000))

            
def save_flow_statistics(flows, output_file):
    """保存流统计信息"""
    stats = []
    for flow_key, flow_data in flows.items():
        stats.append({
            'src_ip': flow_key[0],
            'dst_ip': flow_key[1],
            'sport': flow_key[2],
            'dport': flow_key[3],
            'proto': flow_key[4],
            'packet_count': len(flow_data['packet_features']),
            'label': flow_data['label'],
            'pcap_file': flow_data['pcap_file']
        })
    
    df = pd.DataFrame(stats)
    df.to_csv(output_file, index=False)


class WindowGenerator:
    def __init__(self, window_size=2):
        self.window_size = window_size
        # 预计算特征列名
        self.base_feature_names = [f'pkt{i}_f{j}' 
                                  for i in range(window_size) 
                                  for j in range(FEATURE_DIM)]
        self.time_feature_names = [
            'time1',
            'time2'
        ]
        self.all_feature_names = self.base_feature_names + self.time_feature_names

    def _calc_time_features(self, timestamps):
        """计算时间间隔统计特征"""
        if len(timestamps) < 2:
            return [0]*TIME_FEATURES
        
        intervals = np.diff(timestamps)
        return [
            np.mean(intervals),    # 平均时间间隔
        ]

    def process_flow(self, flow_data):
        """处理单个数据流，生成窗口样本"""
        samples = []
        packet_features = flow_data['packet_features']
        timestamps = flow_data['timestamps']
        label = 1 if flow_data['label'] == 'Attack' else 0
        flow_key = flow_data['flow_key']
        
        # 滑动窗口处理
        for i in range(len(packet_features) - self.window_size + 1):
            # 获取窗口数据
            window_features = packet_features[i:i+self.window_size]
            window_times = timestamps[i:i+self.window_size]
            
            # 转换为二维数组检查
            if len(window_features) != self.window_size:
                continue
                
            # 展平特征
            flattened_features = np.array(window_features).flatten().tolist()
            
            # 计算时间特征
            #time_stats = self._calc_time_features(window_times)
            time_stats = window_times
            
            # 组合特征
            full_features = flattened_features + time_stats
            
            # 构建样本记录
            sample = {
                'flow_key': str(flow_key),
                'window_start': i,
                'label': label,
                'pcap_file': flow_data['pcap_file'],
                **dict(zip(self.all_feature_names, full_features))
            }
            samples.append(sample)
        return samples

def generate_samples(input_file='/home/tianxiao/zongti/raw_flows1.pkl', output_file='/home/tianxiao/zongti/window_samples.csv'):
    # 加载原始流数据
    with open(input_file, 'rb') as f:
        raw_flows = pickle.load(f)
    
    # 初始化窗口生成器
    wg = WindowGenerator(WINDOW_SIZE)
    
    # 处理所有流
    all_samples = []
    flow_stats = defaultdict(int)
    
    for flow_key, flow_data in tqdm(raw_flows.items(), desc="Processing flows"):
        # 添加流标识到数据中
        flow_data['flow_key'] = flow_key
        
        # 生成窗口样本
        samples = wg.process_flow(flow_data)
        
        # 统计信息
        flow_stats['total_flows'] += 1
        flow_stats['total_samples'] += len(samples)
        if flow_data['label'] == 'Attack':
            flow_stats['attack_samples'] += len(samples)
        else:
            flow_stats['benign_samples'] += len(samples)
        
        all_samples.extend(samples)
    
    # 转换为DataFrame
    df = pd.DataFrame(all_samples)
    
    # 保存结果
    df.to_csv(output_file, index=False)
    
    # 打印统计信息
    print("\n数据生成统计:")
    print(f"总数据流数量: {flow_stats['total_flows']}")
    print(f"总窗口样本数: {flow_stats['total_samples']}")
    print(f"恶意样本数量: {flow_stats['attack_samples']}")
    print(f"良性样本数量: {flow_stats['benign_samples']}")
    print(f"样本文件已保存至: {output_file}")

    return df

def load_and_preprocess(data_path):
    """加载数据并进行预处理"""
    df = pd.read_csv(data_path)
    
    # 清除无效数据
    df = df.dropna()
    df = df[(df != np.inf).all(1)]
    
    # 分离特征和标签
    y = df['label']
    X = df.drop(['flow_key', 'window_start', 'label', 'pcap_file'], axis=1)
    
    # 数据类型转换
    X = X.astype(np.float32)
    y = y.astype(np.int8)
    
    return X, y, df

def split_stratified_by_flow(df, test_size=0.3):
    """按流进行分层划分"""
    # 获取唯一的流及其标签
    flow_labels = df.groupby('flow_key')['label'].first().reset_index()
    
    # 分层划分
    train_flows, test_flows = train_test_split(
        flow_labels,
        test_size=test_size,
        stratify=flow_labels['label'],
        random_state=RANDOM_STATE
    )
    
    # 获取对应的数据样本
    train_mask = df['flow_key'].isin(train_flows['flow_key'])
    test_mask = df['flow_key'].isin(test_flows['flow_key'])
    
    return df[train_mask], df[test_mask]

def data_pipeline(data_path):
    """完整数据处理流程"""
    # 1. 加载数据
    X, y, df = load_and_preprocess(data_path)


    # 检查特征唯一性
    for col in X.columns:
        unique_ratio = len(X[col].unique()) / len(X)
        if unique_ratio < 0.01:
            print(f"警告：特征 {col} 的唯一值比例过低（{unique_ratio:.2%}），可能为常量或标识字段！")
    
    # 2. 按流分层划分
    train_df, test_df = split_stratified_by_flow(df, TEST_SIZE)
    
    # 3. 分离训练集特征和标签
    X_train = train_df.drop(['flow_key', 'window_start', 'label', 'pcap_file'], axis=1)
    y_train = train_df['label']
    X_test = test_df.drop(['flow_key', 'window_start', 'label', 'pcap_file'], axis=1)
    y_test = test_df['label']

    # 4. 特征标准化
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    joblib.dump(scaler, SCALER_PATH)
    
    # 5. 平衡处理（根据实际分布选择策略）
    print("\n类别分布:")
    print(f"训练集 - 恶意样本: {sum(y_train)} ({sum(y_train)/len(y_train):.2%})")
    print(f"测试集 - 恶意样本: {sum(y_test)} ({sum(y_test)/len(y_test):.2%})")
    
    
    return X_train, y_train, X_test, y_test

def save_datasets(X_train, y_train, X_test, y_test):
    """保存处理后的数据集"""
    np.savez_compressed(
        '/home/tianxiao/zongti/processed_data.npz',
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test
    )
    print("\n数据集已保存为 processed_data.npz")


# 数据集类
class PacketDataset(Dataset):
    """封装训练和测试数据的 Dataset 类"""
    def __init__(self, X, y):
        self.X = X  # 特征 (num_samples, 16 * 2 + 1)
        self.y = y  # 标签 (num_samples,)
        print("X shape:", self.X.shape)  # 打印 X 的形状

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        # 提取特征和时间戳
        sample = self.X[idx]
        features = sample[:FEATURE_DIM * NUM_PACKETS].reshape(NUM_PACKETS, FEATURE_DIM)  # (num_packets, feature_dim)
        timestamps = sample[FEATURE_DIM * NUM_PACKETS:FEATURE_DIM * NUM_PACKETS + TIME_DIM]  # (time_dim,)
        label = self.y[idx]
        return {
            'features': torch.FloatTensor(features),  # (num_packets, feature_dim)
            'timestamps': torch.DoubleTensor(timestamps),  # (time_dim,)
            'label': torch.FloatTensor([label])  # (1,)
        }

# Transformer + LSTM 模型
class TemporalModel(nn.Module):
    """Transformer + LSTM 混合模型"""
    def __init__(self, input_dim, hidden_dim=128):
        super().__init__()
        # self.positional_embed = nn.Linear(TIME_DIM, hidden_dim)  # 时间戳嵌入
        # 使用双精度线性层处理时间戳
        self.positional_embed = nn.Linear(TIME_DIM, hidden_dim, dtype=torch.float64)
        # Transformer 编码器
        self.transformer = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(
                d_model=hidden_dim,
                nhead=8,
                dim_feedforward=512,
                batch_first=True  # 启用 batch_first 以支持 nested tensor
            ),
            num_layers=3
        )

        # LSTM 时序建模
        self.lstm = nn.LSTM(
            input_size=input_dim + hidden_dim,  # 特征 + Transformer 输出
            hidden_size=hidden_dim,
            bidirectional=True
        )

        # 分类器（输出 logits，不包含 Sigmoid）
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),
            nn.ReLU(),
            nn.Linear(64, 1)  # 输出 logits
        )

    def forward(self, x, timestamps, state=None):
        """
        x: (seq_len, batch, features)
        timestamps: (batch, time_dim)
        state: (h, c) LSTM 初始状态
        """
        # 时间位置编码
        #timestamps = timestamps.double()
        # 把输入统一成和模型权重相同的 dtype
        target_dtype = next(self.parameters()).dtype
        x = x.to(target_dtype)
        timestamps = timestamps.to(target_dtype)
        
        time_embed = self.positional_embed(timestamps).unsqueeze(0)  # (1, batch, hidden_dim)
        # 将嵌入结果转换为与特征相同的精度
        #time_embed = time_embed.to(x.dtype)  # 保持与特征相同的精度

        # Transformer 编码
        transformer_out = self.transformer(time_embed)  # (1, batch, hidden_dim)

        # 特征拼接
        combined = torch.cat([x, transformer_out.expand(x.size(0), -1, -1)], dim=-1)  # (seq_len, batch, input_dim + hidden_dim)

        # LSTM 处理
        lstm_out, new_state = self.lstm(combined, state)

        # 分类器输出（logits）
        logits = self.classifier(lstm_out[-1])  # 只使用最后一个时间步的输出


        
        return logits.squeeze(), new_state
    def forward1(self, x, timestamps, state=None):
        """
        x: (seq_len, batch, features)
        timestamps: (batch, time_dim)
        state: (h, c) LSTM 初始状态
        """
        # 时间位置编码
        timestamps = timestamps.double()
        time_embed = self.positional_embed(timestamps).unsqueeze(0)  # (1, batch, hidden_dim)
        # 将嵌入结果转换为与特征相同的精度
        time_embed = time_embed.to(x.dtype)  # 保持与特征相同的精度

        # Transformer 编码
        transformer_out = self.transformer(time_embed)  # (1, batch, hidden_dim)

        # 特征拼接
        combined = torch.cat([x, transformer_out.expand(x.size(0), -1, -1)], dim=-1)  # (seq_len, batch, input_dim + hidden_dim)

        # LSTM 处理
        lstm_out, new_state = self.lstm(combined, state)

        # 分类器输出（logits）
        logits = self.classifier(lstm_out[-1])  # 只使用最后一个时间步的输出
        return logits.squeeze(), new_state
# 自定义 collate 函数
def custom_collate(batch):
    """处理变长序列的自定义 collate 函数"""
    features = torch.stack([item['features'] for item in batch], dim=1)  # (seq_len, batch, feature_dim)
    timestamps = torch.stack([item['timestamps'] for item in batch], dim=0)  # (batch, time_dim)
    labels = torch.cat([item['label'] for item in batch])  # (batch,)
    return {
        'features': features,
        'timestamps': timestamps,
        'labels': labels
    }

# 训练函数
def train():
    # 设置设备
    device = torch.device("cuda:1" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    torch.cuda.empty_cache()  # 释放未使用的显存

    # 初始化模型和数据集
    model = TemporalModel(input_dim=FEATURE_DIM).to(device)
    train_dataset = PacketDataset(X_train, y_train)
    test_dataset = PacketDataset(X_test, y_test)

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,  # 批次大小
        shuffle=True,
        collate_fn=custom_collate
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
        collate_fn=custom_collate
    )

    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-5)  # 降低学习率
    loss_fn = nn.BCEWithLogitsLoss()  # 使用 BCEWithLogitsLoss
    scaler = GradScaler()  # 混合精度训练的梯度缩放器

    # 训练循环
    for epoch in range(50):
        model.train()
        total_loss = 0
        total_correct = 0
        total_samples = 0

        for batch in train_loader:
            optimizer.zero_grad()

            # 将数据移动到 GPU 并检查格式
            features = batch['features'].float().to(device)
            timestamps = batch['timestamps'].float().to(device)
            labels = batch['labels'].float().to(device)

            # 检查输入数据和标签
            if torch.isnan(features).any() or torch.isinf(features).any():
                print("Features contain NaN or inf!")
            if torch.isnan(timestamps).any() or torch.isinf(timestamps).any():
                print("Timestamps contain NaN or inf!")
            if torch.isnan(labels).any() or torch.isinf(labels).any():
                print("Labels contain NaN or inf!")

            # 混合精度训练
            with autocast():
                # 前向传播
                logits, _ = model(features, timestamps)

                # 计算损失
                loss = loss_fn(logits, labels)

            # 反向传播和梯度裁剪
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            scaler.step(optimizer)
            scaler.update()

            # 计算准确率
            pred_labels = (torch.sigmoid(logits) > 0.5).float()
            total_correct += (pred_labels == labels).sum().item()
            total_samples += labels.size(0)
            total_loss += loss.item()

        # 打印训练结果
        accuracy = total_correct / total_samples
        avg_loss = total_loss / len(train_loader)
        print(f"Epoch {epoch + 1}, Loss: {avg_loss:.4f}, Accuracy: {accuracy:.4f}")

    # 保存模型
    torch.save(model, "/home/tianxiao/zongti/transformer_lstm32-14.pth")
# 测试函数
def evaluate(model_path):
    # 设置设备
    device = torch.device("cuda:1" if torch.cuda.is_available() else "cpu")
    print(f"Evaluating using device: {device}")

    # 加载模型
    model = torch.load(model_path, map_location=device)
    model.eval()

    # 加载测试数据集
    test_dataset = PacketDataset(X_test, y_test)
    test_loader = DataLoader(
        test_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
        collate_fn=custom_collate
    )

    loss_fn = nn.BCEWithLogitsLoss()
    total_loss = 0
    total_correct = 0
    total_samples = 0

    with torch.no_grad():
        for batch in test_loader:
            # 数据转移至设备
            features = batch['features'].float().to(device)
            timestamps = batch['timestamps'].float().to(device)
            labels = batch['labels'].float().to(device)

            # 前向传播
            logits, _ = model(features, timestamps)
            
            # 计算损失
            loss = loss_fn(logits, labels)
            total_loss += loss.item() * labels.size(0)
            
            # 计算准确率
            preds = (torch.sigmoid(logits) > 0.5).float()
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
            

    # 计算最终指标
    avg_loss = total_loss / total_samples
    accuracy = total_correct / total_samples
    print(f"\nTest Results:")
    print(f"Loss: {avg_loss:.4f}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Correct/Total: {total_correct}/{total_samples}")

# 修改主程序
if __name__ == "__main__":
    # 加载数据

    pcap_dir = "/home/tianxiao/zongti/1"
    output_csv = "/home/tianxiao/zongti/flow_statistics.csv"
    
    # 初始化收集器
    collector = FlowCollector()
    
    # 遍历处理所有pcap文件
    for filename in os.listdir(pcap_dir):
        if filename.endswith('.pcap'):
            file_path = os.path.join(pcap_dir, filename)
            collector.process_pcap(file_path)
            print(f"已处理文件: {filename}")
    
    # 保存流统计信息
    save_flow_statistics(collector.flows, output_csv)
    print(f"数据流统计信息已保存至 {output_csv}")
    print(f"共发现 {len(collector.flows)} 个独立数据流")

    # 保存原始流数据（供后续步骤使用）
    import pickle
    with open('/home/tianxiao/zongti/raw_flows1.pkl', 'wb') as f:
        pickle.dump(dict(collector.flows), f)
    print("原始流数据已保存至 raw_flows.pkl")





    df_samples = generate_samples()
    
    # 示例查看数据
    print("\n生成数据的样例：")
    print(df_samples.iloc[0])
    
    # 特征维度验证
    expected_dim = WINDOW_SIZE * FEATURE_DIM + TIME_FEATURES
    actual_dim = len(df_samples.columns) - 4  # 减去元数据列
    print(f"\n特征维度验证: 预期 {expected_dim} 维，实际 {actual_dim} 维")
    
    # 样本平衡性检查
    imbalance_ratio = df_samples['label'].value_counts(normalize=True)
    print("\n类别分布:")
    print(imbalance_ratio)






    TEST_SIZE = 0.3
    RANDOM_STATE = 42
    SCALER_PATH = "/home/tianxiao/zongti/scaler1.pkl"
        # 执行处理流程
    X_train, y_train, X_test, y_test = data_pipeline('/home/tianxiao/zongti/window_samples.csv')
    
    # 保存处理后的数据
    save_datasets(X_train, y_train, X_test, y_test)
    
    # 验证数据形状
    print("\n数据形状验证:")
    print(f"训练集特征: {X_train.shape}")
    print(f"训练集标签: {y_train.shape}")
    print(f"测试集特征: {X_test.shape}")
    print(f"测试集标签: {y_test.shape}")

    data = np.load('/home/tianxiao/zongti/processed_data.npz')


    X_train, y_train = data['X_train'], data['y_train']
    X_test, y_test = data['X_test'], data['y_test']

# 合并特征
    X_train = np.concatenate((X_train, X_test), axis=0, dtype=np.float64)

# 合并标签
    y_train = np.concatenate((y_train, y_test), axis=0, dtype=np.float64)

    train()  # 训练并保存模型
    evaluate("/home/tianxiao/zongti/transformer_lstm32-14.pth")  # 加载模型并测试

