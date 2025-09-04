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
from torch.cuda.amp import GradScaler, autocast
import pickle
from sklearn.metrics import precision_score, recall_score, f1_score,confusion_matrix

# 定义保存文件夹名称
SAVE_DIR = "/home/tianxiao/zongti/saved_files_train"

# 创建保存文件夹（如果不存在）
if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

# 常量定义
FEATURE_DIM = 14
NUM_PACKETS = 2
TIME_DIM = 2
HIDDEN_DIM = 128
BATCH_SIZE = 64
TIME_FEATURES = 2
WINDOW_SIZE = 2
SAMPLE_INTERVAL = 1
TEST_SIZE = 0.1
RANDOM_STATE = 42

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
        if tcp.dataofs > 5:
            opt_len = (tcp.dataofs - 5) * 4
        else:
            opt_len = 0
        features[4]=ip_payload
        features += [
            tcp.flags.value, tcp.window, 
            opt_len, tcp.dataofs
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
        features.append(int(pkt.time*0))
    else:
        features.append(0)

    return features[:FEATURE_DIM]

class FlowCollector:
    def __init__(self):

        # self.attacker_ips = {'172.16.0.1'}
        # self.victim_ips = {'192.168.10.50'}
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
            flow['timestamps'].append(int(pkt.time*0))

            
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

    correlation_matrix = df.corr()

    # 可视化相关性矩阵


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
    output_path = os.path.join(SAVE_DIR, 'processed_data.npz')
    np.savez_compressed(
        output_path,
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test
    )
    print(f"\n数据集已保存为 {output_path}")


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
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    torch.cuda.empty_cache()

    model = TemporalModel(input_dim=FEATURE_DIM).to(device)
    train_dataset = PacketDataset(X_train, y_train)
    test_dataset = PacketDataset(X_test, y_test)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, collate_fn=custom_collate)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate)

    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-5)
    loss_fn = nn.BCEWithLogitsLoss()
    scaler = GradScaler()

    for epoch in range(50):
        model.train()
        total_loss = 0
        total_correct = 0
        total_samples = 0

        for batch in train_loader:
            optimizer.zero_grad()
            features = batch['features'].float().to(device)
            timestamps = batch['timestamps'].float().to(device)
            labels = batch['labels'].float().to(device)

            with autocast():
                logits, _ = model(features, timestamps)
                loss = loss_fn(logits, labels)

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            scaler.step(optimizer)
            scaler.update()

            pred_labels = (torch.sigmoid(logits) > 0.5).float()
            total_correct += (pred_labels == labels).sum().item()
            total_samples += labels.size(0)
            total_loss += loss.item()

        accuracy = total_correct / total_samples
        avg_loss = total_loss / len(train_loader)
        print(f"Epoch {epoch + 1}, Loss: {avg_loss:.4f}, Accuracy: {accuracy:.4f}")

    model_path = os.path.join(SAVE_DIR, "transformer_lstm32-14-time-3.pth")
    torch.save(model, model_path)
    print(f"模型已保存至 {model_path}")

def evaluate1(model_path):
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    print(f"Evaluating using device: {device}")

    model = torch.load(model_path, map_location=device)
    model.eval()

    test_dataset = PacketDataset(X_test, y_test)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate)

    loss_fn = nn.BCEWithLogitsLoss()
    total_loss = 0
    total_correct = 0
    total_samples = 0

    with torch.no_grad():
        for batch in test_loader:
            features = batch['features'].float().to(device)
            timestamps = batch['timestamps'].float().to(device)
            labels = batch['labels'].float().to(device)

            logits, _ = model(features, timestamps)
            loss = loss_fn(logits, labels)
            total_loss += loss.item() * labels.size(0)

            preds = (torch.sigmoid(logits) > 0.5).float()
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)

    avg_loss = total_loss / total_samples
    accuracy = total_correct / total_samples
    print(f"\nTest Results:")
    print(f"Loss: {avg_loss:.4f}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Correct/Total: {total_correct}/{total_samples}")

def evaluate2(model_path):
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
    all_preds = []
    all_labels = []

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
            
            # 计算预测
            preds = (torch.sigmoid(logits) > 0.5).float()
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
            
            # 收集预测和真实标签
            all_preds.append(preds.view(-1).cpu())
            all_labels.append(labels.view(-1).cpu())

    # 计算最终指标
    avg_loss = total_loss / total_samples
    accuracy = total_correct / total_samples
    
    # 将所有预测和标签合并为 numpy 数组
    all_preds = torch.cat(all_preds).numpy().astype(int)
    all_labels = torch.cat(all_labels).numpy().astype(int)
    
    # 计算附加指标
    cm = confusion_matrix(all_labels, all_preds)
    precision = precision_score(all_labels, all_preds)
    recall = recall_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds)

    # 打印结果
    print(f"\nTest Results:")
    print(f"Loss: {avg_loss:.4f}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Correct/Total: {total_correct}/{total_samples}")
    print("Confusion Matrix:")
    print(cm)
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, roc_curve, roc_auc_score
import matplotlib.pyplot as plt

def evaluate3(model_path):
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
    all_preds = []
    all_labels = []
    all_probs = []  # Store probabilities for AUC

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
            
            # 计算预测
            probs = torch.sigmoid(logits)  # Probabilities for AUC
            preds = (probs > 0.5).float()  # Binary predictions
            total_correct += (preds == labels).sum().item()
            total_samples += labels.size(0)
            
            # 收集预测、概率和真实标签
            all_preds.append(preds.view(-1).cpu())
            all_labels.append(labels.view(-1).cpu())
            all_probs.append(probs.view(-1).cpu())

    # 计算最终指标
    avg_loss = total_loss / total_samples
    accuracy = total_correct / total_samples
    
    # 将所有预测、标签和概率合并为 numpy 数组
    all_preds = torch.cat(all_preds).numpy().astype(int)
    all_labels = torch.cat(all_labels).numpy().astype(int)
    all_probs = torch.cat(all_probs).numpy()
    
    # 计算附加指标
    cm = confusion_matrix(all_labels, all_preds)
    precision = precision_score(all_labels, all_preds)
    recall = recall_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds)
    
    # 计算 AUC
    fpr, tpr, _ = roc_curve(all_labels, all_probs)
    auc = roc_auc_score(all_labels, all_probs)

    # 打印结果
    print(f"\nTest Results:")
    print(f"Loss: {avg_loss:.4f}")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Correct/Total: {total_correct}/{total_samples}")
    print("Confusion Matrix:")
    print(cm)
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print(f"AUC: {auc:.4f}")

    # 绘制 ROC 曲线
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, 'b-', label=f'ROC Curve (AUC = {auc:.4f})')  # Blue line
    plt.plot([0, 1], [0, 1], 'r--', label='Random Guessing')  # Diagonal line
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.grid(True)
    plt.legend()
    AUC_fig=os.path.join(SAVE_DIR, "roc_curve.tif")
    plt.savefig(AUC_fig)
    plt.close()

    print("ROC curve saved to 'roc_curve.png'")

def evaluate4(model_path, train_dataset, test_dataset, batch_size):
    # 设置设备
    device = torch.device("cuda:1" if torch.cuda.is_available() else "cpu")
    print(f"Evaluating using device: {device}")

    # 加载模型
    model = torch.load(model_path, map_location=device)
    model.eval()

    # 数据加载器
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=custom_collate
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=custom_collate
    )

    loss_fn = nn.BCEWithLogitsLoss()

    def evaluate_loader(loader, dataset_name):
        total_loss = 0
        total_correct = 0
        total_samples = 0
        all_preds = []
        all_labels = []
        all_probs = []

        with torch.no_grad():
            for batch in loader:
                features = batch['features'].float().to(device)
                timestamps = batch['timestamps'].float().to(device)
                labels = batch['labels'].float().to(device)

                logits, _ = model(features, timestamps)
                loss = loss_fn(logits, labels)
                total_loss += loss.item() * labels.size(0)

                probs = torch.sigmoid(logits)
                preds = (probs > 0.5).float()
                total_correct += (preds == labels).sum().item()
                total_samples += labels.size(0)

                all_preds.append(preds.view(-1).cpu())
                all_labels.append(labels.view(-1).cpu())
                all_probs.append(probs.view(-1).cpu())

        avg_loss = total_loss / total_samples
        accuracy = total_correct / total_samples
        all_preds = torch.cat(all_preds).numpy().astype(int)
        all_labels = torch.cat(all_labels).numpy().astype(int)
        all_probs = torch.cat(all_probs).numpy()

        cm = confusion_matrix(all_labels, all_preds)
        precision = precision_score(all_labels, all_preds, zero_division=0)
        recall = recall_score(all_labels, all_preds, zero_division=0)
        f1 = f1_score(all_labels, all_preds, zero_division=0)
        fpr, tpr, _ = roc_curve(all_labels, all_probs)
        auc = roc_auc_score(all_labels, all_probs)

        print(f"\n{dataset_name} Results:")
        print(f"Loss: {avg_loss:.4f}")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Correct/Total: {total_correct}/{total_samples}")
        print("Confusion Matrix:")
        print(cm)
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        print(f"AUC: {auc:.4f}")

        return fpr, tpr, auc, all_probs, all_labels

    # 评估训练集和测试集
    train_fpr, train_tpr, train_auc, train_probs, train_labels = evaluate_loader(train_loader, "Train")
    test_fpr, test_tpr, test_auc, test_probs, test_labels = evaluate_loader(test_loader, "Test")

    # 绘制 ROC 曲线
    plt.figure(figsize=(8, 6))
    plt.plot(train_fpr, train_tpr, 'b-', label=f'Train ROC (AUC = {train_auc:.4f})')
    plt.plot(test_fpr, test_tpr, 'g-', label=f'Test ROC (AUC = {test_auc:.4f})')
    plt.plot([0, 1], [0, 1], 'r--', label='Random Guessing')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve (Train vs Test)')
    plt.grid(True)
    plt.legend()
    plt.savefig(os.path.join(SAVE_DIR, 'roc_curve_train_test.png'))
    plt.close()

import time
def evaluate(model_path, test_dataset, batch_sizes=[64, 128, 256, 512, 1024, 2048, 4096, 8192]):
    # 设置设备
    device = torch.device("cuda:1" if torch.cuda.is_available() else "cpu")
    print(f"Evaluating using device: {device}")

    # 加载模型
    model = torch.load(model_path, map_location=device)
    model.eval()

    # 损失函数
    loss_fn = nn.BCEWithLogitsLoss()

    # 存储每个批次大小的延迟结果
    latency_results = []

    for batch_size in batch_sizes:
        print(f"\nEvaluating with batch size: {batch_size}")
        
        # 创建 DataLoader
        test_loader = DataLoader(
            test_dataset,
            batch_size=batch_size,
            shuffle=False,
            collate_fn=custom_collate
        )

        total_loss = 0
        total_correct = 0
        total_samples = 0
        all_preds = []
        all_labels = []
        total_latency_ns = 0  # 总预测延迟（纳秒）

        with torch.no_grad():
            for batch in test_loader:
                # 数据转移至设备
                features = batch['features'].float().to(device)
                timestamps = batch['timestamps'].float().to(device)
                labels = batch['labels'].float().to(device)

                # 测量前向传播时间
                start_time = time.perf_counter_ns()
                logits, _ = model(features, timestamps)
                end_time = time.perf_counter_ns()
                batch_latency_ns = end_time - start_time
                #per_sample_latency_ns = batch_latency_ns / labels.size(0)
                total_latency_ns += batch_latency_ns

                # 计算损失
                loss = loss_fn(logits, labels)
                total_loss += loss.item() * labels.size(0)

                # 计算预测
                preds = (torch.sigmoid(logits) > 0.5).float()
                total_correct += (preds == labels).sum().item()
                total_samples += labels.size(0)

                # 收集预测和真实标签
                all_preds.append(preds.view(-1).cpu())
                all_labels.append(labels.view(-1).cpu())

        # 计算最终指标
        avg_loss = total_loss / total_samples
        accuracy = total_correct / total_samples
        avg_latency_per_sample_ns = total_latency_ns / total_samples

        # 将所有预测和标签合并为 numpy 数组
        all_preds = torch.cat(all_preds).numpy().astype(int)
        all_labels = torch.cat(all_labels).numpy().astype(int)

        # 计算附加指标
        cm = confusion_matrix(all_labels, all_preds)
        precision = precision_score(all_labels, all_preds, zero_division=0)
        recall = recall_score(all_labels, all_preds, zero_division=0)
        f1 = f1_score(all_labels, all_preds, zero_division=0)

        # 存储延迟结果
        latency_results.append((batch_size, avg_latency_per_sample_ns))

        # 打印结果
        print(f"\nTest Results (Batch Size: {batch_size}):")
        print(f"Loss: {avg_loss:.4f}")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Correct/Total: {total_correct}/{total_samples}")
        print("Confusion Matrix:")
        print(cm)
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        print(f"Average Latency per Sample: {avg_latency_per_sample_ns:.2f} ns")

    # 打印所有批次大小的延迟结果
    print("\nSummary of Average Latency per Sample (ns):")
    for batch_size, latency in latency_results:
        print(f"Batch Size {batch_size}: {latency:.2f} ns")

    # 保存延迟结果到文件
    with open('latency_results.txt', 'w', encoding='utf-8') as f:
        f.write("Batch Size,Average Latency per Sample (ns)\n")
        for batch_size, latency in latency_results:
            f.write(f"{batch_size},{latency:.2f}\n")

    print("\nLatency results saved to 'latency_results.txt'")
if __name__ == "__main__":
    pcap_dir = "/home/tianxiao/zongti/1"
    output_csv = os.path.join(SAVE_DIR, "flow_statistics.csv")

    collector = FlowCollector()

    for filename in os.listdir(pcap_dir):
        if filename.endswith('.pcap'):
            file_path = os.path.join(pcap_dir, filename)
            collector.process_pcap(file_path)
            print(f"已处理文件: {filename}")

    save_flow_statistics(collector.flows, output_csv)
    print(f"数据流统计信息已保存至 {output_csv}")
    print(f"共发现 {len(collector.flows)} 个独立数据流")

    raw_flows_path = os.path.join(SAVE_DIR, 'raw_flows1.pkl')
    with open(raw_flows_path, 'wb') as f:
        pickle.dump(dict(collector.flows), f)
    print(f"原始流数据已保存至 {raw_flows_path}")

    window_samples_path = os.path.join(SAVE_DIR, 'window_samples.csv')
    df_samples = generate_samples(input_file=raw_flows_path, output_file=window_samples_path)

    print("\n生成数据的样例：")
    print(df_samples.iloc[0])

    expected_dim = WINDOW_SIZE * FEATURE_DIM + TIME_FEATURES
    actual_dim = len(df_samples.columns) - 4
    print(f"\n特征维度验证: 预期 {expected_dim} 维，实际 {actual_dim} 维")

    imbalance_ratio = df_samples['label'].value_counts(normalize=True)
    print("\n类别分布:")
    print(imbalance_ratio)

    SCALER_PATH = os.path.join(SAVE_DIR, "scaler1-time-3.pkl")
    X_train, y_train, X_test, y_test = data_pipeline(window_samples_path)

    save_datasets(X_train, y_train, X_test, y_test)

    print("\n数据形状验证:")
    print(f"训练集特征: {X_train.shape}")
    print(f"训练集标签: {y_train.shape}")
    print(f"测试集特征: {X_test.shape}")
    print(f"测试集标签: {y_test.shape}")

    processed_data_path = os.path.join(SAVE_DIR, 'processed_data.npz')
    data = np.load(processed_data_path)
    X_train, y_train = data['X_train'], data['y_train']
    X_test, y_test = data['X_test'], data['y_test']


    train()
    model_path = os.path.join(SAVE_DIR, "transformer_lstm32-14-time-3.pth")
    test_dataset = PacketDataset(X_test, y_test)
    train_dataset= PacketDataset(X_train, y_train)
    evaluate(model_path,test_dataset)

