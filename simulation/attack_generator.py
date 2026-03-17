"""
Attack Traffic Simulation Module
Generates realistic network traffic for various attack types to test IDS detection
"""

from __future__ import annotations

import random
import string
from datetime import datetime
from typing import Any

import pandas as pd
import numpy as np


class AttackSimulator:
    """Generate realistic attack traffic data for IDS testing"""
    
    # Feature columns required for model prediction  
    FEATURES = [
        'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets',
        'Total_Length_of_Fwd_Packets', 'Total_Length_of_Bwd_Packets',
        'Fwd_Packet_Length_Max', 'Fwd_Packet_Length_Min', 'Fwd_Packet_Length_Mean',
        'Bwd_Packet_Length_Max', 'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
        'Flow_Bytes_Per_Sec', 'Flow_Packets_Per_Sec', 'Flow_IAT_Mean', 'Flow_IAT_Std',
        'Flow_IAT_Max', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean',
        'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Total',
        'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min',
        'Fwd_PSH_Flags', 'Bwd_PSH_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags',
        'Fwd_RST_Flags', 'Bwd_RST_Flags', 'Fwd_SYN_Flags', 'Bwd_SYN_Flags',
        'Fwd_FIN_Flags', 'Bwd_FIN_Flags', 'Fwd_CWE_Flags', 'Bwd_CWE_Flags',
        'Fwd_Ack_Flags', 'Bwd_Ack_Flags', 'Fwd_ECE_Flags', 'Bwd_ECE_Flags',
        'Inbound_Init_Window_size', 'Outbound_Init_Window_size', 'Packet_Length_Std',
        'Packet_Length_Variance', 'FIN_Flag_Count', 'SYN_Flag_Count',
        'RST_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count', 'URG_Flag_Count',
        'CWE_Flag_Count', 'ECE_Flag_Count', 'Down_Up_Ratio', 'Average_Packet_Size',
        'Subflow_Fwd_Packets', 'Subflow_Fwd_Bytes', 'Subflow_Bwd_Packets',
        'Subflow_Bwd_Bytes', 'Init_Win_bytes_Forward', 'Init_Win_bytes_Backward',
        'act_data_pkt_fwd', 'min_seg_size_forward', 'Active_Mean', 'Active_Std',
        'Active_Max', 'Active_Min', 'Idle_Mean', 'Idle_Std', 'Idle_Max',
        'Idle_Min', 'Protocol'
    ]
    
    @staticmethod
    def generate_ddos_attack(count: int = 100, intensity: float = 0.8) -> pd.DataFrame:
        """
        Generate DDoS attack traffic
        Characteristics: High packet rate, many small packets, short durations
        """
        data = []
        for i in range(count):
            num_packets = int(1000 * intensity + random.randint(100, 500))
            packet_size = random.randint(40, 100)  # Small packets typical of DDoS
            
            record = {
                'Flow_Duration': random.randint(1000, 5000),
                'Total_Fwd_Packets': num_packets,
                'Total_Backward_Packets': random.randint(0, num_packets // 10),
                'Total_Length_of_Fwd_Packets': num_packets * packet_size,
                'Total_Length_of_Bwd_Packets': random.randint(0, 1000),
                'Fwd_Packet_Length_Max': packet_size,
                'Fwd_Packet_Length_Min': packet_size - 10,
                'Fwd_Packet_Length_Mean': packet_size - 5,
                'Bwd_Packet_Length_Max': random.randint(100, 1500),
                'Bwd_Packet_Length_Min': 40,
                'Bwd_Packet_Length_Mean': random.randint(50, 200),
                'Flow_Bytes_Per_Sec': num_packets * packet_size / (random.randint(1, 5)),
                'Flow_Packets_Per_Sec': num_packets / (random.randint(1, 5)),
                'Flow_IAT_Mean': random.randint(100, 500),
                'Flow_IAT_Std': random.randint(500, 2000),
                'Flow_IAT_Max': random.randint(2000, 5000),
                'Flow_IAT_Min': random.randint(1, 100),
                'Fwd_IAT_Total': random.randint(5000, 10000),
                'Fwd_IAT_Mean': random.randint(50, 200),
                'Fwd_IAT_Std': random.randint(100, 500),
                'Fwd_IAT_Max': random.randint(1000, 3000),
                'Fwd_IAT_Min': random.randint(1, 50),
                'Bwd_IAT_Total': random.randint(0, 5000),
                'Bwd_IAT_Mean': random.randint(10, 200),
                'Bwd_IAT_Std': random.randint(50, 500),
                'Bwd_IAT_Max': random.randint(500, 2000),
                'Bwd_IAT_Min': random.randint(0, 50),
                'Fwd_PSH_Flags': int(num_packets * 0.1),
                'Bwd_PSH_Flags': random.randint(0, 10),
                'Fwd_URG_Flags': 0,
                'Bwd_URG_Flags': 0,
                'Fwd_RST_Flags': int(num_packets * 0.05),
                'Bwd_RST_Flags': random.randint(0, 5),
                'Fwd_SYN_Flags': int(num_packets * 0.2),
                'Bwd_SYN_Flags': random.randint(0, 20),
                'Fwd_FIN_Flags': int(num_packets * 0.05),
                'Bwd_FIN_Flags': random.randint(0, 5),
                'Fwd_CWE_Flags': 0,
                'Bwd_CWE_Flags': 0,
                'Fwd_Ack_Flags': int(num_packets * 0.3),
                'Bwd_Ack_Flags': random.randint(0, 20),
                'Fwd_ECE_Flags': 0,
                'Bwd_ECE_Flags': 0,
                'Inbound_Init_Window_size': random.randint(1024, 65535),
                'Outbound_Init_Window_size': random.randint(1024, 65535),
                'Packet_Length_Std': random.randint(10, 100),
                'Packet_Length_Variance': random.randint(100, 500),
                'FIN_Flag_Count': int(num_packets * 0.05),
                'SYN_Flag_Count': int(num_packets * 0.2),
                'RST_Flag_Count': int(num_packets * 0.05),
                'PSH_Flag_Count': int(num_packets * 0.1),
                'ACK_Flag_Count': int(num_packets * 0.3),
                'URG_Flag_Count': 0,
                'CWE_Flag_Count': 0,
                'ECE_Flag_Count': 0,
                'Down_Up_Ratio': random.uniform(0.01, 0.1),
                'Average_Packet_Size': packet_size,
                'Subflow_Fwd_Packets': num_packets // 4,
                'Subflow_Fwd_Bytes': (num_packets // 4) * packet_size,
                'Subflow_Bwd_Packets': random.randint(0, num_packets // 20),
                'Subflow_Bwd_Bytes': random.randint(0, 1000),
                'Init_Win_bytes_Forward': random.randint(1024, 65535),
                'Init_Win_bytes_Backward': random.randint(1024, 65535),
                'act_data_pkt_fwd': num_packets,
                'min_seg_size_forward': packet_size - 10,
                'Active_Mean': random.randint(100, 500),
                'Active_Std': random.randint(50, 300),
                'Active_Max': random.randint(500, 2000),
                'Active_Min': random.randint(10, 100),
                'Idle_Mean': random.randint(10, 100),
                'Idle_Std': random.randint(5, 50),
                'Idle_Max': random.randint(50, 500),
                'Idle_Min': random.randint(0, 10),
                'Protocol': random.choice([6, 17, 1]),  # TCP, UDP, ICMP
                'Label': 'DDoS'
            }
            data.append(record)
        
        return pd.DataFrame(data)
    
    @staticmethod
    def generate_port_scan(count: int = 100, intensity: float = 0.8) -> pd.DataFrame:
        """
        Generate port scanning traffic
        Characteristics: Many short connections, different destination ports, quick terminations
        """
        data = []
        for i in range(count):
            num_packets = int(50 * intensity + random.randint(5, 30))
            
            record = {
                'Flow_Duration': random.randint(100, 2000),
                'Total_Fwd_Packets': num_packets,
                'Total_Backward_Packets': random.randint(0, num_packets // 3),
                'Total_Length_of_Fwd_Packets': num_packets * random.randint(40, 100),
                'Total_Length_of_Bwd_Packets': random.randint(0, 500),
                'Fwd_Packet_Length_Max': random.randint(40, 100),
                'Fwd_Packet_Length_Min': 40,
                'Fwd_Packet_Length_Mean': random.randint(40, 80),
                'Bwd_Packet_Length_Max': random.randint(100, 1500),
                'Bwd_Packet_Length_Min': 40,
                'Bwd_Packet_Length_Mean': random.randint(50, 200),
                'Flow_Bytes_Per_Sec': random.randint(100, 5000),
                'Flow_Packets_Per_Sec': random.randint(10, 500),
                'Flow_IAT_Mean': random.randint(500, 2000),
                'Flow_IAT_Std': random.randint(1000, 5000),
                'Flow_IAT_Max': random.randint(5000, 10000),
                'Flow_IAT_Min': random.randint(10, 200),
                'Fwd_IAT_Total': random.randint(1000, 5000),
                'Fwd_IAT_Mean': random.randint(200, 1000),
                'Fwd_IAT_Std': random.randint(200, 1000),
                'Fwd_IAT_Max': random.randint(1000, 5000),
                'Fwd_IAT_Min': random.randint(50, 500),
                'Bwd_IAT_Total': random.randint(0, 2000),
                'Bwd_IAT_Mean': random.randint(100, 500),
                'Bwd_IAT_Std': random.randint(100, 500),
                'Bwd_IAT_Max': random.randint(500, 2000),
                'Bwd_IAT_Min': random.randint(50, 300),
                'Fwd_PSH_Flags': 0,
                'Bwd_PSH_Flags': random.randint(0, 5),
                'Fwd_URG_Flags': 0,
                'Bwd_URG_Flags': 0,
                'Fwd_RST_Flags': int(num_packets * 0.3),
                'Bwd_RST_Flags': int(num_packets * 0.3),
                'Fwd_SYN_Flags': int(num_packets * 0.4),
                'Bwd_SYN_Flags': int(num_packets * 0.2),
                'Fwd_FIN_Flags': int(num_packets * 0.1),
                'Bwd_FIN_Flags': int(num_packets * 0.1),
                'Fwd_CWE_Flags': 0,
                'Bwd_CWE_Flags': 0,
                'Fwd_Ack_Flags': int(num_packets * 0.2),
                'Bwd_Ack_Flags': int(num_packets * 0.2),
                'Fwd_ECE_Flags': 0,
                'Bwd_ECE_Flags': 0,
                'Inbound_Init_Window_size': random.randint(1024, 65535),
                'Outbound_Init_Window_size': random.randint(1024, 65535),
                'Packet_Length_Std': random.randint(10, 50),
                'Packet_Length_Variance': random.randint(50, 200),
                'FIN_Flag_Count': int(num_packets * 0.1),
                'SYN_Flag_Count': int(num_packets * 0.4),
                'RST_Flag_Count': int(num_packets * 0.3),
                'PSH_Flag_Count': 0,
                'ACK_Flag_Count': int(num_packets * 0.2),
                'URG_Flag_Count': 0,
                'CWE_Flag_Count': 0,
                'ECE_Flag_Count': 0,
                'Down_Up_Ratio': random.uniform(0.1, 0.5),
                'Average_Packet_Size': random.randint(40, 80),
                'Subflow_Fwd_Packets': num_packets // 3,
                'Subflow_Fwd_Bytes': (num_packets // 3) * random.randint(40, 80),
                'Subflow_Bwd_Packets': random.randint(0, num_packets // 10),
                'Subflow_Bwd_Bytes': random.randint(0, 500),
                'Init_Win_bytes_Forward': random.randint(1024, 65535),
                'Init_Win_bytes_Backward': random.randint(1024, 65535),
                'act_data_pkt_fwd': 0,
                'min_seg_size_forward': 40,
                'Active_Mean': random.randint(50, 300),
                'Active_Std': random.randint(20, 200),
                'Active_Max': random.randint(200, 1000),
                'Active_Min': random.randint(10, 100),
                'Idle_Mean': random.randint(100, 500),
                'Idle_Std': random.randint(50, 300),
                'Idle_Max': random.randint(500, 2000),
                'Idle_Min': random.randint(10, 100),
                'Protocol': 6,  # TCP for port scans
                'Label': 'Port Scan'
            }
            data.append(record)
        
        return pd.DataFrame(data)
    
    @staticmethod
    def generate_web_attack(count: int = 100, intensity: float = 0.8) -> pd.DataFrame:
        """
        Generate web application attack traffic (SQL injection, XSS, etc.)
        Characteristics: Large packet payloads, specific patterns, sustained connections
        """
        data = []
        for i in range(count):
            num_packets = int(150 * intensity + random.randint(20, 100))
            payload_size = int(500 * intensity + random.randint(100, 1000))
            
            record = {
                'Flow_Duration': random.randint(5000, 30000),
                'Total_Fwd_Packets': num_packets,
                'Total_Backward_Packets': num_packets // 2 + random.randint(0, 20),
                'Total_Length_of_Fwd_Packets': num_packets * payload_size,
                'Total_Length_of_Bwd_Packets': (num_packets // 2) * random.randint(200, 1000),
                'Fwd_Packet_Length_Max': payload_size,
                'Fwd_Packet_Length_Min': payload_size // 2,
                'Fwd_Packet_Length_Mean': (payload_size + payload_size // 2) // 2,
                'Bwd_Packet_Length_Max': random.randint(500, 2000),
                'Bwd_Packet_Length_Min': 40,
                'Bwd_Packet_Length_Mean': random.randint(200, 800),
                'Flow_Bytes_Per_Sec': (num_packets * payload_size) / random.randint(5, 30),
                'Flow_Packets_Per_Sec': num_packets / random.randint(5, 30),
                'Flow_IAT_Mean': random.randint(100, 500),
                'Flow_IAT_Std': random.randint(200, 1000),
                'Flow_IAT_Max': random.randint(1000, 3000),
                'Flow_IAT_Min': random.randint(10, 100),
                'Fwd_IAT_Total': random.randint(5000, 20000),
                'Fwd_IAT_Mean': random.randint(200, 1000),
                'Fwd_IAT_Std': random.randint(200, 1000),
                'Fwd_IAT_Max': random.randint(1000, 5000),
                'Fwd_IAT_Min': random.randint(10, 100),
                'Bwd_IAT_Total': random.randint(5000, 20000),
                'Bwd_IAT_Mean': random.randint(200, 1000),
                'Bwd_IAT_Std': random.randint(200, 1000),
                'Bwd_IAT_Max': random.randint(1000, 5000),
                'Bwd_IAT_Min': random.randint(10, 100),
                'Fwd_PSH_Flags': int(num_packets * 0.3),
                'Bwd_PSH_Flags': int(num_packets * 0.3),
                'Fwd_URG_Flags': random.randint(0, 5),
                'Bwd_URG_Flags': random.randint(0, 5),
                'Fwd_RST_Flags': random.randint(0, 5),
                'Bwd_RST_Flags': random.randint(0, 5),
                'Fwd_SYN_Flags': 1,
                'Bwd_SYN_Flags': 1,
                'Fwd_FIN_Flags': 1,
                'Bwd_FIN_Flags': 1,
                'Fwd_CWE_Flags': 0,
                'Bwd_CWE_Flags': 0,
                'Fwd_Ack_Flags': int(num_packets * 0.5),
                'Bwd_Ack_Flags': int(num_packets * 0.5),
                'Fwd_ECE_Flags': 0,
                'Bwd_ECE_Flags': 0,
                'Inbound_Init_Window_size': random.randint(1024, 65535),
                'Outbound_Init_Window_size': random.randint(1024, 65535),
                'Packet_Length_Std': random.randint(100, 500),
                'Packet_Length_Variance': random.randint(1000, 5000),
                'FIN_Flag_Count': 1,
                'SYN_Flag_Count': 1,
                'RST_Flag_Count': random.randint(0, 3),
                'PSH_Flag_Count': int(num_packets * 0.3),
                'ACK_Flag_Count': int(num_packets * 0.5),
                'URG_Flag_Count': random.randint(0, 2),
                'CWE_Flag_Count': 0,
                'ECE_Flag_Count': 0,
                'Down_Up_Ratio': random.uniform(0.5, 1.5),
                'Average_Packet_Size': payload_size // 2,
                'Subflow_Fwd_Packets': num_packets // 3,
                'Subflow_Fwd_Bytes': (num_packets // 3) * payload_size,
                'Subflow_Bwd_Packets': (num_packets // 2) // 3,
                'Subflow_Bwd_Bytes': ((num_packets // 2) // 3) * random.randint(200, 1000),
                'Init_Win_bytes_Forward': random.randint(1024, 65535),
                'Init_Win_bytes_Backward': random.randint(1024, 65535),
                'act_data_pkt_fwd': num_packets,
                'min_seg_size_forward': payload_size // 2,
                'Active_Mean': random.randint(500, 2000),
                'Active_Std': random.randint(200, 1000),
                'Active_Max': random.randint(2000, 5000),
                'Active_Min': random.randint(100, 500),
                'Idle_Mean': random.randint(10, 100),
                'Idle_Std': random.randint(5, 50),
                'Idle_Max': random.randint(50, 200),
                'Idle_Min': random.randint(0, 20),
                'Protocol': 6,  # TCP for HTTP/HTTPS
                'Label': 'Web Attack'
            }
            data.append(record)
        
        return pd.DataFrame(data)
    
    @staticmethod
    def generate_data_exfiltration(count: int = 100, intensity: float = 0.8) -> pd.DataFrame:
        """
        Generate data exfiltration traffic
        Characteristics: High outbound data, moderate packet rate, sustained connections
        """
        data = []
        for i in range(count):
            num_packets = int(200 * intensity + random.randint(50, 150))
            fwd_packet_size = int(2000 * intensity + random.randint(500, 2000))
            
            record = {
                'Flow_Duration': random.randint(10000, 60000),
                'Total_Fwd_Packets': num_packets,
                'Total_Backward_Packets': num_packets // 4,
                'Total_Length_of_Fwd_Packets': num_packets * fwd_packet_size,
                'Total_Length_of_Bwd_Packets': (num_packets // 4) * random.randint(50, 200),
                'Fwd_Packet_Length_Max': fwd_packet_size,
                'Fwd_Packet_Length_Min': fwd_packet_size // 2,
                'Fwd_Packet_Length_Mean': fwd_packet_size // 1.5,
                'Bwd_Packet_Length_Max': random.randint(100, 500),
                'Bwd_Packet_Length_Min': 40,
                'Bwd_Packet_Length_Mean': random.randint(50, 200),
                'Flow_Bytes_Per_Sec': (num_packets * fwd_packet_size) / random.randint(10, 60),
                'Flow_Packets_Per_Sec': num_packets / random.randint(10, 60),
                'Flow_IAT_Mean': random.randint(200, 1000),
                'Flow_IAT_Std': random.randint(500, 2000),
                'Flow_IAT_Max': random.randint(2000, 5000),
                'Flow_IAT_Min': random.randint(50, 300),
                'Fwd_IAT_Total': random.randint(10000, 50000),
                'Fwd_IAT_Mean': random.randint(400, 1500),
                'Fwd_IAT_Std': random.randint(500, 2000),
                'Fwd_IAT_Max': random.randint(2000, 5000),
                'Fwd_IAT_Min': random.randint(50, 300),
                'Bwd_IAT_Total': random.randint(2000, 10000),
                'Bwd_IAT_Mean': random.randint(500, 2000),
                'Bwd_IAT_Std': random.randint(500, 2000),
                'Bwd_IAT_Max': random.randint(2000, 5000),
                'Bwd_IAT_Min': random.randint(100, 500),
                'Fwd_PSH_Flags': int(num_packets * 0.1),
                'Bwd_PSH_Flags': int(num_packets * 0.05),
                'Fwd_URG_Flags': 0,
                'Bwd_URG_Flags': 0,
                'Fwd_RST_Flags': 0,
                'Bwd_RST_Flags': 0,
                'Fwd_SYN_Flags': 1,
                'Bwd_SYN_Flags': 1,
                'Fwd_FIN_Flags': 1,
                'Bwd_FIN_Flags': 1,
                'Fwd_CWE_Flags': 0,
                'Bwd_CWE_Flags': 0,
                'Fwd_Ack_Flags': int(num_packets * 0.5),
                'Bwd_Ack_Flags': int(num_packets * 0.5),
                'Fwd_ECE_Flags': 0,
                'Bwd_ECE_Flags': 0,
                'Inbound_Init_Window_size': random.randint(1024, 65535),
                'Outbound_Init_Window_size': random.randint(1024, 65535),
                'Packet_Length_Std': random.randint(500, 2000),
                'Packet_Length_Variance': random.randint(5000, 20000),
                'FIN_Flag_Count': 1,
                'SYN_Flag_Count': 1,
                'RST_Flag_Count': 0,
                'PSH_Flag_Count': int(num_packets * 0.1),
                'ACK_Flag_Count': int(num_packets * 0.5),
                'URG_Flag_Count': 0,
                'CWE_Flag_Count': 0,
                'ECE_Flag_Count': 0,
                'Down_Up_Ratio': random.uniform(0.1, 0.3),
                'Average_Packet_Size': fwd_packet_size,
                'Subflow_Fwd_Packets': num_packets // 3,
                'Subflow_Fwd_Bytes': (num_packets // 3) * fwd_packet_size,
                'Subflow_Bwd_Packets': (num_packets // 4) // 3,
                'Subflow_Bwd_Bytes': ((num_packets // 4) // 3) * random.randint(50, 200),
                'Init_Win_bytes_Forward': random.randint(1024, 65535),
                'Init_Win_bytes_Backward': random.randint(1024, 65535),
                'act_data_pkt_fwd': num_packets,
                'min_seg_size_forward': fwd_packet_size // 2,
                'Active_Mean': random.randint(1000, 5000),
                'Active_Std': random.randint(500, 2000),
                'Active_Max': random.randint(5000, 10000),
                'Active_Min': random.randint(100, 500),
                'Idle_Mean': random.randint(50, 200),
                'Idle_Std': random.randint(20, 100),
                'Idle_Max': random.randint(200, 500),
                'Idle_Min': random.randint(10, 50),
                'Protocol': 6,  # TCP
                'Label': 'Data Exfiltration'
            }
            data.append(record)
        
        return pd.DataFrame(data)
    
    @staticmethod
    def generate_brute_force(count: int = 100, intensity: float = 0.8) -> pd.DataFrame:
        """
        Generate brute force attack traffic (login attempts)
        Characteristics: Many failed connections, repeated patterns, quick timeouts
        """
        data = []
        for i in range(count):
            num_packets = int(50 * intensity + random.randint(10, 50))
            
            record = {
                'Flow_Duration': random.randint(1000, 5000),
                'Total_Fwd_Packets': num_packets,
                'Total_Backward_Packets': num_packets // 2,
                'Total_Length_of_Fwd_Packets': num_packets * random.randint(50, 150),
                'Total_Length_of_Bwd_Packets': (num_packets // 2) * random.randint(100, 300),
                'Fwd_Packet_Length_Max': random.randint(100, 200),
                'Fwd_Packet_Length_Min': 50,
                'Fwd_Packet_Length_Mean': random.randint(75, 150),
                'Bwd_Packet_Length_Max': random.randint(200, 500),
                'Bwd_Packet_Length_Min': 40,
                'Bwd_Packet_Length_Mean': random.randint(100, 300),
                'Flow_Bytes_Per_Sec': random.randint(500, 3000),
                'Flow_Packets_Per_Sec': random.randint(50, 300),
                'Flow_IAT_Mean': random.randint(100, 500),
                'Flow_IAT_Std': random.randint(200, 1000),
                'Flow_IAT_Max': random.randint(1000, 3000),
                'Flow_IAT_Min': random.randint(10, 100),
                'Fwd_IAT_Total': random.randint(2000, 10000),
                'Fwd_IAT_Mean': random.randint(200, 1000),
                'Fwd_IAT_Std': random.randint(200, 1000),
                'Fwd_IAT_Max': random.randint(1000, 3000),
                'Fwd_IAT_Min': random.randint(50, 200),
                'Bwd_IAT_Total': random.randint(1000, 5000),
                'Bwd_IAT_Mean': random.randint(200, 1000),
                'Bwd_IAT_Std': random.randint(200, 1000),
                'Bwd_IAT_Max': random.randint(500, 2000),
                'Bwd_IAT_Min': random.randint(50, 200),
                'Fwd_PSH_Flags': int(num_packets * 0.2),
                'Bwd_PSH_Flags': int(num_packets * 0.2),
                'Fwd_URG_Flags': 0,
                'Bwd_URG_Flags': 0,
                'Fwd_RST_Flags': int(num_packets * 0.2),
                'Bwd_RST_Flags': int(num_packets * 0.2),
                'Fwd_SYN_Flags': int(num_packets * 0.3),
                'Bwd_SYN_Flags': int(num_packets * 0.3),
                'Fwd_FIN_Flags': int(num_packets * 0.2),
                'Bwd_FIN_Flags': int(num_packets * 0.2),
                'Fwd_CWE_Flags': 0,
                'Bwd_CWE_Flags': 0,
                'Fwd_Ack_Flags': int(num_packets * 0.3),
                'Bwd_Ack_Flags': int(num_packets * 0.3),
                'Fwd_ECE_Flags': 0,
                'Bwd_ECE_Flags': 0,
                'Inbound_Init_Window_size': random.randint(1024, 65535),
                'Outbound_Init_Window_size': random.randint(1024, 65535),
                'Packet_Length_Std': random.randint(20, 100),
                'Packet_Length_Variance': random.randint(100, 500),
                'FIN_Flag_Count': int(num_packets * 0.2),
                'SYN_Flag_Count': int(num_packets * 0.3),
                'RST_Flag_Count': int(num_packets * 0.2),
                'PSH_Flag_Count': int(num_packets * 0.2),
                'ACK_Flag_Count': int(num_packets * 0.3),
                'URG_Flag_Count': 0,
                'CWE_Flag_Count': 0,
                'ECE_Flag_Count': 0,
                'Down_Up_Ratio': random.uniform(0.5, 1.5),
                'Average_Packet_Size': random.randint(75, 200),
                'Subflow_Fwd_Packets': num_packets // 3,
                'Subflow_Fwd_Bytes': (num_packets // 3) * random.randint(50, 150),
                'Subflow_Bwd_Packets': (num_packets // 2) // 3,
                'Subflow_Bwd_Bytes': ((num_packets // 2) // 3) * random.randint(100, 300),
                'Init_Win_bytes_Forward': random.randint(1024, 65535),
                'Init_Win_bytes_Backward': random.randint(1024, 65535),
                'act_data_pkt_fwd': num_packets,
                'min_seg_size_forward': 50,
                'Active_Mean': random.randint(200, 1000),
                'Active_Std': random.randint(100, 500),
                'Active_Max': random.randint(1000, 3000),
                'Active_Min': random.randint(50, 200),
                'Idle_Mean': random.randint(50, 300),
                'Idle_Std': random.randint(20, 150),
                'Idle_Max': random.randint(500, 2000),
                'Idle_Min': random.randint(10, 100),
                'Protocol': 6,  # TCP
                'Label': 'Brute Force'
            }
            data.append(record)
        
        return pd.DataFrame(data)
    
    @staticmethod
    def generate_normal_traffic(count: int = 100) -> pd.DataFrame:
        """
        Generate normal benign traffic for baseline
        """
        data = []
        for i in range(count):
            num_packets = random.randint(5, 50)
            
            record = {
                'Flow_Duration': random.randint(100, 10000),
                'Total_Fwd_Packets': num_packets,
                'Total_Backward_Packets': num_packets,
                'Total_Length_of_Fwd_Packets': num_packets * random.randint(40, 500),
                'Total_Length_of_Bwd_Packets': num_packets * random.randint(40, 500),
                'Fwd_Packet_Length_Max': random.randint(100, 1500),
                'Fwd_Packet_Length_Min': 40,
                'Fwd_Packet_Length_Mean': random.randint(100, 800),
                'Bwd_Packet_Length_Max': random.randint(100, 1500),
                'Bwd_Packet_Length_Min': 40,
                'Bwd_Packet_Length_Mean': random.randint(100, 800),
                'Flow_Bytes_Per_Sec': random.randint(100, 5000),
                'Flow_Packets_Per_Sec': random.randint(10, 100),
                'Flow_IAT_Mean': random.randint(500, 2000),
                'Flow_IAT_Std': random.randint(1000, 5000),
                'Flow_IAT_Max': random.randint(5000, 10000),
                'Flow_IAT_Min': random.randint(100, 500),
                'Fwd_IAT_Total': random.randint(5000, 20000),
                'Fwd_IAT_Mean': random.randint(500, 2000),
                'Fwd_IAT_Std': random.randint(500, 2000),
                'Fwd_IAT_Max': random.randint(2000, 5000),
                'Fwd_IAT_Min': random.randint(100, 500),
                'Bwd_IAT_Total': random.randint(5000, 20000),
                'Bwd_IAT_Mean': random.randint(500, 2000),
                'Bwd_IAT_Std': random.randint(500, 2000),
                'Bwd_IAT_Max': random.randint(2000, 5000),
                'Bwd_IAT_Min': random.randint(100, 500),
                'Fwd_PSH_Flags': random.randint(0, 5),
                'Bwd_PSH_Flags': random.randint(0, 5),
                'Fwd_URG_Flags': 0,
                'Bwd_URG_Flags': 0,
                'Fwd_RST_Flags': random.randint(0, 2),
                'Bwd_RST_Flags': random.randint(0, 2),
                'Fwd_SYN_Flags': 1,
                'Bwd_SYN_Flags': 1,
                'Fwd_FIN_Flags': 1,
                'Bwd_FIN_Flags': 1,
                'Fwd_CWE_Flags': 0,
                'Bwd_CWE_Flags': 0,
                'Fwd_Ack_Flags': random.randint(0, num_packets),
                'Bwd_Ack_Flags': random.randint(0, num_packets),
                'Fwd_ECE_Flags': 0,
                'Bwd_ECE_Flags': 0,
                'Inbound_Init_Window_size': random.randint(1024, 65535),
                'Outbound_Init_Window_size': random.randint(1024, 65535),
                'Packet_Length_Std': random.randint(50, 500),
                'Packet_Length_Variance': random.randint(500, 5000),
                'FIN_Flag_Count': 1,
                'SYN_Flag_Count': 1,
                'RST_Flag_Count': random.randint(0, 2),
                'PSH_Flag_Count': random.randint(0, 5),
                'ACK_Flag_Count': random.randint(0, num_packets),
                'URG_Flag_Count': 0,
                'CWE_Flag_Count': 0,
                'ECE_Flag_Count': 0,
                'Down_Up_Ratio': random.uniform(0.5, 2.0),
                'Average_Packet_Size': random.randint(100, 800),
                'Subflow_Fwd_Packets': num_packets // 2,
                'Subflow_Fwd_Bytes': (num_packets // 2) * random.randint(100, 500),
                'Subflow_Bwd_Packets': num_packets // 2,
                'Subflow_Bwd_Bytes': (num_packets // 2) * random.randint(100, 500),
                'Init_Win_bytes_Forward': random.randint(1024, 65535),
                'Init_Win_bytes_Backward': random.randint(1024, 65535),
                'act_data_pkt_fwd': random.randint(0, num_packets),
                'min_seg_size_forward': 40,
                'Active_Mean': random.randint(500, 2000),
                'Active_Std': random.randint(500, 2000),
                'Active_Max': random.randint(2000, 5000),
                'Active_Min': random.randint(100, 500),
                'Idle_Mean': random.randint(100, 1000),
                'Idle_Std': random.randint(100, 1000),
                'Idle_Max': random.randint(1000, 5000),
                'Idle_Min': random.randint(100, 500),
                'Protocol': random.choice([6, 17]),  # TCP or UDP
                'Label': 'BENIGN'
            }
            data.append(record)
        
        return pd.DataFrame(data)
