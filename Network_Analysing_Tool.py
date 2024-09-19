import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time

#Capturing data packets from a network adapter
def capture_packets(interface, packet_count):
    try:
        capture = pyshark.LiveCapture(interface=interface)
        capture.sniff(packet_count=packet_count)
        packets = capture._packets
        return packets
    except Exception as e:
        print(f"Error opening adapter: {e}")
        return []

#creating a storage for the packets captured
class PacketStorage:
    def __init__(self):
        self.packets = []

    def add_packet(self, packet):
        self.packets.append(packet)

    def to_dataframe(self):
        """
        Converts the packets stored in the class instance 
        to a pandas DataFrame.

        Returns:
            pandas.DataFrame: A DataFrame containing the 
            following columns:
                - 'src_ip' (str): The source IP address of 
                   each packet.
                - 'dst_ip' (str): The destination IP 
                   address of each packet.
                - 'protocol' (str): The highest layer 
                   protocol of each packet.
                - 'timestamp' (float): The timestamp of 
                   each packet in seconds since the epoch.

        """
        data = []
        for packet in self.packets:
            if hasattr(packet, 'ip'):
                data.append({
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'protocol': packet.highest_layer,
                    'timestamp': float(packet.sniff_time.timestamp())
                })
        return pd.DataFrame(data)

#Visualizing the data Plots
def plot_traffic_volume(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    df.set_index('timestamp', inplace=True)
    traffic_volume = df.resample('min').size()  # Resample per minute
    plt.figure(figsize=(10, 5))
    traffic_volume.plot()
    plt.title('Network Traffic Volume')
    plt.xlabel('Time')
    plt.ylabel('Number of Packets')
    plt.show()

#Ploting the protocol distribution
def plot_protocol_distribution(df):
    plt.figure(figsize=(10, 5))
    sns.countplot(x='protocol', data=df)
    plt.title('Protocol Distribution')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.show()

#Implementing machine learning algorithms to detect anomalies and potential threats
def detect_anomalies(df):
    model = IsolationForest(contamination=0.01)  # Adjust contamination factor as needed
    features = df[['src_ip', 'dst_ip', 'protocol']].map(lambda x: hash(x) % 10**8)
    model.fit(features)
    df['anomaly'] = model.predict(features)
    return df[df['anomaly'] == -1]

#Sending an email alert
def send_alert(anomalies):
    msg = MIMEMultipart()
    msg['From'] = 'your_email@example.com'  # Replace with your email
    msg['To'] = 'alert_recipient@example.com'   # Replace with the recipient's email
    msg['Subject'] = 'Network Anomaly Alert'
    body = f"Anomalies detected:\n\n{anomalies.to_string()}"
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.example.com', 587)  # Replace with your SMTP server details
    server.starttls()
    server.login(msg['From'], 'your_password')  # Replace with your email and password
    server.sendmail(msg['From'], msg['To'], msg.as_string())
    server.quit()

# Main Function
def main():
    interface = 'Wi-Fi'  # Adjust to your network interface
    packet_count = 100  # Adjust as needed

    # Capture packets
    packets = capture_packets(interface, packet_count)
    if not packets:
        print("No packets captured. Please check the interface and permissions.")
        return
    
    # Store packets
    storage = PacketStorage()
    for packet in packets:
        storage.add_packet(packet)

    # Convert to DataFrame
    df = storage.to_dataframe()

    # Visualize data
    plot_traffic_volume(df)
    plot_protocol_distribution(df)

    # Detect anomalies
    anomalies = detect_anomalies(df)
    if not anomalies.empty:
        send_alert(anomalies)   # Send an alert if anomalies are detected   

if __name__ == '__main__':
    while True:
        main()
	    time.sleep(300)

