from flask import Flask, jsonify, render_template, request, send_file
import scapy.all as scapy
import threading
import json
from datetime import datetime

app = Flask(__name__)
captured_packets = []
capture_flag = False

# Variables to track PPS and inter-arrival time
last_packet_time = None
packet_count = 0
pps_start_time = None


def capture_packets():
    """Captures network packets continuously until stopped."""
    global capture_flag, captured_packets, last_packet_time, packet_count, pps_start_time
    captured_packets = []  # Reset packet list for a new capture session
    last_packet_time = None  # Reset for inter-arrival time
    packet_count = 0  # Reset for PPS
    pps_start_time = datetime.now()  # Start time for PPS calculation

    def packet_handler(packet):
        global last_packet_time, packet_count, pps_start_time
        if not capture_flag:
            return  # Stop capturing when flag is False

        # Current timestamp for this packet
        current_time = datetime.now()

        # Calculate Inter-Arrival Time
        inter_arrival_time = (current_time - last_packet_time).total_seconds() if last_packet_time else 0
        last_packet_time = current_time

        # Calculate PPS (Packets per Second)
        packet_count += 1
        elapsed_time = (current_time - pps_start_time).total_seconds()
        pps = packet_count / elapsed_time if elapsed_time > 0 else 0
        if elapsed_time >= 1:  # Reset PPS counter every second
            packet_count = 1
            pps_start_time = current_time

        # TCP Flag Count (count occurrences of each flag)
        tcp_flags = packet.sprintf("%TCP.flags%") if packet.haslayer(scapy.TCP) else ""
        tcp_flag_count = {
            "SYN": tcp_flags.count("S"),
            "ACK": tcp_flags.count("A"),
            "FIN": tcp_flags.count("F"),
            "RST": tcp_flags.count("R"),
            "PSH": tcp_flags.count("P"),
            "URG": tcp_flags.count("U")
        }

        # Wi-Fi Frame Detection (for 802.11 packets)
        wifi_frame_info = {}

        if packet.haslayer(scapy.Dot11):
            wifi_frame_info = {
                "frame_type": packet[scapy.Dot11].type,  # 0: Management, 1: Control, 2: Data
                "frame_subtype": packet[scapy.Dot11].subtype,  # e.g., 12 for Deauthentication
                "source_mac": packet[scapy.Dot11].addr2,
                "destination_mac": packet[scapy.Dot11].addr1
            }

        packet_info = {
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A",
            "destination_ip": packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A",
            "protocol": packet.sprintf("%IP.proto%"),
            "syn_flag": "Yes" if packet.haslayer(scapy.TCP) and "S" in tcp_flags else "No",
            "ack_flag": "Yes" if packet.haslayer(scapy.TCP) and "A" in tcp_flags else "No",
            "source_port": packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else (
                packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else "N/A"),
            "destination_port": packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else (
                packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else "N/A"),
            "length": len(packet),
            "http_code": packet[scapy.Raw].load[:3].decode() if packet.haslayer(scapy.Raw) and packet[scapy.Raw].load[
                                                                                               :3].isdigit() else "N/A",
            "ack_number": packet[scapy.TCP].ack if packet.haslayer(scapy.TCP) else "N/A",
            "window_size": packet[scapy.TCP].window if packet.haslayer(scapy.TCP) else "N/A",
            "sequence_number": packet[scapy.TCP].seq if packet.haslayer(scapy.TCP) else "N/A",
            "interface": "eth0",  # Change as per your system interface
            "ip_type": "IPv4" if packet.haslayer(scapy.IP) else "IPv6" if packet.haslayer(scapy.IPv6) else "N/A",
            "checksum_status": "Valid" if packet.haslayer(scapy.IP) and packet[scapy.IP].chksum else "Invalid",
            # New Features
            "pps": round(pps, 2),  # Packets per second
            "inter_arrival_time": round(inter_arrival_time, 6),  # Time between this and previous packet
            "tcp_flag_count": tcp_flag_count,  # Count of each TCP flag
            "wifi_frame_info": wifi_frame_info if wifi_frame_info else "N/A"  # Wi-Fi frame details
        }
        captured_packets.append(packet_info)

    scapy.sniff(filter="ip", prn=packet_handler, store=False)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_flag
    capture_flag = True
    thread = threading.Thread(target=capture_packets, daemon=True)
    thread.start()
    return jsonify({"status": "Packet capture started"})


@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capture_flag
    capture_flag = False
    return jsonify({"status": "Packet capture stopped"})


@app.route('/get_data', methods=['GET'])
def get_data():
    return jsonify(captured_packets)


@app.route('/download_data', methods=['GET'])
def download_data():
    with open('captured_packets.json', 'w') as f:
        json.dump(captured_packets, f, indent=4)
    return send_file('captured_packets.json', as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
