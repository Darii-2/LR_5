from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from collections import defaultdict
import prettytable

# Налаштування
INTERFACE = "Ethernet"  # інтерфейс
THRESHOLD_PACKETS = 50  # Поріг пакетів для одного джерела
THRESHOLD_PORTS = 10    # Поріг різних портів для одного джерела
LOG_FILE = "captured_packets.log"  # Файл для збереження даних

# Дані про трафік
traffic_data = defaultdict(lambda: {"count": 0, "ports": set()})
alerted_ips = set()

# Функція для обробки пакетів
def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Зберігаємо дані про пакети
        traffic_data[src_ip]["count"] += 1
        traffic_data[src_ip]["ports"].add(dst_port)

        # Записуємо інформацію про кожен пакет у файл
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"Packet captured: Source IP: {src_ip}, Destination Port: {dst_port}\n")

        # Перевірка на підозрілу активність
        if src_ip not in alerted_ips:
            if traffic_data[src_ip]["count"] > THRESHOLD_PACKETS:
                log_alert(f"Suspicious activity detected: {src_ip} sent over {THRESHOLD_PACKETS} packets!")
                alerted_ips.add(src_ip)

            if len(traffic_data[src_ip]["ports"]) > THRESHOLD_PORTS:
                log_alert(f"Port scanning detected from {src_ip}! Unique ports: {len(traffic_data[src_ip]['ports'])}")
                alerted_ips.add(src_ip)

# Функція для запису попереджень
def log_alert(message):
    print(f"[ALERT] {message}")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[ALERT] {message}\n")

# Функція для підсумкової таблиці
def print_traffic_summary():
    table = prettytable.PrettyTable(["Source IP", "Packet Count", "Unique Ports"])
    for ip, data in traffic_data.items():
        table.add_row([ip, data["count"], len(data["ports"])])
    print(table)

# Запуск сніффера
def start_sniffing():
    print(f"Starting packet capture on interface {INTERFACE}...")
    try:
        with open(LOG_FILE, "w") as log_file:
            log_file.write("Packet capture started.\n")
        sniff(iface=INTERFACE, prn=process_packet, store=False)
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    start_sniffing()