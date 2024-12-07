import subprocess
import nmap
import socket

# Функція для налаштування брандмауера
def configure_firewall():
    rules = [
        ('Block IP 192.168.1.100', 'in', 'block', 'remoteip=192.168.1.100'),
        ('Block IP Range 192.168.1.0/24', 'in', 'block', 'remoteip=192.168.1.0/24'),
        ('Block Port 80', 'in', 'block', 'protocol=TCP localport=80'),
        ('Allow Port 80 from Trusted IP', 'in', 'allow', 'protocol=TCP localport=80 remoteip=192.168.1.100'),
    ]

    # Додавання правил брандмауера
    for rule in rules:
        rule_name, direction, action, params = rule
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir={direction} action={action} {params}'
        try:
            subprocess.run(command, check=True, shell=True)
            print(f"Команда успішно виконана: {command}")
        except subprocess.CalledProcessError as e:
            print(f"Помилка при виконанні: {e}")

    # Включення журналювання заблокованих з'єднань
    try:
        subprocess.run('netsh advfirewall set allprofiles logging droppedconnections enable', check=True, shell=True)
        print("Журналювання за заборонені підключення увімкнено.")
    except subprocess.CalledProcessError as e:
        print(f"Помилка при увімкненні журналювання: {e}")

# Функція для сканування мережі
def scan_network(ip_range, ports):
    nm = nmap.PortScanner()
    
    # Сканування діапазону IP та портів
    print(f"Сканування діапазону IP: {ip_range} для портів: {ports}")
    nm.scan(hosts=ip_range, arguments=f'-p {ports} --open')

    active_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            active_hosts.append(host)
            print(f"Активний хост: {host}")
            for port in nm[host]['tcp']:
                print(f"  Порт {port}: {nm[host]['tcp'][port]['state']}")
                if 'name' in nm[host]['tcp'][port]:
                    print(f"    Сервіс: {nm[host]['tcp'][port]['name']}")
                if 'product' in nm[host]['tcp'][port]:
                    print(f"    Версія продукту: {nm[host]['tcp'][port].get('product', 'Не визначено')}")
                if 'version' in nm[host]['tcp'][port]:
                    print(f"    Версія: {nm[host]['tcp'][port].get('version', 'Не визначено')}")
    return active_hosts

# Основна функція для виконання завдання
def main():
    # Налаштування брандмауера
    configure_firewall()

    # Сканування мережі
    ip_range = "192.168.1.0/24"  # Діапазон IP-адрес
    ports = "22,80,443"  # Порти для сканування
    active_hosts = scan_network(ip_range, ports)

    if active_hosts:
        print(f"Знайдено активні хости: {', '.join(active_hosts)}")
    else:
        print("Не знайдено активних хостів.")

if __name__ == "__main__":
    main()