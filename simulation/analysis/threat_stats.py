class ThreatStats:
    def __init__(self):
        self.total_packets = 0
        self.total_attacks = 0
        self.force_land_count = 0
        self.isolation_count = 0

    def update(self, packet):
        self.total_packets += 1

        if packet.get("flagged"):
            self.total_attacks += 1

        if packet.get("response") == "FORCE_LAND":
            self.force_land_count += 1

        if packet.get("response") == "ISOLATE_DRONE":
            self.isolation_count += 1

    def display(self):
        print("\n===== THREAT STATS =====")
        print(f"Packets Processed : {self.total_packets}")
        print(f"Detected Attacks  : {self.total_attacks}")
        print(f"FORCE_LAND Count  : {self.force_land_count}")
        print(f"ISOLATIONS        : {self.isolation_count}")
        print("========================\n")
