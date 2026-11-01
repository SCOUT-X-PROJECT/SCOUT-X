# Right now it just keeps track of state in memory which is fine for testing.

class TrustEngine:
    
    INITIAL_TRUST = 1.0
    ANOMALY_PENALTY = 0.15        # base penalty per bad packet
    HIGH_SEVERITY_BONUS = 0.05    # extra drop if things look real bad
    PERSISTENT_BONUS = 0.05       # same here for persistent attacks
    PER_FLAG_PENALTY = 0.02       # add a bit more per flag we find
    CLEAN_RECOVERY = 0.02         # how fast they gain trust back (intentionally slow)
    MAX_FLAGS_PENALTY = 0.10      # cap this so a million flags doesn't instantly drop trust to negative infinity lol

    def __init__(self):
        
        self.trust = self.INITIAL_TRUST
        self.history_count = 0 
    def update(self, packet):
        self.history_count += 1
        
        # grab validation data safely
        validation_data = packet.get("validation")
        if validation_data is None:
            validation = {}
        else:
            validation = validation_data
            
        is_anomalous = bool(validation.get("is_anomalous", False))
        
        # handle flags list safely
        flags = validation.get("flags") 
        if flags is None:
            flags = []
        elif not isinstance(flags, list):
            flags = []
            
        pattern = packet.get("pattern")
        severity = packet.get("severity")

        if is_anomalous:
            # calc the penalty for a bad packet
            total_penalty = self.ANOMALY_PENALTY
            
            flag_contrib = len(flags) * self.PER_FLAG_PENALTY
            if flag_contrib > self.MAX_FLAGS_PENALTY:
                flag_contrib = self.MAX_FLAGS_PENALTY
            
            total_penalty = total_penalty + flag_contrib

            if severity == "HIGH":
                total_penalty += self.HIGH_SEVERITY_BONUS
                
            if pattern == "PERSISTENT_ATTACK":
                total_penalty += self.PERSISTENT_BONUS

            # subtract and make sure we don't go below 0
            self.trust = self.trust - total_penalty
            if self.trust < 0.0:
                self.trust = 0.0
                
        else:
            # slowly recover trust on clean packets
            self.trust = self.trust + self.CLEAN_RECOVERY
            if self.trust > 1.0:
                self.trust = 1.0

        # rounding just to keep logs clean
        return round(self.trust, 4)

    def reset(self):
        # just put it back to default
        self.trust = self.INITIAL_TRUST
        self.history_count = 0