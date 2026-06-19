class Decision:

    def __init__(self, detector, src_ip, score, attack_type):
        self.detector = detector
        self.src_ip = src_ip
        self.score = score
        self.attack_type = attack_type


class DecisionEngine:

    def __init__(self):

        # Umbral global (puedes ajustarlo por tesis)
        self.global_threshold = 200

        # ponderación por tipo de ataque
        self.weights = {
            "SYN_FLOOD": 1.0,
            "UDP_FLOOD": 0.9,
            "ICMP_FLOOD": 0.8,
            "LOW_SLOW": 1.2,
            "DDOS_DISTRIBUTED": 1.3
        }

    def evaluate(self, detections):

        if not detections:
            return None

        scored = []

        for d in detections:

            attack_type = d.get("type")
            src_ip = d.get("src_ip")
            score = d.get("score", 0)

            weight = self.weights.get(attack_type, 1.0)

            final_score = score * weight

            scored.append({
                "type": attack_type,
                "src_ip": src_ip,
                "score": final_score,
                "detector": attack_type
            })

        # seleccionar el ataque más fuerte
        best = max(scored, key=lambda x: x["score"])

        # decisión final
        if best["score"] < self.global_threshold:
            return None

        return Decision(
            detector=best["detector"],
            src_ip=best["src_ip"],
            score=best["score"],
            attack_type=best["type"]
        )
