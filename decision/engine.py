from config.settings import DECISION_THRESHOLD

class DecisionEngine:

    def evaluate(self, detections):

        if not detections:
            return None

        score = sum(d.score for d in detections)

        if score >= DECISION_THRESHOLD:

            return max(detections, key=lambda x: x.score)

        return None
