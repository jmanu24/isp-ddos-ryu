class DetectorRegistry:
    def __init__(self):
        self.detectors = []

    def register(self, detector):
        self.detectors.append(detector)

    def get_all(self):
        return self.detectors
