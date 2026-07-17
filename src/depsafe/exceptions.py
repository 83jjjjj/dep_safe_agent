

class Submitted(Exception):
    def __init__(self, message: dict):
        self.message = message
        super().__init__()
