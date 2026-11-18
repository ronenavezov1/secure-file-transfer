class File:
    def __init__(self, owner_token, file_name, file_path, verified=False):
        self.owner_token = owner_token
        self.file_name = file_name
        self.file_path = file_path
        self.verified = verified
