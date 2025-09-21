import os

class EnsureTrailingSlash:
    @staticmethod
    # Ensure the path ends with a trailing slash
    def ensure_trailing_slash(path):
        if not path.endswith(os.sep):  # os.sep is '/' on Unix or '\\' on Windows
            return path + os.sep
        return path
