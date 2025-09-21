import glob
import os


class FileFinderGlob:
    @staticmethod
    def find_files_with_glob(directory, pattern="*", recursive=False):
        """
        Find files in a directory matching a specific pattern using glob.

        :param directory: The directory to search in.
        :param pattern: The pattern to match (e.g., '*.txt' for text files).
        :return: List of matching file paths (full paths).
        """
        search_pattern = os.path.join(directory, pattern)
        r = glob.glob(search_pattern, recursive=recursive)
        return len(r), r





