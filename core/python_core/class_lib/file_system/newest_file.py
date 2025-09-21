import os
import json

class NewestFile:
    @staticmethod
    def get_newest_file(folder_path, get_file_content=True, get_full_path=True):
        """
        Finds the newest file in a directory and tries to parse it as JSON.

        :param directory: Path to the directory.
        :return: A dictionary with the JSON content if the newest file is valid JSON,
                 or False if no valid JSON file is found.
        """
        try:
            # Step 1: Find the newest file in the directory
            newest_file = None
            max_mtime = 0

            with os.scandir(folder_path) as entries:
                for entry in entries:
                    if entry.is_file(follow_symlinks=False):  # Check if it is a file
                        mtime = entry.stat().st_mtime  # Get the modification time
                        if mtime > max_mtime:
                            newest_file = entry.path  # Save file path
                            max_mtime = mtime

            if not newest_file:
                return False, False  # No files found

            if get_file_content:
                with open(newest_file, 'r', encoding="utf-8") as f:
                    return True, json.load(f)  # Parse and return JSON content as a dictionary
            else:
                if get_full_path:
                    return True, newest_file
                else:
                    return True, os.path.basename(newest_file)

        except (json.JSONDecodeError, IOError):  # Handle invalid JSON or file access issues
            return False, False

