import os


class FileDirectoryPruner:
    @staticmethod
    def keep_latest_files(directory, keep_count=3):
        # Check if the directory exists
        if not os.path.exists(directory) or not os.path.isdir(directory):
            print(f"Invalid directory: {directory}")
            return

        # Get a list of all files in the directory
        files = [os.path.join(directory, f) for f in os.listdir(directory)
                 if os.path.isfile(os.path.join(directory, f))]

        # Debug: Print the initial list of files
        #print(f"Initial list of files: {files}")

        # Ensure there are files to process
        if not files:
            print(f"No files to process in directory: {directory}")
            return

        # Sort files by modification time in descending order (newest first)
        files.sort(key=os.path.getmtime, reverse=True)

        # Debug: Print the sorted list of files
        #print(f"Sorted list of files (newest first): {files}")

        # Determine files to delete (all files after the first `keep_count`)
        files_to_delete = files[keep_count:]

        # Debug: Print the files identified for deletion
        #print(f"Files to delete: {files_to_delete}")

        # Delete files beyond the `keep_count`
        for file_to_delete in files_to_delete:
            try:
                # Check if the file is writable
                if not os.access(file_to_delete, os.W_OK):
                    print(f"Permission denied: {file_to_delete}")
                    continue

                # Delete the file
                os.remove(file_to_delete)
                #print(f"Successfully deleted: {file_to_delete}")

            except FileNotFoundError:
                print(f"File not found (maybe already deleted): {file_to_delete}")
            except PermissionError:
                print(f"Permission denied when trying to delete file: {file_to_delete}")
            except Exception as e:
                print(f"Error deleting {file_to_delete}: {e}")

        # Debug: Confirm remaining files in the directory
        remaining_files = [os.path.join(directory, f) for f in os.listdir(directory)
                           if os.path.isfile(os.path.join(directory, f))]
        #print(f"Files remaining in the directory: {remaining_files}")
