import os
import json
import tempfile


class FileSystemBuilder:

    def process_item(self, base, item, current_path=None, create_path=True):

        """Process an individual file or directory item.

        Args:
            item (dict): The dictionary specifying the file or directory.
            current_path (str): The current directory path being processed. Defaults to `self.base`.
            :param create_path:
        """

        # Ensure the base directory exists
        if create_path and (not os.path.exists(base)):
            os.makedirs(base)  # Create the base directory

        # Use base path if no current path is provided
        if current_path is None:
            current_path = base

        # Get attributes for the item
        name = item.get('name', 'Unknown')
        item_type = item.get('type', 'unknown')
        content = item.get('content', None)
        atomic = item.get('atomic', False)


        # Resolve the full path for the item
        item_path = os.path.join(current_path, name)

        # Handle directory
        if item_type == 'd':  # Directory

            if not os.path.exists(item_path):
                os.makedirs(item_path, exist_ok=True)  # Create directory

            # If content is a dictionary, recursively process its items
            if isinstance(content, dict):
                #print(f"[INFO] Recursively processing the contents of directory: {name}")
                for key, value in content.items():
                    nested_item = {'name': key, 'type': 'd' if isinstance(value, dict) else 'f', 'content': value}
                    self.process_item(base, nested_item, current_path=item_path)

        # Handle file
        elif item_type == 'f':  # File type
            if content:  # If there is content to write into the file
                if atomic:  # Perform atomic write only if `atomic=True`
                    dir_name = os.path.dirname(item_path)  # Get the directory of the file's path
                    # Create a temporary file in the same directory as the target file
                    with tempfile.NamedTemporaryFile('w', delete=False, dir=dir_name) as temp_file:
                        temp_file_path = temp_file.name  # Save the path of the temporary file
                        if isinstance(content, (dict, list)):
                            # If the content is a dictionary or list, serialize it into JSON format
                            json.dump(content, temp_file, indent=4)
                        else:
                            # Write other types of content (e.g., strings) directly to the temporary file
                            temp_file.write(content)
                    # Atomically replace the target file with the temporary file
                    os.replace(temp_file_path, item_path)
                else:  # Perform a non-atomic write
                    with open(item_path, 'w', encoding="utf-8") as file:  # Open the target file for writing
                        if isinstance(content, (dict, list)):
                            # Serialize dicts/lists into JSON format before writing
                            json.dump(content, file, indent=4)
                        else:
                            # Write other types of content directly
                            file.write(content)
            else:  # If there is no content, create an empty file
                open(item_path, 'w', encoding="utf-8").close()

    def process_selection(self, base, selection):

        for item in selection:
            self.process_item(base, item)
