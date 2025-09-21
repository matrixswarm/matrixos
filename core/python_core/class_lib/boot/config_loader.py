import os
import importlib.util


class ConfigLoader:
    @staticmethod
    def load_configuration(file_path):
        """
        Dynamically loads the entire configuration (matrix_directive) from a given Python file.
        :param file_path: Full path to the configuration file.
        :return: The matrix_directive dictionary if found, or raises an error.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        # Dynamically import the file
        spec = importlib.util.spec_from_file_location("module", file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Ensure the file has a `matrix_directive` attribute
        if not hasattr(module, "matrix_directive"):
            raise AttributeError(
                f"The file '{os.path.basename(file_path)}' does not contain a 'matrix_directive' attribute!"
            )

        # Return the directive as a whole
        return module.matrix_directive
