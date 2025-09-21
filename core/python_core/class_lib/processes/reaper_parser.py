import re
import json


class ReaperParser:
    """
    A sibling class to Reaper, designed to parse input strings into structured dictionaries
    while validating and normalizing components.
    """

    @staticmethod
    def parse_job_string(job_string):
        """
        Parses a single job string and validates/cleans it.
        Example: "bb:matrix:calendar-agent-1:google_calendar"
        """
        # Allowed characters for job string components (lowercase letters, numbers, _, -)
        allowed_chars_pattern = r"[a-z0-9_-]+"

        # Split the job string into components by ":"
        components = job_string.split(":")

        # Validate each component
        cleaned_components = [
            segment if re.fullmatch(allowed_chars_pattern, segment)
            else ""  # Replace invalid segments with an empty string
            for segment in components
        ]

        # Reassemble the cleaned job string
        cleaned_job_string = ":".join(cleaned_components)

        return cleaned_job_string

    @staticmethod
    def process_job_list(job_list):
        """
        Processes a list of job strings into a list of validated/cleaned job strings.
        """
        if not isinstance(job_list, list):
            raise ValueError("Expected a list of job strings!")

        # Process each job string in the list
        cleaned_jobs = [
            ReaperParser.parse_job_string(job_string)  # Parse each individual job string
            for job_string in job_list
        ]

        return cleaned_jobs

    @staticmethod
    def pretty_print(parsed_data):
        """
        Pretty print the data (list or dictionary) in a JSON format for better readability.
        """
        print(json.dumps(parsed_data, indent=4))


# Example usage
if __name__ == "__main__":
    # Example list of job strings
    job_list = [
        "bb:matrix:calendar-agent-1:google_calendar",
        "bb:bootloader:matrix:matrix",
        "invalid:%%%:example-job",
        "valid:job-string-1:example_test"
    ]

    # Process the list of job strings
    parser = ReaperParser()
    cleaned_job_list = parser.process_job_list(job_list)

    # Pretty print the cleaned job list
    parser.pretty_print(cleaned_job_list)
