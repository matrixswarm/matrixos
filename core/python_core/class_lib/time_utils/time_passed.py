from datetime import datetime
import traceback
import sys

class TimePassed:
    @staticmethod
    def get_time_passed(timestamp, precise=False):
        """
        Calculates the time in seconds (or microseconds, if precise) that has passed since the given timestamp.

        :param timestamp: A string representing the start time in the format "YYYYMMDDHHMMSS..." (microseconds optional).
        :param precise: A boolean indicating whether to include microseconds in the comparison (default is False).
        :return: The number of seconds passed as a floating point (precise) or integer, or None if the timestamp is invalid.
        """
        try:
            if precise:
                # Try parsing all characters of "YYYYMMDDHHMMSSffffff" (supports microseconds).
                start_time = datetime.strptime(timestamp, "%Y%m%d%H%M%S%f")
            else:
                # Parse only the first 14 characters for "YYYYMMDDHHMMSS".
                start_time = datetime.strptime(timestamp[:14], "%Y%m%d%H%M%S")

            # Get the current time
            current_time = datetime.now()

            # Calculate time difference
            time_difference = (current_time - start_time).total_seconds()

            return time_difference

        except Exception as e:

            # Get information about the exception
            tb = traceback.format_exc()


            # If the timestamp is invalid, return None
            print(f"[TimePassed][ERROR] Invalid timestamp format. Please provide a valid timestamp {e}.")
            print(f"[TimePassed][ERROR] Full traceback:\n{tb}")

            return None

