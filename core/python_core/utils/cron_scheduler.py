# matrixswarm/core/utils/cron_scheduler.py
import time
from datetime import datetime


class CronScheduler:
    """
    A simple cron-like scheduler that supports an optional seconds field.
    Expression format: [seconds] minute hour day_of_month month day_of_week
    """

    def __init__(self, expression: str):
        self.fields = expression.split()
        if len(self.fields) not in [5, 6]:
            raise ValueError("Invalid cron expression. Must have 5 or 6 fields.")
        self.has_seconds = len(self.fields) == 6

    def is_due(self, last_run_timestamp: float) -> bool:
        """
        Checks if the job is due to run based on the current time and the
        last execution time.
        """
        now = datetime.now()
        last_run_dt = datetime.fromtimestamp(last_run_timestamp)

        # Basic check to prevent running multiple times in the same second/minute
        if self.has_seconds:
            if int(time.time()) == int(last_run_timestamp):
                return False
        else:
            if now.minute == last_run_dt.minute and now.hour == last_run_dt.hour:
                return False

        # Map current time to the cron fields
        time_parts = [now.second, now.minute, now.hour, now.day, now.month, now.weekday()]
        if not self.has_seconds:
            time_parts.pop(0)  # Remove seconds if not used

        # Check each field against the expression
        for i, part in enumerate(self.fields):
            if not self._matches(time_parts[i], part):
                return False
        return True

    def _matches(self, value: int, expression: str) -> bool:
        """Checks if a single time value matches a cron field expression."""
        if expression == '*':
            return True

        for part in expression.split(','):
            # Handle ranges (e.g., 1-5)
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start <= value <= end:
                    return True
            # Handle steps (e.g., */15)
            elif '*/' in part:
                step = int(part.split('/')[1])
                if value % step == 0:
                    return True
            # Handle specific values
            elif int(part) == value:
                return True
        return False
