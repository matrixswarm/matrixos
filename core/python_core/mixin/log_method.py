import inspect
import traceback
class LogMixin:

    def set_logger(self, log_fn):
        self._log_fn = log_fn

    def get_logger(self):
        return self._log_fn

    def log(self, msg="", error=None, block=None, level="INFO"):

        try:
            r=False
            if hasattr(self, "_log_fn") and callable(self._log_fn):
                r=True
            if r and self._log_fn:
                frame = inspect.currentframe()
                outer_frames = inspect.getouterframes(frame)

                def get_class_method(frame_info):
                    obj = frame_info.frame.f_locals.get('self', None)
                    cls = obj.__class__.__name__.upper() if obj else "GLOBAL"
                    method = frame_info.function.upper()
                    return f"{cls}:{method}"

                # Prepare chain
                chain = []

                # Start from the top matrix-level frame (usually 2 calls up, but we go 3 deep just in case)
                if len(outer_frames) > 3:
                    chain.append(get_class_method(outer_frames[3]))  # Top level (e.g. MATRIX)
                if len(outer_frames) > 2:
                    chain.append(get_class_method(outer_frames[2]))  # Mid level (caller of caller)
                if len(outer_frames) > 1:
                    chain.append(get_class_method(outer_frames[1]))  # Direct caller (inside self)
                    lineno = outer_frames[1].lineno
                else:
                    lineno = "XX"

                # Optional block
                if block:
                    chain.append(block.upper())

                # Compose log tail
                custom_tail = ''.join(f"[{c}]" for c in chain) + f"[L{lineno}]"

                # Fire it off
                self._log_fn(msg, error=error, custom_tail=custom_tail, level=level)
            else:
                print(f"[{level}] {msg}")
                if error:
                    print(f"[ERROR] {error}")
                    print(traceback.format_exc())
        except Exception as e:
            print(str(e))
            print(traceback.format_exc())