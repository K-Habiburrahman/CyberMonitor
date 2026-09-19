import threading
from datetime import datetime

import etw
import etw.evntrace as evntrace
import psutil


# ============================================================
# WINDOWS KERNEL TRACE GUID
# ============================================================

KERNEL_GUID = etw.GUID(
    "{9E814AAD-3204-11D2-9A82-006008A86939}"
)


# ============================================================
# WINDOWS ETW MONITOR
# ============================================================

class WindowsETWMonitor:

    def __init__(self, event_callback):

        self.event_callback = event_callback

        self.lock = threading.Lock()

        # TID -> PID
        self.thread_to_pid = {}

        # PID -> process information
        self.process_table = {}

        self.capture = None

        # IMPORTANT:
        # Controls callback processing.
        self.running = False

        # Prevent multiple starts.
        self.started = False


    # ========================================================
    # PROCESS INFORMATION
    # ========================================================

    def remember_process(self, event):

        try:

            process_id = event.get("ProcessId")

            if not process_id:
                return

            pid = int(str(process_id), 0)

            parent_id = event.get("ParentId")

            if parent_id:

                parent_id = int(
                    str(parent_id),
                    0
                )

            process_info = {
                "pid": pid,
                "process_name": event.get(
                    "ImageFileName"
                ),
                "process_exe": event.get(
                    "CommandLine"
                ),
                "parent_pid": parent_id
            }

            with self.lock:

                self.process_table[pid] = process_info

        except Exception:
            pass


    # ========================================================
    # PROCESS LOOKUP
    # ========================================================

    def get_process(self, pid):

        if not pid:
            return None

        with self.lock:

            process = self.process_table.get(
                pid
            )

        if process:

            return process.copy()

        # ----------------------------------------------------
        # FALLBACK TO PSUTIL
        # ----------------------------------------------------

        try:

            proc = psutil.Process(pid)

            try:
                name = proc.name()
            except Exception:
                name = None

            try:
                exe = proc.exe()
            except Exception:
                exe = None

            try:
                parent = proc.parent()
            except Exception:
                parent = None

            return {
                "pid": pid,
                "process_name": name,
                "process_exe": exe,
                "parent_pid": (
                    parent.pid
                    if parent
                    else None
                )
            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            return None


    # ========================================================
    # ETW EVENT CALLBACK
    # ========================================================

    def handle_event(self, event):

        # IMPORTANT:
        # Ignore every event after stop() is requested.

        if not self.running:
            return

        try:

            if not isinstance(event, tuple):
                return

            if len(event) != 2:
                return

            _, data = event

            if not isinstance(data, dict):
                return

            task_name = data.get(
                "Task Name"
            )

            header = data.get(
                "EventHeader",
                {}
            )

            if not isinstance(header, dict):
                header = {}

            tid = header.get(
                "ThreadId"
            )

            header_pid = header.get(
                "ProcessId"
            )


            # =================================================
            # PROCESS EVENT
            # =================================================

            if task_name == "PROCESS":

                self.remember_process(data)

                pid_value = data.get(
                    "ProcessId"
                )

                try:

                    pid = int(
                        str(pid_value),
                        0
                    )

                except Exception:

                    pid = None

                if pid and tid:

                    with self.lock:

                        self.thread_to_pid[
                            int(tid)
                        ] = pid

                return


            # =================================================
            # THREAD EVENT
            # =================================================

            if task_name == "THREAD":

                thread_pid = (
                    data.get("ProcessId")
                    or header_pid
                )

                try:

                    thread_pid = int(
                        str(thread_pid),
                        0
                    )

                except Exception:

                    thread_pid = None

                if tid and thread_pid:

                    with self.lock:

                        self.thread_to_pid[
                            int(tid)
                        ] = thread_pid

                return


            # =================================================
            # FILE EVENT
            # =================================================

            if "FILE" not in str(
                task_name
            ).upper():

                return


            # =================================================
            # DETERMINE PID
            # =================================================

            pid = None

            if tid:

                with self.lock:

                    pid = self.thread_to_pid.get(
                        int(tid)
                    )

            if not pid:

                pid = header_pid

            try:

                if pid:

                    pid = int(
                        str(pid),
                        0
                    )

            except Exception:

                pid = None


            # =================================================
            # PROCESS ATTRIBUTION
            # =================================================

            process = self.get_process(
                pid
            )

            process_name = None
            process_exe = None
            parent_pid = None

            if process:

                process_name = process.get(
                    "process_name"
                )

                process_exe = process.get(
                    "process_exe"
                )

                parent_pid = process.get(
                    "parent_pid"
                )


            # =================================================
            # EXTRACT FILE PATH
            # =================================================

            path = None

            possible_path_fields = [
                "FileName",
                "FileNameRundown",
                "OpenPath",
                "Name",
                "Path"
            ]

            for field in possible_path_fields:

                value = data.get(field)

                if isinstance(value, str):

                    if (
                        "\\" in value
                        or "/" in value
                    ):

                        path = value
                        break


            # =================================================
            # NORMALIZED EVENT
            # =================================================

            normalized = {

                "type": task_name,

                "path": path,

                "timestamp": (
                    datetime.now().isoformat()
                ),

                "pid": pid,

                "process_name": process_name,

                "process_exe": process_exe,

                "parent_pid": parent_pid,

                "source": "ETW",

                "raw_event": data
            }


            # =================================================
            # CONSOLE OUTPUT
            # =================================================

            print()

            print("=" * 80)

            print(
                "[CYBERMONITOR FILE EVENT]"
            )

            print("=" * 80)

            print(
                "TYPE         :",
                normalized["type"]
            )

            print(
                "PATH         :",
                normalized["path"]
            )

            print(
                "PID          :",
                normalized["pid"]
            )

            print(
                "PROCESS      :",
                normalized["process_name"]
            )

            print(
                "PROCESS EXE  :",
                normalized["process_exe"]
            )

            print(
                "PARENT PID   :",
                normalized["parent_pid"]
            )

            print(
                "TID          :",
                tid
            )

            print(
                "TIMESTAMP    :",
                normalized["timestamp"]
            )

            print("=" * 80)


            # =================================================
            # SEND TO CYBERMONITOR
            # =================================================

            if (
                self.running
                and self.event_callback
            ):

                self.event_callback(
                    normalized
                )


        except Exception as error:

            if self.running:

                print(
                    "[ETW] Callback error:",
                    error
                )


    # ========================================================
    # START
    # ========================================================

    def start(self):

        if self.started:

            print(
                "[ETW] Monitor already started."
            )

            return


        print(
            "[ETW] Starting Windows Kernel Logger..."
        )


        # ====================================================
        # KERNEL FLAGS
        # ====================================================

        kernel_flags = (

            evntrace.EVENT_TRACE_FLAG_PROCESS

            | evntrace.EVENT_TRACE_FLAG_THREAD

            | evntrace.EVENT_TRACE_FLAG_FILE_IO

            | evntrace.EVENT_TRACE_FLAG_FILE_IO_INIT
        )


        # ====================================================
        # PROVIDER
        # ====================================================

        provider = etw.ProviderInfo(

            "Windows Kernel Trace",

            KERNEL_GUID,

            level=4,

            any_keywords=kernel_flags
        )


        # ====================================================
        # CREATE ETW CAPTURE
        # ====================================================

        self.capture = etw.ETW(

            session_name="NT Kernel Logger",

            providers=[
                provider
            ],

            event_callback=(
                self.handle_event
            ),

            callback_wait_time=0.01
        )


        # ====================================================
        # STATE FIRST
        # ====================================================

        self.running = True

        self.started = True


        # ====================================================
        # START CAPTURE
        # ====================================================

        try:

            self.capture.start()

        except Exception:

            self.running = False
            self.started = False
            self.capture = None

            raise


        print(
            "[ETW] Windows ETW monitor started."
        )

        print(
            "[ETW] Process + Thread + File I/O monitoring active."
        )


    # ========================================================
    # STOP
    # ========================================================

    def stop(self):

        if not self.started:

            return


        print(
            "[ETW] Stopping ETW..."
        )


        # ====================================================
        # STOP CALLBACK PROCESSING FIRST
        # ====================================================

        self.running = False


        # ====================================================
        # STOP ETW CAPTURE
        # ====================================================

        capture = self.capture

        self.capture = None

        if capture:

            try:

                capture.stop()

            except Exception as error:

                print(
                    "[ETW] Stop error:",
                    error
                )


        # ====================================================
        # CLEAR STATE
        # ====================================================

        with self.lock:

            self.thread_to_pid.clear()

            self.process_table.clear()


        self.started = False


        print(
            "[ETW] Windows ETW monitor stopped."
        )


# ============================================================
# PUBLIC API
# ============================================================

def start_windows_etw(event_callback):

    monitor = WindowsETWMonitor(
        event_callback
    )

    monitor.start()

    return monitor
