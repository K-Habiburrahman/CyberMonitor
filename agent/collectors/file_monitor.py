import os
from datetime import datetime


MONITORED_DIRECTORIES = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/AppData/Local/Temp"),
]


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".scr",
}


def get_file_snapshot():
    """
    Create a snapshot of files in monitored directories.
    """

    snapshot = {}

    for directory in MONITORED_DIRECTORIES:

        if not os.path.exists(directory):
            continue

        for root, dirs, files in os.walk(directory):

            for filename in files:

                path = os.path.abspath(
                    os.path.join(root, filename)
                )

                try:
                    stat = os.stat(path)

                    snapshot[path] = {
                        "size": stat.st_size,
                        "modified": stat.st_mtime,

                        # File identity.
                        # Helps detect renames.
                        "file_id": stat.st_ino,
                    }

                except (PermissionError, FileNotFoundError):
                    continue

    return snapshot


def detect_file_changes(previous_snapshot, current_snapshot):
    """
    Compare two snapshots and detect:

    - CREATED
    - DELETED
    - MODIFIED
    - RENAMED

    A rename is detected when a deleted file and a newly
    created file have matching size and modification time.
    """

    events = []

    # ----------------------------------------
    # Find created and deleted files
    # ----------------------------------------

    created_paths = [
        path
        for path in current_snapshot
        if path not in previous_snapshot
    ]

    deleted_paths = [
        path
        for path in previous_snapshot
        if path not in current_snapshot
    ]

    # ----------------------------------------
    # Detect RENAMED files
    # ----------------------------------------

    renamed_created = set()
    renamed_deleted = set()

    for old_path in deleted_paths:

        old_info = previous_snapshot[old_path]

        for new_path in created_paths:

            new_info = current_snapshot[new_path]

            # Same file characteristics = likely rename
            if (
                old_info["size"] == new_info["size"]
                and old_info["modified"] == new_info["modified"]
            ):
                events.append({
                    "type": "RENAMED",
                    "old_path": old_path,
                    "path": new_path,
                    "filename": os.path.basename(new_path),
                    "old_filename": os.path.basename(old_path),
                    "extension": os.path.splitext(new_path)[1].lower(),
                    "suspicious": (
                        os.path.splitext(new_path)[1].lower()
                        in SUSPICIOUS_EXTENSIONS
                    ),
                    "timestamp": datetime.now().isoformat(),
                })

                renamed_deleted.add(old_path)
                renamed_created.add(new_path)

                break

    # ----------------------------------------
    # CREATED
    # ----------------------------------------

    for path in created_paths:

        if path in renamed_created:
            continue

        extension = os.path.splitext(path)[1].lower()

        events.append({
            "type": "CREATED",
            "path": path,
            "filename": os.path.basename(path),
            "extension": extension,
            "suspicious": extension in SUSPICIOUS_EXTENSIONS,
            "timestamp": datetime.now().isoformat(),
        })

    # ----------------------------------------
    # DELETED
    # ----------------------------------------

    for path in deleted_paths:

        if path in renamed_deleted:
            continue

        extension = os.path.splitext(path)[1].lower()

        events.append({
            "type": "DELETED",
            "path": path,
            "filename": os.path.basename(path),
            "extension": extension,
            "suspicious": False,
            "timestamp": datetime.now().isoformat(),
        })

    # ----------------------------------------
    # MODIFIED
    # ----------------------------------------

    for path in current_snapshot:

        if path in previous_snapshot:

            old = previous_snapshot[path]
            new = current_snapshot[path]

            if (
                old["size"] != new["size"]
                or old["modified"] != new["modified"]
            ):

                extension = os.path.splitext(path)[1].lower()

                events.append({
                    "type": "MODIFIED",
                    "path": path,
                    "filename": os.path.basename(path),
                    "extension": extension,
                    "suspicious": (
                        extension in SUSPICIOUS_EXTENSIONS
                    ),
                    "timestamp": datetime.now().isoformat(),
                })

    return events