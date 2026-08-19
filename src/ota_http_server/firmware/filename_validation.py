from pathlib import Path


def validate_firmware_filename(filename: str) -> None:
    if filename in {"", ".", ".."}:
        raise ValueError("Firmware file must be a plain filename without directory traversal")

    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise ValueError("Firmware file must be a plain filename without path elements")
