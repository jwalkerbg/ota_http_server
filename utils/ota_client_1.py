import sys

import requests


BASE_URL = "http://127.0.0.1:8071"

USERNAME = "imc"
PASSWORD = "azsxdcfv"

OTA_EXPIRES_SECONDS = 1800
OUTPUT_FILE = "firmware.bin"


def main():
    # ------------------------------------------------------------
    # Command-line arguments
    # ------------------------------------------------------------
    if len(sys.argv) != 5:
        print(
            "Usage:\n"
            "  python download_firmware.py "
            "<device_id> <project> <current_vs> <download_vs>\n\n"
            "Example:\n"
            "  python download_firmware.py "
            "e6f87d77-4216-4be1-ab83-b5fa6792b747 "
            "smart_air 01.21.01 01.23.01"
        )
        sys.exit(1)

    device_id = sys.argv[1]
    project = sys.argv[2]
    current_vs = sys.argv[3]
    download_vs = sys.argv[4]

    # ------------------------------------------------------------
    # 1. Login
    # ------------------------------------------------------------
    print("Logging in...")

    response = requests.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={
            "username": USERNAME,
            "password": PASSWORD,
        },
        timeout=30,
    )

    response.raise_for_status()

    login_data = response.json()
    user_token = login_data["access_token"]

    print("Login OK")

    # ------------------------------------------------------------
    # 2. Request OTA JWT
    # ------------------------------------------------------------
    print("Requesting OTA authorization...")

    response = requests.post(
        f"{BASE_URL}/api/v1/auth/ota",
        headers={
            "Authorization": f"Bearer {user_token}",
        },
        json={
            "device_id": device_id,
            "project": project,
            "current_vs": current_vs,
            "download_vs": download_vs,
            "expires_seconds": OTA_EXPIRES_SECONDS,
        },
        timeout=30,
    )

    response.raise_for_status()

    ota_data = response.json()
    ota_token = ota_data["token"]

    print("OTA authorization OK")
    print(f"Device: {device_id}")
    print(f"Project: {project}")
    print(f"Current firmware: {current_vs}")
    print(f"Download firmware: {download_vs}")

    # ------------------------------------------------------------
    # 3. Download firmware
    # ------------------------------------------------------------
    print("Downloading firmware...")

    response = requests.get(
        f"{BASE_URL}/firmware",
        headers={
            "Authorization": f"Bearer {ota_token}",
        },
        stream=True,
        timeout=60,
    )

    response.raise_for_status()

    total_size = int(response.headers.get("Content-Length", 0))
    downloaded = 0

    with open(OUTPUT_FILE, "wb") as f:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue

            f.write(chunk)
            downloaded += len(chunk)

            if total_size:
                percent = downloaded * 100 / total_size
                print(
                    f"\rDownloaded: {downloaded:,} / "
                    f"{total_size:,} bytes ({percent:.1f}%)",
                    end="",
                )

    print()
    print(f"Firmware saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    try:
        main()

    except requests.HTTPError as e:
        print(f"\nHTTP error: {e}")

        if e.response is not None:
            print(f"Server response: {e.response.text}")

        sys.exit(1)

    except requests.RequestException as e:
        print(f"\nConnection error: {e}")
        sys.exit(1)

    except KeyError as e:
        print(f"\nUnexpected server response. Missing field: {e}")
        sys.exit(1)
