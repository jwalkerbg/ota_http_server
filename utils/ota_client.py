import argparse
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
    parser = argparse.ArgumentParser(
        description="Authenticate and download OTA firmware."
    )

    parser.add_argument(
        "device_id",
        help="Device UUID",
    )

    parser.add_argument(
        "project",
        help="Project name",
    )

    parser.add_argument(
        "current_vs",
        help="Current firmware version",
    )

    parser.add_argument(
        "download_vs",
        help="Firmware version to download",
    )

    parser.add_argument(
        "--cert",
        metavar="FILE",
        help="CA certificate PEM file used to verify the HTTPS server",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------
    # Configure certificate verification
    # ------------------------------------------------------------
    #
    # If --cert is specified, requests uses that certificate/CA
    # file to verify the HTTPS server.
    #
    # If --cert is not specified, requests uses its normal
    # certificate verification behavior.
    #
    verify = args.cert if args.cert else True

    # ------------------------------------------------------------
    # Create HTTP session
    # ------------------------------------------------------------
    session = requests.Session()

    try:
        # --------------------------------------------------------
        # 1. Login
        # --------------------------------------------------------
        print("Logging in...")

        response = session.post(
            f"{BASE_URL}/api/v1/auth/login",
            json={
                "username": USERNAME,
                "password": PASSWORD,
            },
            timeout=30,
            verify=verify,
        )

        response.raise_for_status()

        login_data = response.json()
        user_token = login_data["access_token"]

        print("Login OK")

        # --------------------------------------------------------
        # 2. Request OTA JWT
        # --------------------------------------------------------
        print("Requesting OTA authorization...")

        response = session.post(
            f"{BASE_URL}/api/v1/auth/ota",
            headers={
                "Authorization": f"Bearer {user_token}",
            },
            json={
                "device_id": args.device_id,
                "project": args.project,
                "current_vs": args.current_vs,
                "download_vs": args.download_vs,
                "expires_seconds": OTA_EXPIRES_SECONDS,
            },
            timeout=30,
            verify=verify,
        )

        response.raise_for_status()

        ota_data = response.json()
        ota_token = ota_data["token"]

        print("OTA authorization OK")
        print(f"Device: {args.device_id}")
        print(f"Project: {args.project}")
        print(f"Current firmware: {args.current_vs}")
        print(f"Download firmware: {args.download_vs}")

        # --------------------------------------------------------
        # 3. Download firmware
        # --------------------------------------------------------
        print("Downloading firmware...")

        response = session.get(
            f"{BASE_URL}/firmware",
            headers={
                "Authorization": f"Bearer {ota_token}",
            },
            stream=True,
            timeout=60,
            verify=verify,
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

    except requests.HTTPError as e:
        print(f"\nHTTP error: {e}")

        if e.response is not None:
            print(f"Server response: {e.response.text}")

        sys.exit(1)

    except requests.exceptions.SSLError as e:
        print("\nTLS/SSL certificate verification failed:")
        print(e)
        sys.exit(1)

    except requests.RequestException as e:
        print(f"\nConnection error: {e}")
        sys.exit(1)

    except KeyError as e:
        print(f"\nUnexpected server response. Missing field: {e}")
        sys.exit(1)

    finally:
        session.close()


if __name__ == "__main__":
    main()

