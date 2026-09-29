import argparse
import sys

import requests


BASE_URL = "https://example.com:8070"

USERNAME = "imc"
PASSWORD = "azsxdcfv"

OTA_EXPIRES_SECONDS = 1800
OUTPUT_FILE = "firmware.bin"


def print_request(response, show_body=False):
    """Print request and response information for verbose mode."""

    request = response.request

    print()
    print("============================================================")
    print("REQUEST")
    print("============================================================")
    print(f"{request.method} {request.url}")

    print("\nRequest headers:")
    for name, value in request.headers.items():
        # Never print credentials/tokens in clear text.
        if name.lower() == "authorization":
            value = "Bearer <redacted>"

        print(f"  {name}: {value}")

    if request.body:
        body = request.body

        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        print("\nRequest body:")
        print(body)

    print()
    print("============================================================")
    print("RESPONSE")
    print("============================================================")
    print(f"HTTP {response.status_code} {response.reason}")

    print("\nResponse headers:")
    for name, value in response.headers.items():
        print(f"  {name}: {value}")

    if show_body:
        print("\nResponse body:")
        print(response.text)

    print("============================================================")
    print()


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

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print HTTP requests and responses",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------
    # Configure certificate verification
    # ------------------------------------------------------------
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

        if args.verbose:
            print_request(response, show_body=True)

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

        if args.verbose:
            print_request(response, show_body=True)

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

        if args.verbose:
            # Do not print the binary response body.
            print_request(response, show_body=False)

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
