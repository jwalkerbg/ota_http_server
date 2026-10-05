import argparse
import json
import logging
import sys
import uuid

import requests
import paho.mqtt.client as mqtt


# ============================================================
# Configuration
# ============================================================

BASE_URL = "https://okto7.com:8070"

USERNAME = "imc"
PASSWORD = "azsxdcfv"

OTA_EXPIRES_SECONDS = 1800

OUTPUT_FILE = "firmware.bin"

# MQTT defaults
MQTT_BROKER = "broker.emqx.io"
MQTT_PORT = 1883
MQTT_CID = 23051
MQTT_QOS = 1


# ============================================================
# HTTP helpers
# ============================================================

def login(session):
    url = f"{BASE_URL}/api/v1/auth/login"

    response = session.post(
        url,
        json={
            "username": USERNAME,
            "password": PASSWORD,
        },
    )

    response.raise_for_status()

    data = response.json()

    try:
        return data["access_token"]
    except KeyError:
        raise RuntimeError(f"Login response does not contain access_token: {data}")


def request_ota_token(
    session,
    user_jwt,
    device_id,
    project,
    current_vs,
    download_vs,
):
    url = f"{BASE_URL}/api/v1/auth/ota"

    headers = {
        "Authorization": f"Bearer {user_jwt}",
        "Content-Type": "application/json",
    }

    payload = {
        "device_id": device_id,
        "project": project,
        "current_vs": current_vs,
        "download_vs": download_vs,
        "expires_seconds": OTA_EXPIRES_SECONDS,
    }

    response = session.post(
        url,
        headers=headers,
        json=payload,
    )

    response.raise_for_status()

    data = response.json()

    try:
        return data["token"]
    except KeyError:
        raise RuntimeError(f"OTA response does not contain token: {data}")


def download_firmware(session, ota_jwt, output_file, verify):
    url = f"{BASE_URL}/firmware"

    headers = {
        "Authorization": f"Bearer {ota_jwt}",
    }

    response = session.get(
        url,
        headers=headers,
        stream=True,
        verify=verify,
    )

    response.raise_for_status()

    with open(output_file, "wb") as f:
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)

    return response


# ============================================================
# MQTT
# ============================================================

def send_mqtt_ota_command(
    ota_jwt,
    device_id,
    client_uuid,
    broker,
    port,
    qos,
    verbose=False,
):
    topic = f"@/{device_id}/CMD/JSON"

    payload = {
        "cid": MQTT_CID,
        "client": client_uuid,
        "command": "OV",
        "data": {
            "v0": ota_jwt,
        },
    }

    payload_json = json.dumps(payload)

    if verbose:
        print()
        print("MQTT")
        print(f"Broker: {broker}:{port}")
        print(f"Topic:  {topic}")
        print("Payload:")
        print(
            json.dumps(
                {
                    **payload,
                    "data": {
                        "v0": "<redacted>",
                    },
                },
                indent=2,
            )
        )

    mqtt_client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=str(uuid.uuid4()),
    )

    try:
        if verbose:
            print(f"Connecting to MQTT broker {broker}:{port}...")

        mqtt_client.connect(
            broker,
            port,
            keepalive=30,
        )

        mqtt_client.loop_start()

        info = mqtt_client.publish(
            topic,
            payload_json,
            qos=qos,
            retain=False,
        )

        info.wait_for_publish()

        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(
                f"MQTT publish failed, return code: {info.rc}"
            )

        if verbose:
            print("MQTT command published successfully.")

    finally:
        mqtt_client.loop_stop()
        mqtt_client.disconnect()


# ============================================================
# Verbose HTTP logging
# ============================================================

def setup_http_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    # Prevent requests/urllib3 from dumping Authorization headers.
    logging.getLogger("urllib3").setLevel(logging.DEBUG)


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Request an OTA JWT and either download firmware or send an MQTT OTA command."
    )

    parser.add_argument(
        "device_id",
        help="ESP32 device UUID",
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
        help="Firmware version to download/install",
    )

    parser.add_argument(
        "--cert",
        help="CA PEM file used to verify HTTPS server",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    # --------------------------------------------------------
    # MQTT options
    # --------------------------------------------------------

    parser.add_argument(
        "--mqtt",
        action="store_true",
        help="Send OTA command to ESP32 via MQTT instead of downloading firmware",
    )

    parser.add_argument(
        "--mqtt-broker",
        default=MQTT_BROKER,
        help=f"MQTT broker hostname (default: {MQTT_BROKER})",
    )

    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=MQTT_PORT,
        help=f"MQTT broker port (default: {MQTT_PORT})",
    )

    parser.add_argument(
        "--mqtt-client",
        help="Client UUID placed in MQTT payload",
    )

    parser.add_argument(
        "--mqtt-qos",
        type=int,
        choices=[0, 1, 2],
        default=MQTT_QOS,
        help=f"MQTT QoS level (default: {MQTT_QOS})",
    )

    args = parser.parse_args()

    if args.verbose:
        setup_http_logging()

    # --mqtt-client is required when MQTT mode is selected.
    if args.mqtt and not args.mqtt_client:
        parser.error(
            "--mqtt-client is required when --mqtt is specified"
        )

    verify = args.cert if args.cert else True

    session = requests.Session()

    try:
        # ----------------------------------------------------
        # 1. Login
        # ----------------------------------------------------

        print("Logging in...")

        user_jwt = login(session)

        if args.verbose:
            print("USER_JWT received.")

        # ----------------------------------------------------
        # 2. Request OTA JWT
        # ----------------------------------------------------

        print("Requesting OTA authorization...")

        ota_jwt = request_ota_token(
            session=session,
            user_jwt=user_jwt,
            device_id=args.device_id,
            project=args.project,
            current_vs=args.current_vs,
            download_vs=args.download_vs,
        )

        if args.verbose:
            print("OTA_JWT received.")

        # ----------------------------------------------------
        # 3. Either MQTT command OR HTTP firmware download
        # ----------------------------------------------------

        if args.mqtt:
            print("Sending OTA command via MQTT...")

            send_mqtt_ota_command(
                ota_jwt=ota_jwt,
                device_id=args.device_id,
                client_uuid=args.mqtt_client,
                broker=args.mqtt_broker,
                port=args.mqtt_port,
                qos=args.mqtt_qos,
                verbose=args.verbose,
            )

            print("OTA command sent successfully.")

        else:
            print("Downloading firmware...")

            response = download_firmware(
                session=session,
                ota_jwt=ota_jwt,
                output_file=OUTPUT_FILE,
                verify=verify,
            )

            print(
                f"Firmware downloaded successfully: {OUTPUT_FILE}"
            )

            if args.verbose:
                print(
                    f"HTTP status: {response.status_code}"
                )

                content_length = response.headers.get(
                    "Content-Length"
                )

                if content_length:
                    print(
                        f"Content-Length: {content_length}"
                    )

                content_disposition = response.headers.get(
                    "Content-Disposition"
                )

                if content_disposition:
                    print(
                        f"Content-Disposition: {content_disposition}"
                    )

    except requests.HTTPError as e:
        print(
            f"HTTP error: {e}",
            file=sys.stderr,
        )

        if e.response is not None:
            try:
                print(
                    e.response.text,
                    file=sys.stderr,
                )
            except Exception:
                pass

        sys.exit(1)

    except Exception as e:
        print(
            f"Error: {e}",
            file=sys.stderr,
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
    