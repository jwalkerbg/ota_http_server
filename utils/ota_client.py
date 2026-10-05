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

# How long to wait for each ESP32 response
MQTT_TIMEOUT = 120


# ============================================================
# HTTP helpers
# ============================================================

def login(session, verify):
    url = f"{BASE_URL}/api/v1/auth/login"

    response = session.post(
        url,
        json={
            "username": USERNAME,
            "password": PASSWORD,
        },
        verify=verify,
    )

    response.raise_for_status()

    data = response.json()

    try:
        return data["access_token"]
    except KeyError:
        raise RuntimeError(
            f"Login response does not contain access_token: {data}"
        )


def request_ota_token(
    session,
    user_jwt,
    device_id,
    project,
    current_vs,
    download_vs,
    verify,
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
        verify=verify,
    )

    response.raise_for_status()

    data = response.json()

    try:
        return data["token"]
    except KeyError:
        raise RuntimeError(
            f"OTA response does not contain token: {data}"
        )


def download_firmware(
    session,
    ota_jwt,
    output_file,
    verify,
):
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
        for chunk in response.iter_content(
            chunk_size=1024 * 1024
        ):
            if chunk:
                f.write(chunk)

    return response


# ============================================================
# MQTT OTA
# ============================================================

class MqttOtaHandler:
    def __init__(
        self,
        device_id,
        expected_cid,
        timeout,
        verbose=False,
    ):
        self.device_id = device_id
        self.expected_cid = expected_cid
        self.timeout = timeout
        self.verbose = verbose

        self.response_received = False
        self.ota_result_received = False

        self.response_payload = None
        self.ota_result_payload = None

        self.response_error = None
        self.ota_result = None

    @property
    def response_topic(self):
        return f"@/{self.device_id}/RSP/JSON"

    @property
    def unsolicited_topic(self):
        return f"@/{self.device_id}/USL/JSON"

    def on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code != 0:
            self.response_error = (
                f"MQTT connection failed: {reason_code}"
            )
            return

        if self.verbose:
            print("MQTT connected.")

        result1, _ = client.subscribe(
            self.response_topic,
            qos=MQTT_QOS,
        )

        result2, _ = client.subscribe(
            self.unsolicited_topic,
            qos=MQTT_QOS,
        )

        if result1 != mqtt.MQTT_ERR_SUCCESS:
            self.response_error = (
                f"Failed to subscribe to {self.response_topic}: "
                f"{result1}"
            )
            return

        if result2 != mqtt.MQTT_ERR_SUCCESS:
            self.response_error = (
                f"Failed to subscribe to {self.unsolicited_topic}: "
                f"{result2}"
            )
            return

        if self.verbose:
            print(f"Subscribed: {self.response_topic}")
            print(f"Subscribed: {self.unsolicited_topic}")

    def on_message(self, client, userdata, message):
        try:
            payload_text = message.payload.decode("utf-8")

            if self.verbose:
                print()
                print("MQTT message received:")
                print(f"Topic:   {message.topic}")
                print(f"Payload: {payload_text}")

            payload = json.loads(payload_text)

        except Exception as e:
            if self.verbose:
                print(
                    f"Could not decode MQTT message: {e}"
                )
            return

        # ----------------------------------------------------
        # Command acknowledgement
        # ----------------------------------------------------

        if message.topic == self.response_topic:

            cid = payload.get("cid")
            response = payload.get("response")

            # Ignore acknowledgements belonging to another command.
            if cid != self.expected_cid:
                if self.verbose:
                    print(
                        f"Ignoring RSP with cid={cid}, "
                        f"expected {self.expected_cid}"
                    )
                return

            self.response_payload = payload
            self.response_received = True

            if response != "OK":
                self.response_error = (
                    f"ESP32 rejected OTA command: {response}"
                )

            if self.verbose:
                print(
                    f"OTA command acknowledgement received "
                    f"(cid={cid}, response={response})."
                )

            return

        # ----------------------------------------------------
        # Unsolicited OTA result
        # ----------------------------------------------------

        if message.topic == self.unsolicited_topic:

            message_type = payload.get("type")
            message_src = payload.get("src")

            # We are interested specifically in:
            #
            # {
            #   "type": "finished",
            #   ...
            #   "data": {
            #       "result": 1
            #   }
            # }
            #
            if message_type != "finished" or message_src != "ota":
                if self.verbose:
                    print(
                        f"Ignoring USL message with type="
                        f"{message_type}"
                        f"and source="
                        f"{message_src}"
                    )
                return

            data = payload.get("data", {})
            result = data.get("result")

            self.ota_result_payload = payload
            self.ota_result = result
            self.ota_result_received = True

            if self.verbose:
                print(
                    f"OTA result received: result={result}"
                )


def send_mqtt_ota_command(
    ota_jwt,
    device_id,
    client_uuid,
    broker,
    port,
    qos,
    timeout,
    verbose=False,
):
    command_topic = f"@/{device_id}/CMD/JSON"

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
        print(f"Command topic: {command_topic}")
        print(f"Response topic: @{device_id}/RSP/JSON")
        print(f"Unsolicited topic: @{device_id}/USL/JSON")
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

    handler = MqttOtaHandler(
        device_id=device_id,
        expected_cid=MQTT_CID,
        timeout=timeout,
        verbose=verbose,
    )

    mqtt_client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=str(uuid.uuid4()),
    )

    mqtt_client.on_connect = handler.on_connect
    mqtt_client.on_message = handler.on_message

    try:
        # ----------------------------------------------------
        # Connect
        # ----------------------------------------------------

        if verbose:
            print(
                f"Connecting to MQTT broker "
                f"{broker}:{port}..."
            )

        mqtt_client.connect(
            broker,
            port,
            keepalive=30,
        )

        # ----------------------------------------------------
        # Start MQTT network processing.
        #
        # on_connect will subscribe to both topics.
        # ----------------------------------------------------

        mqtt_client.loop_start()

        # Give on_connect/subscriptions a moment to complete.
        # loop_start() runs asynchronously.
        import time

        subscription_wait = 0.1
        deadline = time.monotonic() + timeout

        while (
            handler.response_error is None
            and time.monotonic() < deadline
        ):
            # paho doesn't expose a simple "subscriptions ready"
            # flag, so wait briefly for on_connect to execute.
            if mqtt_client.is_connected():
                break

            time.sleep(subscription_wait)

        if not mqtt_client.is_connected():
            raise RuntimeError(
                "MQTT connection was not established."
            )

        # ----------------------------------------------------
        # Make sure on_connect has had time to subscribe.
        # ----------------------------------------------------

        time.sleep(0.2)

        if handler.response_error:
            raise RuntimeError(handler.response_error)

        # ----------------------------------------------------
        # Publish OTA command
        # ----------------------------------------------------

        if verbose:
            print("Publishing OTA command...")

        info = mqtt_client.publish(
            command_topic,
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
            print("OTA command published successfully.")

        # ----------------------------------------------------
        # Wait for command acknowledgement
        # ----------------------------------------------------

        if verbose:
            print(
                f"Waiting up to {timeout} seconds "
                f"for command acknowledgement..."
            )

        deadline = time.monotonic() + timeout

        while (
            not handler.response_received
            and handler.response_error is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.1)

        if handler.response_error:
            raise RuntimeError(handler.response_error)

        if not handler.response_received:
            raise TimeoutError(
                "Timeout waiting for ESP32 OTA command "
                "acknowledgement."
            )

        print("ESP32 acknowledged OTA command.")

        # ----------------------------------------------------
        # Wait for OTA finished notification
        # ----------------------------------------------------

        if verbose:
            print(
                f"Waiting up to {timeout} seconds "
                f"for OTA result..."
            )

        deadline = time.monotonic() + timeout

        while (
            not handler.ota_result_received
            and time.monotonic() < deadline
        ):
            time.sleep(0.1)

        if not handler.ota_result_received:
            raise TimeoutError(
                "Timeout waiting for ESP32 OTA result."
            )

        # ----------------------------------------------------
        # Interpret OTA result
        # ----------------------------------------------------

        if handler.ota_result == 1:
            print("ESP32 OTA completed successfully.")
            return True

        print(
            f"ESP32 OTA failed. "
            f"Result code: {handler.ota_result}"
        )

        return False

    finally:
        mqtt_client.loop_stop()

        try:
            mqtt_client.disconnect()
        except Exception:
            pass


# ============================================================
# Verbose HTTP logging
# ============================================================

def setup_http_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    logging.getLogger("urllib3").setLevel(logging.DEBUG)


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Request an OTA JWT and either download firmware "
            "or send an MQTT OTA command."
        )
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
        help=(
            "Send OTA command to ESP32 via MQTT "
            "instead of downloading firmware"
        ),
    )

    parser.add_argument(
        "--mqtt-broker",
        default=MQTT_BROKER,
        help=(
            f"MQTT broker hostname "
            f"(default: {MQTT_BROKER})"
        ),
    )

    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=MQTT_PORT,
        help=(
            f"MQTT broker port "
            f"(default: {MQTT_PORT})"
        ),
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
        help=(
            f"MQTT QoS level "
            f"(default: {MQTT_QOS})"
        ),
    )

    parser.add_argument(
        "--mqtt-timeout",
        type=int,
        default=MQTT_TIMEOUT,
        help=(
            f"Timeout in seconds for each ESP32 MQTT response "
            f"(default: {MQTT_TIMEOUT})"
        ),
    )

    args = parser.parse_args()

    if args.verbose:
        setup_http_logging()

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

        user_jwt = login(
            session,
            verify,
        )

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
            verify=verify,
        )

        if args.verbose:
            print("OTA_JWT received.")

        # ----------------------------------------------------
        # 3. MQTT OR HTTP
        # ----------------------------------------------------

        if args.mqtt:

            print("Sending OTA command via MQTT...")

            success = send_mqtt_ota_command(
                ota_jwt=ota_jwt,
                device_id=args.device_id,
                client_uuid=args.mqtt_client,
                broker=args.mqtt_broker,
                port=args.mqtt_port,
                qos=args.mqtt_qos,
                timeout=args.mqtt_timeout,
                verbose=args.verbose,
            )

            if not success:
                sys.exit(1)

        else:

            print("Downloading firmware...")

            response = download_firmware(
                session=session,
                ota_jwt=ota_jwt,
                output_file=OUTPUT_FILE,
                verify=verify,
            )

            print(
                f"Firmware downloaded successfully: "
                f"{OUTPUT_FILE}"
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
                        f"Content-Disposition: "
                        f"{content_disposition}"
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

    except TimeoutError as e:

        print(
            f"Timeout: {e}",
            file=sys.stderr,
        )

        sys.exit(1)

    except Exception as e:

        print(
            f"Error: {e}",
            file=sys.stderr,
        )

        sys.exit(1)


if __name__ == "__main__":
    main()