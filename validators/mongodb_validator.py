from __future__ import annotations

import random
import socket
import struct
from typing import Any, Dict, Optional, Tuple

from .common import ValidationResult, tcp_probe


OP_REPLY = 1
OP_MSG = 2013
MAX_MESSAGE_SIZE = 16 * 1024 * 1024


class MongoWireError(Exception):
    """
    Raised when a response does not match the expected MongoDB wire format.
    """


def _encode_cstring(value: str) -> bytes:
    return value.encode("utf-8") + b"\x00"


def _encode_bson_document(document: Dict[str, Any]) -> bytes:
    elements = []

    for key, value in document.items():
        encoded_key = _encode_cstring(key)

        if isinstance(value, bool):
            elements.append(
                b"\x08" + encoded_key + (b"\x01" if value else b"\x00")
            )

        elif isinstance(value, int):
            if -(2 ** 31) <= value <= (2 ** 31 - 1):
                elements.append(
                    b"\x10" + encoded_key + struct.pack("<i", value)
                )
            else:
                elements.append(
                    b"\x12" + encoded_key + struct.pack("<q", value)
                )

        elif isinstance(value, str):
            encoded_value = value.encode("utf-8")
            elements.append(
                b"\x02"
                + encoded_key
                + struct.pack("<i", len(encoded_value) + 1)
                + encoded_value
                + b"\x00"
            )

        else:
            raise TypeError(
                f"Unsupported BSON value type for {key}: {type(value).__name__}"
            )

    body = b"".join(elements) + b"\x00"

    return struct.pack("<i", len(body) + 4) + body


def _build_hello_request(request_id: int) -> bytes:
    """
    Create a minimal read-only MongoDB OP_MSG hello command.
    """

    document = _encode_bson_document(
        {
            "hello": 1,
            "$db": "admin",
        }
    )

    body = (
        struct.pack("<I", 0)  # OP_MSG flag bits
        + b"\x00"             # Kind 0 body section
        + document
    )

    header = struct.pack(
        "<iiii",
        16 + len(body),
        request_id,
        0,
        OP_MSG,
    )

    return header + body


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size

    while remaining > 0:
        chunk = sock.recv(remaining)

        if not chunk:
            raise MongoWireError(
                "Connection closed before the MongoDB response was complete."
            )

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def _read_cstring(data: bytes, offset: int, end: int) -> Tuple[str, int]:
    terminator = data.find(b"\x00", offset, end)

    if terminator == -1:
        raise MongoWireError("Malformed BSON cstring.")

    return (
        data[offset:terminator].decode("utf-8", errors="replace"),
        terminator + 1,
    )


def _decode_bson_document(
    data: bytes,
    offset: int = 0,
) -> Tuple[Dict[str, Any], int]:
    if len(data) - offset < 5:
        raise MongoWireError("BSON document is too short.")

    document_size = struct.unpack_from("<i", data, offset)[0]

    if document_size < 5:
        raise MongoWireError("Invalid BSON document size.")

    end = offset + document_size

    if end > len(data):
        raise MongoWireError("BSON document exceeds response size.")

    if data[end - 1] != 0:
        raise MongoWireError("BSON document is missing its terminator.")

    cursor = offset + 4
    document: Dict[str, Any] = {}

    while cursor < end - 1:
        element_type = data[cursor]
        cursor += 1

        key, cursor = _read_cstring(data, cursor, end)

        if element_type == 0x01:  # double
            if cursor + 8 > end:
                raise MongoWireError("Malformed BSON double.")

            value = struct.unpack_from("<d", data, cursor)[0]
            cursor += 8

        elif element_type == 0x02:  # string
            if cursor + 4 > end:
                raise MongoWireError("Malformed BSON string length.")

            length = struct.unpack_from("<i", data, cursor)[0]
            cursor += 4

            if length <= 0 or cursor + length > end:
                raise MongoWireError("Malformed BSON string.")

            value = data[cursor:cursor + length - 1].decode(
                "utf-8",
                errors="replace",
            )
            cursor += length

        elif element_type in {0x03, 0x04}:  # document or array
            value, cursor = _decode_bson_document(data, cursor)

        elif element_type == 0x05:  # binary
            if cursor + 5 > end:
                raise MongoWireError("Malformed BSON binary value.")

            length = struct.unpack_from("<i", data, cursor)[0]
            cursor += 4

            if length < 0 or cursor + 1 + length > end:
                raise MongoWireError("Malformed BSON binary payload.")

            subtype = data[cursor]
            cursor += 1

            value = {
                "subtype": subtype,
                "length": length,
            }

            cursor += length

        elif element_type == 0x07:  # ObjectId
            if cursor + 12 > end:
                raise MongoWireError("Malformed BSON ObjectId.")

            value = data[cursor:cursor + 12].hex()
            cursor += 12

        elif element_type == 0x08:  # boolean
            if cursor + 1 > end:
                raise MongoWireError("Malformed BSON boolean.")

            value = bool(data[cursor])
            cursor += 1

        elif element_type == 0x09:  # UTC datetime
            if cursor + 8 > end:
                raise MongoWireError("Malformed BSON datetime.")

            value = struct.unpack_from("<q", data, cursor)[0]
            cursor += 8

        elif element_type == 0x0A:  # null
            value = None

        elif element_type == 0x10:  # int32
            if cursor + 4 > end:
                raise MongoWireError("Malformed BSON int32.")

            value = struct.unpack_from("<i", data, cursor)[0]
            cursor += 4

        elif element_type == 0x11:  # timestamp
            if cursor + 8 > end:
                raise MongoWireError("Malformed BSON timestamp.")

            value = struct.unpack_from("<Q", data, cursor)[0]
            cursor += 8

        elif element_type == 0x12:  # int64
            if cursor + 8 > end:
                raise MongoWireError("Malformed BSON int64.")

            value = struct.unpack_from("<q", data, cursor)[0]
            cursor += 8

        else:
            raise MongoWireError(
                f"Unsupported BSON element type: 0x{element_type:02x}"
            )

        document[key] = value

    return document, end


def _parse_op_msg(body: bytes) -> Dict[str, Any]:
    if len(body) < 5:
        raise MongoWireError("MongoDB OP_MSG body is too short.")

    flags = struct.unpack_from("<I", body, 0)[0]
    cursor = 4

    # Ignore optional checksum handling for this minimal safe validator.
    checksum_present = bool(flags & 0x01)
    parse_end = len(body) - 4 if checksum_present else len(body)

    while cursor < parse_end:
        section_kind = body[cursor]
        cursor += 1

        if section_kind == 0:
            document, _ = _decode_bson_document(body, cursor)
            return document

        if section_kind == 1:
            if cursor + 4 > parse_end:
                raise MongoWireError("Malformed OP_MSG document sequence.")

            section_size = struct.unpack_from("<i", body, cursor)[0]

            if section_size < 5 or cursor + section_size > parse_end:
                raise MongoWireError("Invalid OP_MSG document sequence size.")

            cursor += section_size
            continue

        raise MongoWireError(
            f"Unsupported OP_MSG section kind: {section_kind}"
        )

    raise MongoWireError("MongoDB OP_MSG response did not contain a body.")


def _parse_op_reply(body: bytes) -> Dict[str, Any]:
    """
    Parse the first document from a legacy OP_REPLY response.
    """

    if len(body) < 20:
        raise MongoWireError("MongoDB OP_REPLY body is too short.")

    number_returned = struct.unpack_from("<i", body, 16)[0]

    if number_returned < 1:
        raise MongoWireError("MongoDB OP_REPLY did not contain a document.")

    document, _ = _decode_bson_document(body, 20)

    return document


def _parse_mongodb_response(
    response: bytes,
    expected_response_to: int,
) -> Tuple[int, Dict[str, Any]]:
    if len(response) < 16:
        raise MongoWireError("MongoDB response header is too short.")

    message_length, _, response_to, opcode = struct.unpack_from(
        "<iiii",
        response,
        0,
    )

    if message_length != len(response):
        raise MongoWireError("MongoDB response length is inconsistent.")

    if response_to not in {0, expected_response_to}:
        raise MongoWireError("MongoDB response ID did not match the request.")

    body = response[16:]

    if opcode == OP_MSG:
        return opcode, _parse_op_msg(body)

    if opcode == OP_REPLY:
        return opcode, _parse_op_reply(body)

    raise MongoWireError(
        f"Unexpected MongoDB response opcode: {opcode}"
    )


def _send_hello(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    request_id = random.randint(1, 2 ** 30)
    request = _build_hello_request(request_id)

    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)

        header = _recv_exact(sock, 16)
        message_length = struct.unpack_from("<i", header, 0)[0]

        if message_length < 16 or message_length > MAX_MESSAGE_SIZE:
            raise MongoWireError(
                f"Invalid MongoDB response size: {message_length}"
            )

        body = _recv_exact(sock, message_length - 16)
        opcode, document = _parse_mongodb_response(
            header + body,
            expected_response_to=request_id,
        )

        return {
            "opcode": opcode,
            "document": document,
        }


def validate(
    host: str,
    port: int = 27017,
    finding_id: str = "MONGODB_EXPOSED",
) -> ValidationResult:
    """
    Confirm MongoDB using a single safe hello exchange.

    The protocol handshake doubles as the reachability check, avoiding an
    unnecessary preliminary TCP connection.
    """

    try:
        response = _send_hello(
            host=host,
            port=port,
        )

    except socket.timeout:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="TIMEOUT",
            reachability="UNKNOWN",
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "MongoDB hello request timed out. The port may be filtered, "
                "slow to respond, or running an unrelated service."
            ),
            details=[
                "MongoDB hello request timed out.",
            ],
            metadata={
                "probe_type": "mongodb_hello",
            },
        )

    except ConnectionRefusedError as exc:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="NONE",
            status="NOT_REACHABLE",
            reachability="NOT_REACHABLE",
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary="MongoDB port refused the connection.",
            details=[
                f"Connection refused: {exc}",
            ],
            metadata={
                "probe_type": "mongodb_hello",
                "error": str(exc),
            },
        )

    except MongoWireError as exc:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="PROTOCOL_MISMATCH",
            reachability="CONFIRMED",
            protocol="MISMATCH",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "Port is reachable, but a valid MongoDB wire-protocol "
                "response was not observed."
            ),
            details=[
                "TCP connection succeeded.",
                f"MongoDB protocol check failed: {exc}",
            ],
            metadata={
                "probe_type": "mongodb_hello",
                "error": str(exc),
            },
        )

    except OSError as exc:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="INCONCLUSIVE",
            reachability="UNKNOWN",
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "MongoDB hello exchange could not be completed."
            ),
            details=[
                f"MongoDB hello exchange failed: {exc}",
            ],
            metadata={
                "probe_type": "mongodb_hello",
                "error": str(exc),
            },
        )

    document = response["document"]
    opcode = response["opcode"]

    evidence = [
        "TCP connection succeeded.",
        "MongoDB hello command returned a valid wire-protocol response.",
        f"MongoDB response opcode: {opcode}",
    ]

    interesting_fields = [
        "isWritablePrimary",
        "secondary",
        "arbiterOnly",
        "msg",
        "setName",
        "minWireVersion",
        "maxWireVersion",
        "maxBsonObjectSize",
        "maxMessageSizeBytes",
        "connectionId",
        "readOnly",
        "ok",
    ]

    metadata_fields = {}

    for field in interesting_fields:
        if field in document:
            metadata_fields[field] = document[field]
            evidence.append(f"{field}: {document[field]}")

    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=True,
        confidence="HIGH",
        status="CONFIRMED",
        reachability="CONFIRMED",
        protocol="CONFIRMED",
        exposure="PRESENT",
        authentication="UNKNOWN",
        transport="TCP",
        summary=(
            "MongoDB wire protocol was confirmed with a safe hello request. "
            "Authentication posture and data access were not tested."
        ),
        details=evidence,
        metadata={
            "probe_type": "mongodb_hello",
            "mongodb": metadata_fields,
            "response_opcode": opcode,
        },
    )
