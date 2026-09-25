# Assault Fire PH emulator - stable public baseline (v94)
#
# Clean-room/community server-emulation research. This public copy is based on
# the last known stable v94 branch before experimental first-login/new-account
# work. Original game binaries/assets are not included.
#
# Configuration:
#   AF_PRIVATE_KEY  local RSA private key (default: server/PRIVATE.PEM)
#   AF_LOG_PATH     server log path (default: server/af_server_live.log)
#   AF_X32DBG_LOG   optional x32dbg crypto log path

import re
from pathlib import Path
import socket
import threading
import time
import struct

import hashlib
import os
import subprocess
import csv
import io
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# v24: v20 success framing plus BOTH PublicData bitmap and PrivateData tail probes.
QUIET_ROLE_HEX = True

def _short_hex(b, n=48):
    b = bytes(b or b'')
    return b[:n].hex() + (f"...(+{len(b)-n}B)" if len(b) > n else "")

# ---------------------------------------------------------------------------
# VERSION SERVER RESPONSE (port 9060)
# ---------------------------------------------------------------------------

RESP = bytearray(bytes.fromhex(
    "000000414355000700020020230100000000000000000001"
    "000000010001000000000018001900000001000000000000"
    "0009312e302e302e323400000000000001"
))

RESP[0:4] = len(RESP).to_bytes(4, "big")
RESP[22] = 0
RESP[23] = 0
RESP[26] = 0
RESP[27] = 0

VERSION_RESPONSE = bytes(RESP)


# ---------------------------------------------------------------------------
# AUTH / AP CRYPTO
# ---------------------------------------------------------------------------

P_PRIME = int(
    "BB2A43DF39322DAAC8C3B30C9F21E13F"
    "646B7234A846231038C087F3408A558D"
    "A8AA1912AE906DEF3E781E39FE172B20"
    "3A6B8452056B3C9CB21237CAC3F5AA1B",
    16
)

G = 2

IV = bytes.fromhex(
    "b83bca76c4fd6d3ba5964edeb300df6c"
)

PRIME_BYTES = P_PRIME.to_bytes(64, "big")

PROJECT_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_PATH = Path(os.environ.get("AF_PRIVATE_KEY", str(PROJECT_DIR / "PRIVATE.PEM")))
LOG_PATH = Path(os.environ.get("AF_LOG_PATH", str(PROJECT_DIR / "af_server_live.log")))


try:
    with open(PRIVATE_KEY_PATH, "rb") as f:
        RSA_PRIV = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    print(
        "[BOOT] Loaded RSA private key from",
        PRIVATE_KEY_PATH,
        flush=True
    )

except Exception as e:
    print(
        f"[BOOT] FAILED to load RSA private key: {e}",
        flush=True
    )
    RSA_PRIV = None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(label, message):
    line = (
        f"[{time.strftime('%H:%M:%S')}] "
        f"[{label}] {message}"
    )
    print(line, flush=True)
    try:
        with LOG_PATH.open("a", encoding="utf-8") as fp:
            fp.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def recv_exact(conn, size, timeout=10.0):
    conn.settimeout(timeout)

    data = bytearray()

    while len(data) < size:
        try:
            chunk = conn.recv(size - len(data))
        except socket.timeout:
            break

        if not chunk:
            break

        data.extend(chunk)

    return bytes(data)


# ---------------------------------------------------------------------------
# Normal PKCS#7 AES used by the initial AUTH handshake
# ---------------------------------------------------------------------------

def aes_cbc_encrypt_pkcs7(key, plaintext):
    padlen = 16 - (len(plaintext) % 16)

    padded = (
        plaintext +
        bytes([padlen]) * padlen
    )

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(IV),
        backend=default_backend()
    )

    enc = cipher.encryptor()

    return enc.update(padded) + enc.finalize()


# ---------------------------------------------------------------------------
# AP message crypto
#
# TCLS uses its own padding layout here.
#
# Let:
#
#     r = plaintext_length % 16
#
# If r == 0:
#
#     r = 16
#
# All complete blocks except the last r plaintext bytes are written normally.
#
# The remaining r bytes go into the beginning of a final 32-byte area:
#
#     final[0:r] = tail
#     final[16]  = 16-r
#
# Everything else in that 32-byte area is zero.
# ---------------------------------------------------------------------------

def ap_encrypt(key, plaintext):
    if not plaintext:
        raise ValueError("cannot AP-encrypt empty plaintext")

    r = len(plaintext) & 0x0F

    if r == 0:
        r = 16

    prefix_len = len(plaintext) - r

    prefix = plaintext[:prefix_len]
    tail = plaintext[prefix_len:]

    final = bytearray(32)

    final[0:r] = tail

    # TCLS custom padding marker
    final[16] = 16 - r

    padded = prefix + bytes(final)

    if len(padded) % 16 != 0:
        raise ValueError("internal AP padding error")

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(IV),
        backend=default_backend()
    )

    enc = cipher.encryptor()

    return enc.update(padded) + enc.finalize()


def ap_decrypt(key, ciphertext):
    if len(ciphertext) < 32:
        raise ValueError(
            f"AP ciphertext too short: {len(ciphertext)}"
        )

    if len(ciphertext) % 16 != 0:
        raise ValueError(
            f"AP ciphertext not block aligned: {len(ciphertext)}"
        )

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(IV),
        backend=default_backend()
    )

    dec = cipher.decryptor()

    padded = (
        dec.update(ciphertext) +
        dec.finalize()
    )

    # In the last 32-byte special block,
    # offset 16 contains 16-r.
    marker = padded[-16]

    if marker > 15:
        raise ValueError(
            f"invalid AP padding marker: {marker}"
        )

    logical_len = (
        len(padded) -
        (16 + marker)
    )

    if logical_len < 0:
        raise ValueError(
            "invalid AP logical length"
        )

    return padded[:logical_len]


# ---------------------------------------------------------------------------
# AP HNNW frame
# ---------------------------------------------------------------------------

def recv_ap_frame(conn, timeout=15.0):
    header = recv_exact(
        conn,
        6,
        timeout=timeout
    )

    if not header:
        return None

    if len(header) != 6:
        raise ValueError(
            f"short AP header: {len(header)}B"
        )

    if header[:4] != b"HNNW":
        raise ValueError(
            f"wrong AP sync word: {header[:4]!r}"
        )

    body_len = int.from_bytes(
        header[4:6],
        "big"
    )

    ciphertext = recv_exact(
        conn,
        body_len,
        timeout=timeout
    )

    if len(ciphertext) != body_len:
        raise ValueError(
            f"short AP body: "
            f"{len(ciphertext)}/{body_len}B"
        )

    return ciphertext


def build_ap_frame(key, plaintext):
    encrypted = ap_encrypt(
        key,
        plaintext
    )

    return (
        b"HNNW" +
        len(encrypted).to_bytes(2, "big") +
        encrypted
    )


# ---------------------------------------------------------------------------
# Generic TDR header
#
#   u16 msgsize
#   u16 version
#   u32 seqno
#   u16 cmd
#
# msgsize = number of bytes AFTER this 10-byte header.
# ---------------------------------------------------------------------------

def parse_tdr_header(data):
    if len(data) < 10:
        raise ValueError(
            f"TDR message too short: {len(data)}B"
        )

    msgsize = int.from_bytes(
        data[0:2],
        "big"
    )

    version = int.from_bytes(
        data[2:4],
        "big"
    )

    seqno = int.from_bytes(
        data[4:8],
        "big"
    )

    cmd = int.from_bytes(
        data[8:10],
        "big"
    )

    return {
        "msgsize": msgsize,
        "version": version,
        "seqno": seqno,
        "cmd": cmd,
        "body": data[10:]
    }


# ---------------------------------------------------------------------------
# AP_CMD_RESULT = cmd 4
#
# Body:
#
#   u32 error_code
#   u32 oas_error_code
#
#   u32 error_message_length
#   char error_message[length]
#
#   u32 uid
#   u32 timestamp
#
#   u16 ticket_size
#   byte ticket[ticket_size]
# ---------------------------------------------------------------------------

def build_ap_result_plaintext(seqno):
    error_code = 0
    oas_error_code = 0

    # TCLS requires at least one byte and requires the
    # last byte to be NUL.
    error_message = b"\x00"

    # Give the client usable non-zero values.
    uid = 10001
    timestamp = int(time.time()) & 0xFFFFFFFF

    # Opaque ticket. Later, when the client presents this
    # to the next service, our private server can simply
    # recognize/accept the same bytes.
    ticket = b"LOCAL_TICKET_001"

    body = (
        error_code.to_bytes(4, "big") +
        oas_error_code.to_bytes(4, "big") +

        len(error_message).to_bytes(4, "big") +
        error_message +

        uid.to_bytes(4, "big") +
        timestamp.to_bytes(4, "big") +

        len(ticket).to_bytes(2, "big") +
        ticket
    )

    header = (
        len(body).to_bytes(2, "big") +
        (1).to_bytes(2, "big") +
        seqno.to_bytes(4, "big") +
        (4).to_bytes(2, "big")
    )

    plaintext = header + body

    return plaintext


# ---------------------------------------------------------------------------
# Initial AUTH handshake
# ---------------------------------------------------------------------------

def build_auth_response(request_bytes):
    if RSA_PRIV is None:
        raise RuntimeError(
            "RSA private key is not loaded"
        )

    if len(request_bytes) != 214:
        raise ValueError(
            f"AUTH request should be 214B, "
            f"got {len(request_bytes)}B"
        )

    # The entire 128 bytes at 86:214 are ONE RSA-1024 ciphertext.
    rsa_ciphertext = request_bytes[86:214]

    plain = RSA_PRIV.decrypt(
        rsa_ciphertext,
        padding.PKCS1v15()
    )

    print(
        f"[AUTH] RSA plaintext len={len(plain)}",
        flush=True
    )

    print(
        f"[AUTH] RSA plaintext={plain.hex()}",
        flush=True
    )

    if len(plain) != 68:
        raise ValueError(
            f"unexpected RSA plaintext length: "
            f"{len(plain)}"
        )

    # RSA plaintext:
    #
    #   0:4   nonce
    #   4:68  client DH public key
    #
    nonce = int.from_bytes(
        plain[0:4],
        "big"
    )

    client_pub_bytes = plain[4:68]

    client_pub = int.from_bytes(
        client_pub_bytes,
        "big"
    )

    print(
        f"[AUTH] nonce=0x{nonce:08x}",
        flush=True
    )

    print(
        f"[AUTH] client_pub="
        f"{client_pub_bytes.hex()}",
        flush=True
    )

    if not (1 < client_pub < P_PRIME):
        raise ValueError(
            "invalid client DH public key"
        )

    # Server DH private key
    server_priv = (
        int.from_bytes(
            os.urandom(64),
            "big"
        ) % (P_PRIME - 2)
    ) + 1

    # Server public key
    server_pub = pow(
        G,
        server_priv,
        P_PRIME
    )

    server_pub_bytes = (
        server_pub.to_bytes(
            64,
            "big"
        )
    )

    # Shared secret
    shared = pow(
        client_pub,
        server_priv,
        P_PRIME
    )

    shared_bytes = shared.to_bytes(
        64,
        "big"
    )

    # TCLS key derivation:
    #
    # AES-128 key = MD5(64-byte DH shared secret)
    #
    aes_key = hashlib.md5(
        shared_bytes
    ).digest()

    print(
        f"[AUTH] server_pub="
        f"{server_pub_bytes.hex()}",
        flush=True
    )

    print(
        f"[AUTH] shared="
        f"{shared_bytes.hex()}",
        flush=True
    )

    print(
        f"[AUTH] aes_key="
        f"{aes_key.hex()}",
        flush=True
    )

    # Client requires nonce + 1.
    ack_seq = (
        nonce + 1
    ) & 0xFFFFFFFF

    ack_plain = (
        ack_seq.to_bytes(4, "big") +
        b"\x00" * 16
    )

    print(
        f"[AUTH] ack_seq="
        f"0x{ack_seq:08x}",
        flush=True
    )

    print(
        f"[AUTH] ack_plain="
        f"{ack_plain.hex()}",
        flush=True
    )

    # The initial handshake uses normal PKCS#7,
    # unlike subsequent AP messages.
    field_E = aes_cbc_encrypt_pkcs7(
        aes_key,
        ack_plain
    )

    print(
        f"[AUTH] field_E="
        f"{field_E.hex()}",
        flush=True
    )

    field_D = server_pub_bytes

    # SHA1 RSA signature over:
    #
    #     server_DH_public || encrypted_ACK
    #
    sig = RSA_PRIV.sign(
        field_D + field_E,
        padding.PKCS1v15(),
        hashes.SHA1()
    )

    if len(sig) != 128:
        raise ValueError(
            f"unexpected RSA signature size: "
            f"{len(sig)}"
        )

    body = (
        (0).to_bytes(2, "big") +
        (0).to_bytes(4, "big") +
        len(field_E).to_bytes(2, "big") +
        len(field_D).to_bytes(1, "big") +
        field_D +
        field_E +
        sig
    )

    response = (
        b"HNNW" +
        len(body).to_bytes(2, "big") +

        # version
        (1).to_bytes(2, "big") +

        # status
        (0).to_bytes(4, "big") +

        # cmd = 2
        (2).to_bytes(2, "big") +

        body
    )

    print(
        f"[AUTH] response={len(response)}B "
        f"header={response[:14].hex()}",
        flush=True
    )

    return response, aes_key


# ---------------------------------------------------------------------------
# VERSION handler
# ---------------------------------------------------------------------------

def handle_version(conn, addr):
    try:
        request = recv_exact(
            conn,
            65,
            timeout=6.0
        )

        pid, pname = identify_peer_process(addr, conn.getsockname()[1])
        owner = f" OWNER={pname or '?'} PID={pid}" if pid is not None else " OWNER=<unresolved>"
        uin_hint = 0
        if len(request) >= 53:
            try:
                uin_hint = int.from_bytes(request[49:53], "big")
            except Exception:
                uin_hint = 0
        log(
            "VERSION",
            f"Connected from {addr}{owner} ({len(request)}B) uin_hint={uin_hint}"
        )

        if len(request) != 65:
            log("VERSION", f"Bad request length: {len(request)}")
            return

        log("VERSION", f"RX {_short_hex(request)}")

        # IMPORTANT:
        # Echo THIS request, because after START it contains
        # the UID and selected World/Server ID.
        response = bytearray(request)

        # Length
        response[0:4] = len(response).to_bytes(4, "big")

        # Success/status fields
        response[22] = 0
        response[23] = 0
        response[26] = 0
        response[27] = 0

        response = bytes(response)

        conn.sendall(response)

        log(
            "VERSION",
            f"TX {len(response)}B: {_short_hex(response)}"
        )

    except Exception as e:
        log("VERSION", f"error: {e}")

    finally:
        try:
            conn.close()
        except Exception:
            pass
# ---------------------------------------------------------------------------
# AUTH + APAccount handler
# ---------------------------------------------------------------------------

def handle_auth(conn, addr):
    t0 = time.time()

    try:
        # ---------------------------------------------------------------
        # 1. Initial RSA/DH handshake request
        # ---------------------------------------------------------------

        request = recv_exact(
            conn,
            214,
            timeout=10.0
        )

        log(
            "AUTH",
            f"Connected from {addr} "
            f"({len(request)}B)"
        )

        if len(request) != 214:
            log(
                "AUTH",
                "did not receive full "
                "214-byte handshake"
            )
            return

        print(
            f"[AUTH] header="
            f"{request[:16].hex()}",
            flush=True
        )

        # ---------------------------------------------------------------
        # 2. Build/send server AUTH ACK
        # ---------------------------------------------------------------

        response, aes_key = (
            build_auth_response(request)
        )

        conn.sendall(response)

        log(
            "AUTH",
            f"AUTH ACK sent "
            f"({len(response)}B)"
        )

        # ---------------------------------------------------------------
        # 3. Receive encrypted AP_CMD_VERIFY / cmd 3
        # ---------------------------------------------------------------

        ciphertext = recv_ap_frame(
            conn,
            timeout=15.0
        )

        if ciphertext is None:
            log(
                "AUTH",
                "client sent no AP request"
            )
            return

        log(
            "AUTH",
            f"AP RX encrypted "
            f"{len(ciphertext)}B: "
            f"{ciphertext.hex()}"
        )

        plaintext = ap_decrypt(
            aes_key,
            ciphertext
        )

        log(
            "AUTH",
            f"AP RX plaintext "
            f"{len(plaintext)}B: "
            f"{plaintext.hex()}"
        )

        hdr = parse_tdr_header(
            plaintext
        )

        log(
            "AUTH",
            "AP RX "
            f"msgsize={hdr['msgsize']} "
            f"version={hdr['version']} "
            f"seq={hdr['seqno']} "
            f"cmd={hdr['cmd']} "
            f"body={len(hdr['body'])}B"
        )

        if hdr["version"] != 1:
            log(
                "AUTH",
                "WARNING: unexpected "
                f"TDR version {hdr['version']}"
            )

        if hdr["msgsize"] != len(
            hdr["body"]
        ):
            log(
                "AUTH",
                "WARNING: TDR msgsize "
                f"says {hdr['msgsize']} "
                f"but body is "
                f"{len(hdr['body'])}B"
            )

        if hdr["cmd"] != 3:
            log(
                "AUTH",
                "WARNING: expected client "
                f"cmd=3, got cmd={hdr['cmd']}"
            )

        # ---------------------------------------------------------------
        # 4. Send AP_CMD_RESULT / cmd 4 success
        # ---------------------------------------------------------------

        result_plain = (
            build_ap_result_plaintext(
                hdr["seqno"]
            )
        )

        result_frame = build_ap_frame(
            aes_key,
            result_plain
        )

        log(
            "AUTH",
            f"AP TX cmd=4 plaintext "
            f"{len(result_plain)}B: "
            f"{result_plain.hex()}"
        )

        log(
            "AUTH",
            f"AP TX cmd=4 frame "
            f"{len(result_frame)}B: "
            f"{result_frame.hex()}"
        )

        conn.sendall(
            result_frame
        )

        # ---------------------------------------------------------------
        # 5. Client should now send cmd 5 acknowledgement
        # ---------------------------------------------------------------

        try:
            ack_ciphertext = recv_ap_frame(
                conn,
                timeout=10.0
            )
        except socket.timeout:
            ack_ciphertext = None

        if ack_ciphertext:
            log(
                "AUTH",
                f"AP RX second encrypted "
                f"{len(ack_ciphertext)}B: "
                f"{ack_ciphertext.hex()}"
            )

            ack_plaintext = ap_decrypt(
                aes_key,
                ack_ciphertext
            )

            log(
                "AUTH",
                f"AP RX second plaintext "
                f"{len(ack_plaintext)}B: "
                f"{ack_plaintext.hex()}"
            )

            if len(ack_plaintext) >= 10:
                ack_hdr = parse_tdr_header(
                    ack_plaintext
                )

                log(
                    "AUTH",
                    "AP RX second "
                    f"msgsize="
                    f"{ack_hdr['msgsize']} "
                    f"version="
                    f"{ack_hdr['version']} "
                    f"seq="
                    f"{ack_hdr['seqno']} "
                    f"cmd="
                    f"{ack_hdr['cmd']}"
                )

                if ack_hdr["cmd"] == 5:
                    log(
                        "AUTH",
                        "SUCCESS: client "
                        "accepted AP cmd=4 "
                        "and sent cmd=5"
                    )

        else:
            log(
                "AUTH",
                "No cmd=5 received"
            )

        # Let the client close naturally.
        try:
            conn.settimeout(3.0)

            extra = conn.recv(4096)

            if extra:
                log(
                    "AUTH",
                    f"EXTRA RX "
                    f"({len(extra)}B): "
                    f"{extra.hex()}"
                )

        except socket.timeout:
            pass

        log(
            "AUTH",
            f"finished after "
            f"{time.time() - t0:.2f}s"
        )

    except ConnectionResetError:
        log(
            "AUTH",
            "connection reset by client"
        )

    except Exception as e:
        log(
            "AUTH",
            f"ERROR: {type(e).__name__}: {e}"
        )

    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Placeholder DIR / ROLE handlers
#
# Once APAccount succeeds, whichever one the client contacts next
# is what we'll reverse next.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ROLE / 65005 TPDU decoder helpers
#
# This is intentionally a decoder/probe first.  It does not fake a server reply
# until the next expected reply is proven from the client parser.
# ---------------------------------------------------------------------------

ROLE_BOOTSTRAP_TEA_KEY = b"aaaaaaaaaaaaaaaa"
ROLE_TEA_DELTA = 0x9E3779B9
ROLE_U32_MASK = 0xFFFFFFFF


def _role_tea_dec_block(block, key):
    import struct
    y, z = struct.unpack(">2I", block)
    a, b, c, d = struct.unpack(">4I", key)
    s = (ROLE_TEA_DELTA << 4) & ROLE_U32_MASK
    for _ in range(16):
        z = (z - ((((y << 4) & ROLE_U32_MASK) + c) ^ ((y + s) & ROLE_U32_MASK) ^ ((y >> 5) + d))) & ROLE_U32_MASK
        y = (y - ((((z << 4) & ROLE_U32_MASK) + a) ^ ((z + s) & ROLE_U32_MASK) ^ ((z >> 5) + b))) & ROLE_U32_MASK
        s = (s - ROLE_TEA_DELTA) & ROLE_U32_MASK
    return struct.pack(">2I", y, z)


def role_qqtea_decrypt(ciphertext, key=ROLE_BOOTSTRAP_TEA_KEY):
    if len(ciphertext) % 8 or len(ciphertext) < 16:
        return None, "bad ciphertext length"

    cur = _role_tea_dec_block(ciphertext[:8], key)
    padding = cur[0] & 7
    out_len = len(ciphertext) - padding - 10
    if out_len < 0:
        return None, "bad decoded length"

    index = padding + 1
    crypt_off = 8
    pre_crypt = b"\x00" * 8

    def next_block(cur_block, off):
        if off >= len(ciphertext):
            return None, None, None
        prev_cipher = ciphertext[off - 8:off]
        mixed = bytes(a ^ b for a, b in zip(ciphertext[off:off + 8], cur_block))
        return _role_tea_dec_block(mixed, key), off + 8, prev_cipher

    # Skip the two random bytes after the padding area.
    for _ in range(2):
        if index == 8:
            cur, crypt_off, pre_crypt = next_block(cur, crypt_off)
            if cur is None:
                return None, "ran out while skipping random bytes"
            index = 0
        index += 1

    plain = bytearray()
    for _ in range(out_len):
        if index == 8:
            cur, crypt_off, pre_crypt = next_block(cur, crypt_off)
            if cur is None:
                return None, "ran out while decrypting body"
            index = 0
        plain.append(cur[index] ^ pre_crypt[index])
        index += 1

    for n in range(7):
        if index == 8:
            cur, crypt_off, pre_crypt = next_block(cur, crypt_off)
            if cur is None:
                return bytes(plain), f"ran out while checking trailer byte {n}"
            index = 0
        trailer = cur[index] ^ pre_crypt[index]
        if trailer != 0:
            return bytes(plain), f"zero trailer failed at byte {n}: {trailer:02x}"
        index += 1

    return bytes(plain), "ok"


def decode_role_packet_for_log(data):
    import struct
    lines = []
    lines.append(f"ROLE decode: total={len(data)} bytes")
    if len(data) < 34:
        lines.append("too short for known 65005 AUTH frame")
        return lines

    lines.append(
        "header: "
        f"b0={data[0]:02x} version={data[1]:02x} cmd={data[2]:02x} "
        f"head_len={data[3]} enc_head_len={data[4]} "
        f"body_len={struct.unpack('>I', data[5:9])[0]}"
    )
    lines.append(
        "auth-head: "
        f"enc_method={struct.unpack('>I', data[9:13])[0]} "
        f"service_id={struct.unpack('>I', data[13:17])[0]} "
        f"auth_type={struct.unpack('>I', data[17:21])[0]} "
        f"uin={struct.unpack('>I', data[21:25])[0]} "
        f"auth_data_len={data[25]}"
    )

    auth_len = data[25]
    auth_data = data[26:26 + auth_len]
    if len(auth_data) >= 8:
        version = struct.unpack('>H', auth_data[0:2])[0]
        ts = struct.unpack('>I', auth_data[2:6])[0]
        enc_len = struct.unpack('>H', auth_data[6:8])[0]
        enc = auth_data[8:8 + enc_len]
        lines.append(f"unified-wrapper: version={version} time={ts} enc_len={enc_len}")
        plain, status = role_qqtea_decrypt(enc)
        lines.append(f"unified-decrypt: {status}")
        if plain is not None:
            lines.append(f"unified-plain-len={len(plain)} hex={plain.hex()}")
            if len(plain) >= 50:
                uin = struct.unpack('>I', plain[6:10])[0]
                ts2 = struct.unpack('>I', plain[10:14])[0]
                session_key = plain[30:46]
                lines.append(f"parsed-unified: uin={uin} time={ts2} session_key={session_key!r} session_key_hex={session_key.hex()}")

    tail = data[26 + auth_len:]
    lines.append(f"tail/body: offset={26 + auth_len} len={len(tail)} hex={tail.hex()}")
    return lines




ROLE_MODE3_IV = bytes(range(16))
ROLE_SYN_RAND = b"LOCAL_SYN_RAND01"  # exactly 16 bytes


def role_mode3_encrypt(plain, key):
    """Reimplementation of tacc_2_1.dll mode-3 (0x100E1460).

    AES-CBC with IV 00..0F and Tencent/TSF4G tail padding:
      random filler || b"tsf4g" || one-byte total pad length.
    Filler bytes are not validated by the client, so zeroes are deterministic.
    """
    if len(key) != 16:
        raise ValueError("mode3 requires a 16-byte key")
    rem = len(plain) & 0x0F
    pad_len = (16 - rem) if rem <= 10 else (32 - rem)
    filler_len = pad_len - 6
    padded = plain + (b"\x00" * filler_len) + b"tsf4g" + bytes([pad_len])
    enc = Cipher(algorithms.AES(key), modes.CBC(ROLE_MODE3_IV)).encryptor()
    return enc.update(padded) + enc.finalize()


def role_mode3_decrypt(ciphertext, key):
    """Reimplementation of tacc_2_1.dll 0x100E1620."""
    if len(key) != 16 or not ciphertext or (len(ciphertext) & 0x0F):
        return None, "bad mode3 input"
    dec = Cipher(algorithms.AES(key), modes.CBC(ROLE_MODE3_IV)).decryptor()
    raw = dec.update(ciphertext) + dec.finalize()
    if len(raw) < 6 or raw[-6:-1] != b"tsf4g":
        return None, f"bad tsf4g trailer raw={raw.hex()}"
    pad_len = raw[-1]
    if pad_len <= 0 or pad_len > len(raw):
        return None, f"bad pad length {pad_len}"
    plain_len = len(raw) - pad_len
    rem = plain_len & 0x0F
    expected = (16 - rem) if rem <= 10 else (32 - rem)
    if expected != pad_len:
        return None, f"pad mismatch got={pad_len} expected={expected}"
    return raw[:plain_len], "ok"


def role_extract_auth_state(data):
    """Extract live mode, UIN, session key and request sequence from cmd03."""
    st = {}
    if len(data) < 34 or data[2] != 0x03:
        return st
    try:
        st["mode"] = struct.unpack(">I", data[9:13])[0]
        st["uin"] = struct.unpack(">I", data[21:25])[0]
        auth_len = data[25]
        auth_data = data[26:26 + auth_len]
        if len(auth_data) >= 8:
            enc_len = struct.unpack(">H", auth_data[6:8])[0]
            enc = auth_data[8:8 + enc_len]
            plain, status = role_qqtea_decrypt(enc)
            if plain is not None and len(plain) >= 46:
                st["session_key"] = plain[30:46]
        head_len = data[3]
        body_len = struct.unpack(">I", data[5:9])[0]
        body = data[head_len:head_len + body_len]
        if st.get("mode") == 3 and st.get("session_key") and body:
            bp, bs = role_mode3_decrypt(body, st["session_key"])
            st["body_status"] = bs
            st["body_plain"] = bp
            if bp is not None and len(bp) >= 4:
                st["seq"] = struct.unpack(">I", bp[:4])[0]
                st["app_plain"] = bp[4:]
    except Exception as e:
        st["error"] = f"{type(e).__name__}: {e}"
    return st


def role_build_syn(session_key, seq, randstr=ROLE_SYN_RAND):
    """Build the server -> client TPDU SYN wire packet (cmd 08).

    Important correction vs v1:
      The client calls its generic receive routine for this first server reply
      with body_output=NULL. Therefore body_len MUST be 0 here. If we include
      an encrypted sequence/body, the generic receiver fails before the cmd08
      SYN parser gets a chance to run.

    TPDUSynInfo is the fixed 16-byte randstr. The SYN extension stores
    one-byte encrypted length followed by the mode-3 ciphertext at offset 0x0A.
    """
    if len(randstr) != 16:
        raise ValueError("randstr must be 16 bytes")
    syn_cipher = role_mode3_encrypt(randstr, session_key)
    head_len = 10 + len(syn_cipher)
    if head_len > 255 or len(syn_cipher) > 255:
        raise ValueError("SYN header too large")
    head = bytearray()
    head += bytes([0x00, 0x0C, 0x08, head_len, 0x04])
    head += struct.pack(">I", 0)          # body_len = 0 for first server SYN
    head += bytes([len(syn_cipher)])
    head += syn_cipher
    return bytes(head)




def role_build_tacc_one_private_entry_app(
    uin=10001,
    server_id=0x01010101,
    host="127.0.0.1",
    port=65005,
    cmdid=2,
    update_time=0,
):
    """v24: compact TDR success response with the corrected schema.

    Critical differences from v24:
      - keep the already-fixed cmd05 outer framing (NO extra 4-byte seq prefix)
      - serialize variable arrays compactly on the wire instead of sending
        fixed host-output padding
      - PrivateInfoCount = 1 on the wire
      - PrivateInfo.ServerID = DIR LeafID 0x01010101
      - PrivateData is the tacc_datadef.tdr six-byte record:
            LastActiveTime:u32 || rolecount:i16
        It is NOT IPv4:port.
      - PublicDataLen = 0 for this probe; GetBitMapInfo's return is ignored
        by OnDataArrive, so do not invent bitmap policy bytes here.
    """
    if update_time == 0:
        update_time = int(time.time())

    # tacc_datadef.tdr:
    #   PrivateData = BE u32 LastActiveTime || BE i16 rolecount
    private_data = struct.pack(">Ih", 0, 1)

    body = bytearray()
    body += struct.pack(">H", 0)                         # TaccRsp.Errno = success

    # RspInfoSucc compact wire order.
    body += struct.pack(">I", uin & 0xffffffff)          # Uin
    body += b"\x00"                                      # HasMorePkg
    body += struct.pack(">I", update_time & 0xffffffff)  # PublicInfo.UpdateTime
    body += struct.pack(">H", 0)                         # PublicDataLen = 0
    # no PublicData bytes
    body += struct.pack(">H", 1)                         # PrivateInfoCount = 1

    # PrivateInfo[0]
    body += struct.pack(">I", update_time & 0xffffffff)  # UpdateTime
    body += struct.pack(">I", server_id & 0xffffffff)    # ServerID = DIR leaf ID
    body += struct.pack(">H", len(private_data))         # PrivateDataLen = 6
    body += private_data                                 # 00 00 00 00 00 01

    total_len = 14 + len(body)
    pkg = bytearray()
    pkg += struct.pack(">I", total_len)
    pkg += struct.pack(">H", 0x00c8)
    pkg += struct.pack(">H", 0x0002)                     # request uses version 2
    pkg += struct.pack(">H", cmdid & 0xffff)             # response CmdID = 2
    pkg += struct.pack(">I", 0)                          # app Seq
    pkg += body

    return bytes(pkg), bytes(private_data)

def role_build_plain_tpdu_body_response(session_key, seq, app_payload):
    """Build server->client cmd05 carrying a TACC response.

    Critical fix vs v11-v14:
      In sub_100D6FD0 -> sub_100D60E0, when received command == 0x05 and
      the last decrypt/copy flag is 0, the client DOES NOT decrypt the body.
      It passes the body bytes directly to tdr_ntoh(pkg body).

    Therefore cmd05 body must be plaintext and begin directly with TACCCliPkg.

    The previous v18 prepended a uint32 TPDU sequence here. Static analysis of
    tacc_2_1.dll+CFA00 proves that was wrong: the root TACCCliPkg descriptor
    reads its 16-bit Version at input offset +6. With a 4-byte seq prefix it
    read the low 16 bits of PkgLen (0x0010) as Version and rejected 16 > 2.

    Do NOT AES-encrypt this body for cmd05 and do NOT prepend seq.
    """
    body_plain = bytes(app_payload)

    pkt = bytearray()
    pkt += bytes([0x00, 0x0c, 0x05, 0x09, 0x04])
    pkt += struct.pack('>I', len(body_plain))
    pkt += body_plain

    # Keep third return value for caller compatibility.
    return bytes(pkt), body_plain, body_plain



ROLE_SYN_VARIANT_STATE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "role_syn_variant_state_unused_v4.txt",
)

ROLE_SYN_VARIANTS = [
    {"name": "00_raw16_aes_body0",       "b0": 0x00, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "aes",  "body": "none"},
    {"name": "55_raw16_aes_body0",       "b0": 0x55, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "aes",  "body": "none"},
    {"name": "00_len8_raw16_aes_body0",  "b0": 0x00, "enc_head_len": 0x04, "plain": "len8raw",   "crypto": "aes",  "body": "none"},
    {"name": "55_len8_raw16_aes_body0",  "b0": 0x55, "enc_head_len": 0x04, "plain": "len8raw",   "crypto": "aes",  "body": "none"},
    {"name": "00_len16_raw16_aes_body0", "b0": 0x00, "enc_head_len": 0x04, "plain": "len16raw",  "crypto": "aes",  "body": "none"},
    {"name": "00_len32_raw16_aes_body0", "b0": 0x00, "enc_head_len": 0x04, "plain": "len32raw",  "crypto": "aes",  "body": "none"},
    {"name": "00_raw16_nul_aes_body0",   "b0": 0x00, "enc_head_len": 0x04, "plain": "raw16nul",  "crypto": "aes",  "body": "none"},
    {"name": "00_nul_raw16_aes_body0",   "b0": 0x00, "enc_head_len": 0x04, "plain": "nulraw16",  "crypto": "aes",  "body": "none"},
    {"name": "00_raw16_aes_bodyseq",     "b0": 0x00, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "aes",  "body": "seq"},
    {"name": "55_raw16_aes_bodyseq",     "b0": 0x55, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "aes",  "body": "seq"},
    {"name": "00_raw16_plain_body0",     "b0": 0x00, "enc_head_len": 0x04, "plain": "raw16",     "crypto": "none", "body": "none"},
    {"name": "00_len8_raw16_plain_body0","b0": 0x00, "enc_head_len": 0x04, "plain": "len8raw",   "crypto": "none", "body": "none"},
    {"name": "00_raw16_aes_ehlen0",      "b0": 0x00, "enc_head_len": 0x00, "plain": "raw16",     "crypto": "aes",  "body": "none"},
    {"name": "55_len8_raw16_aes_bodyseq","b0": 0x55, "enc_head_len": 0x04, "plain": "len8raw",   "crypto": "aes",  "body": "seq"},
]


def role_syn_plaintext(kind, randstr):
    if kind == "raw16":
        return randstr
    if kind == "len8raw":
        return bytes([len(randstr)]) + randstr
    if kind == "len16raw":
        return struct.pack(">H", len(randstr)) + randstr
    if kind == "len32raw":
        return struct.pack(">I", len(randstr)) + randstr
    if kind == "raw16nul":
        return randstr + b"\x00"
    if kind == "nulraw16":
        return b"\x00" + randstr
    raise ValueError(f"unknown SYN plaintext variant: {kind}")


def role_build_syn_variant(session_key, seq, variant, randstr=ROLE_SYN_RAND):
    plain = role_syn_plaintext(variant["plain"], randstr)

    if variant["crypto"] == "aes":
        syn_field = role_mode3_encrypt(plain, session_key)
    elif variant["crypto"] == "none":
        syn_field = plain
    else:
        raise ValueError(f"unknown SYN crypto variant: {variant['crypto']}")

    body = b""
    if variant["body"] == "seq":
        body = role_mode3_encrypt(struct.pack(">I", seq & 0xffffffff), session_key)
    elif variant["body"] != "none":
        raise ValueError(f"unknown SYN body variant: {variant['body']}")

    head_len = 10 + len(syn_field)
    if head_len > 255 or len(syn_field) > 255:
        raise ValueError("SYN variant header too large")

    pkt = bytearray()
    pkt += bytes([variant["b0"], 0x0C, 0x08, head_len, variant["enc_head_len"]])
    pkt += struct.pack(">I", len(body))
    pkt += bytes([len(syn_field)])
    pkt += syn_field
    pkt += body
    return bytes(pkt), plain, syn_field, body


def role_choose_syn_variant():
    # v4: static trace says the generic TQQAPI path uses the real TPDU magic byte 0x55.
    # The captured client.exe request used 0x00 because CPlayerInfoQuerier manually builds
    # its first AUTH frame and leaves byte 0 zeroed before the transport wraps it.
    # Server -> client SYN should follow the normal TQQAPI packet shape.
    variant = {
        "name": "v4_exact_static_55_raw16_aes_body0",
        "b0": 0x55,
        "enc_head_len": 0x04,
        "plain": "raw16",
        "crypto": "aes",
        "body": "none",
    }
    return 0, variant, "forced v4 from static cmd08 parser: b0=0x55, raw TPDUSynInfo[16], encrypted header, no body"

def role_decode_synack(data, session_key):
    if len(data) < 10:
        return [f"SYNACK too short: {len(data)}"]
    lines=[]
    try:
        cmd=data[2]
        head_len=data[3]
        body_len=struct.unpack(">I", data[5:9])[0]
        lines.append(f"follow-up header: version={data[1]:02x} cmd={cmd:02x} head_len={head_len} enc_head_len={data[4]} body_len={body_len}")
        if cmd == 0x09:
            enc_len=data[9]
            enc=data[10:10+enc_len]
            p, status=role_mode3_decrypt(enc, session_key)
            lines.append(f"SYNACK rand decrypt: {status}")
            if p is not None:
                lines.append(f"SYNACK rand plain={p!r} hex={p.hex()} matches={p == ROLE_SYN_RAND}")
        if body_len and head_len + body_len <= len(data):
            bp, bs=role_mode3_decrypt(data[head_len:head_len+body_len], session_key)
            lines.append(f"follow-up body decrypt: {bs} plain={bp.hex() if bp is not None else None}")
    except Exception as e:
        lines.append(f"SYNACK decode error: {type(e).__name__}: {e}")
    return lines


def identify_peer_process(addr, server_port):
    """
    On Windows, map the accepted connection's ephemeral source port back
    to its owning PID/process name using netstat -ano + tasklist.
    """
    if os.name != "nt":
        return None, None

    remote_port = int(addr[1])

    try:
        cp = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3.0,
        )

        pid = None

        for raw in cp.stdout.splitlines():
            parts = raw.split()

            if len(parts) < 5 or parts[0].upper() != "TCP":
                continue

            local_ep = parts[1]
            remote_ep = parts[2]
            state = parts[3].upper()
            pid_text = parts[4]

            # We want the CLIENT side of this loopback connection:
            #
            #   local   127.0.0.1:<ephemeral>
            #   remote  127.0.0.1:<server_port>
            #
            try:
                local_port = int(local_ep.rsplit(":", 1)[1])
                peer_port = int(remote_ep.rsplit(":", 1)[1])
            except Exception:
                continue

            if (
                local_port == remote_port
                and peer_port == int(server_port)
                and state in ("ESTABLISHED", "SYN_SENT", "SYN_RECEIVED")
            ):
                try:
                    pid = int(pid_text)
                except ValueError:
                    pid = None
                break

        if pid is None:
            return None, None

        cp2 = subprocess.run(
            [
                "tasklist",
                "/FI", f"PID eq {pid}",
                "/FO", "CSV",
                "/NH",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3.0,
        )

        process_name = None

        rows = list(csv.reader(io.StringIO(cp2.stdout)))

        if rows and rows[0]:
            first = rows[0][0].strip()

            if first and not first.upper().startswith("INFO:"):
                process_name = first

        return pid, process_name

    except Exception as e:
        log("PID", f"peer-process lookup failed: {type(e).__name__}: {e}")
        return None, None



# ---------------------------------------------------------------------------
# TGame / ProtocalHandler mode-4 handshake helpers (v26)
# ---------------------------------------------------------------------------

TGAME_SYN_RAND = b"LOCAL_SYN_RAND01"  # exactly 16 bytes




TGAME_KEY_ALPHABET = set(b"ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789")
TGAME_MODE3_IV = bytes(range(16))

def _tgame_enable_debug_privilege():
    """Enable SeDebugPrivilege in this server process when available."""
    if os.name != "nt":
        return False, "not-windows"
    import ctypes
    from ctypes import wintypes

    TOKEN_ADJUST_PRIVILEGES = 0x20
    TOKEN_QUERY = 0x08
    SE_PRIVILEGE_ENABLED = 0x02

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(token)):
        return False, f"OpenProcessToken err={ctypes.get_last_error()}"
    try:
        luid = LUID()
        if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False, f"LookupPrivilegeValueW err={ctypes.get_last_error()}"
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
            return False, f"AdjustTokenPrivileges err={ctypes.get_last_error()}"
        err = ctypes.get_last_error()
        if err == 1300:  # ERROR_NOT_ALL_ASSIGNED
            return False, "SeDebugPrivilege not assigned (run server elevated)"
        return True, "SeDebugPrivilege enabled"
    finally:
        k32.CloseHandle(token)



# ---------------------------------------------------------------------------
# TGame AuthAP ticket-anchored crypto-state recovery (v42)
# ---------------------------------------------------------------------------

# ProtocalHandler live AuthAP object layout, expressed relative to the first
# byte of the ticket at outer+0x3A0.  The key and ticket are copied into the
# same object by the live setter at ProtocalHandler+0x33C30.
_TGA_OFF_KEY       = -0x1B8   # outer+0x1E8, 16 bytes
_TGA_OFF_MODE      = -0x1D0   # outer+0x1D0, u32
_TGA_OFF_SVCID     = -0x1C8   # outer+0x1D8, u32
_TGA_OFF_UIN       = -0x1BC   # outer+0x1E4, u32
_TGA_OFF_TICKETLEN = -0x004   # outer+0x39C, u32
_TGA_OFF_AUTHTYPE  = +0x404   # outer+0x7A4, must be 4 for AuthAP
_TGA_OFF_HANDLER   = -0x1EC   # outer+0x1B4, CTdrProtocalHandler*
_TGA_HANDLER_CONN  = 0x88
_TGA_CONN_RAWKEY   = 0x50
_TGA_CONN_MODE     = 0x84

# A TGame process can keep the GEO AuthAP object alive while creating a second
# AuthAP object for the ZONE socket.  Both contain the same ticket.  Track the
# exact object anchor already consumed by each successful connection so the
# second handshake cannot accidentally reuse the GEO connection's key.
_TGAME_USED_AUTH_ANCHORS = {}
_TGAME_USED_AUTH_ANCHORS_LOCK = threading.Lock()


def tgame_recover_key_by_ticket(pid, ticket, want_authtype=4, exclude_anchors=None):
    """Recover the exact live TGame mode/key by anchoring on its AuthAP ticket.

    This is an exact-match, read-only lookup in the local TGame process:
      ticket bytes -> containing AuthAP object -> key/mode.

    Unlike the abandoned heuristic key scanners, candidates are accepted only
    when the surrounding object fields validate (ticket length/AuthType) and
    are independently cross-checked through CTdrProtocalHandler->hQQClt.
    """
    if os.name != "nt" or pid is None:
        return None, None, "not-windows/no-pid"
    if isinstance(ticket, str):
        ticket = ticket.encode("latin1", "replace")
    ticket = bytes(ticket or b"")
    if len(ticket) < 8:
        return None, None, f"ticket too short to anchor on ({len(ticket)}B)"

    exclude_anchors = set(int(x) for x in (exclude_anchors or ()))

    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
    ]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    def read_mem(h, addr, n):
        if not addr or addr < 0 or n <= 0:
            return None
        buf = (ctypes.c_ubyte * n)()
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(
            h, ctypes.c_void_p(int(addr)), buf, n, ctypes.byref(got)
        ):
            return None
        if got.value != n:
            return None
        return bytes(buf)

    def read_u32(h, addr):
        b = read_mem(h, addr, 4)
        return None if b is None else struct.unpack("<I", b)[0]

    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    h = k32.OpenProcess(access, False, int(pid))
    if not h:
        # Reuse the existing local-backend privilege helper once, then retry.
        _tgame_enable_debug_privilege()
        h = k32.OpenProcess(access, False, int(pid))
    if not h:
        return None, None, (
            f"OpenProcess({pid}) failed err={ctypes.get_last_error()}"
        )

    try:
        candidates = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()

        # 32-bit TGame user address range. Search only committed private pages;
        # the ticket copy lives in the mutable AuthAP object, not image/mapped data.
        while addr < 0x7FFF0000:
            q = k32.VirtualQueryEx(
                h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not q:
                break

            base = int(mbi.BaseAddress or addr)
            size = int(mbi.RegionSize or 0x1000)

            usable = (
                mbi.State == MEM_COMMIT
                and mbi.Type == MEM_PRIVATE
                and not (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                and size <= 0x04000000
            )

            if usable:
                blk = read_mem(h, base, size)
                if blk:
                    pos = blk.find(ticket)
                    while pos >= 0:
                        candidates.append(base + pos)
                        pos = blk.find(ticket, pos + 1)

            next_addr = base + max(size, 0x1000)
            if next_addr <= addr:
                break
            addr = next_addr

        if not candidates:
            return None, None, (
                f"ticket {ticket!r} not found in TGame PID={pid}"
            )

        rejected = []
        valid = []
        for anchor in candidates:
            ticket_len = read_u32(h, anchor + _TGA_OFF_TICKETLEN)
            auth_type = read_u32(h, anchor + _TGA_OFF_AUTHTYPE)

            if ticket_len != len(ticket) or auth_type != want_authtype:
                rejected.append(
                    f"{hex(anchor)}:len={ticket_len},auth={auth_type}"
                )
                continue

            key = read_mem(h, anchor + _TGA_OFF_KEY, 16)
            mode = read_u32(h, anchor + _TGA_OFF_MODE)
            if key is None or mode not in (2, 3, 4) or key == bytes(16):
                rejected.append(
                    f"{hex(anchor)}:mode={mode},key={'none' if key is None else key.hex()}"
                )
                continue

            info = {
                "source": "AuthAP ticket anchor",
                "pid": int(pid),
                "anchor": hex(anchor),
                "outer": hex(anchor - 0x3A0),
                "uin": read_u32(h, anchor + _TGA_OFF_UIN),
                "service_id": read_u32(h, anchor + _TGA_OFF_SVCID),
                "auth_type": auth_type,
                "mode": mode,
                "verified": False,
            }

            # Independent confirmation through the exact handler/connection
            # that SetEncryptMethod populates.
            handler = read_u32(h, anchor + _TGA_OFF_HANDLER)
            if handler:
                conn = read_u32(h, handler + _TGA_HANDLER_CONN)
                if conn:
                    conn_key = read_mem(h, conn + _TGA_CONN_RAWKEY, 16)
                    conn_mode = read_u32(h, conn + _TGA_CONN_MODE)
                    info["handler"] = hex(handler)
                    info["conn"] = hex(conn)
                    info["conn_mode"] = conn_mode
                    if conn_key == key and conn_mode == mode:
                        info["verified"] = True
                    else:
                        info["crosscheck_key"] = (
                            conn_key.hex() if conn_key is not None else None
                        )
                        info["crosscheck_mode"] = conn_mode

            valid.append((bool(info.get("verified")), int(anchor), key, mode, info))

        if valid:
            # Prefer a never-before-used AuthAP object for this PID. Within that
            # set, prefer a candidate independently verified through hQQClt.
            fresh = [v for v in valid if v[1] not in exclude_anchors]
            if exclude_anchors and not fresh:
                return None, None, (
                    "validated ticket anchors exist, but all belong to prior "
                    f"connections: {[hex(v[1]) for v in valid]}"
                )
            pool = fresh if fresh else valid
            pool.sort(key=lambda v: (v[0], v[1]), reverse=True)
            _verified, _anchor, key, mode, info = pool[0]
            info["fresh_for_connection"] = _anchor not in exclude_anchors
            info["candidate_count"] = len(valid)
            return key, mode, info

        return None, None, (
            "ticket anchor candidates found but none validated: "
            + "; ".join(rejected[:8])
        )
    finally:
        k32.CloseHandle(h)


def tgame_find_internal_crypto_state(pid):
    """Locate ProtocalHandler's live connection key in the local TGame process.

    Static layout recovered from ProtocalHandler.dll:
      conn+0x50 : raw 16-byte generated key
      conn+0x84 : encryption mode (2/3/4)

    This is deliberately read-only and is used only for the local replacement
    backend, because the synthetic LOCAL_TICKET_001 does not carry the original
    Tencent-side credential material needed to derive the client-generated key.
    """
    if os.name != "nt" or pid is None:
        return None, None, "not-windows/no-pid"

    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01
    # ProtocalHandler connection objects are mutable process-private storage.
    # Exclude mapped/image pages: v35's three "AchievementSyste" hits were
    # static image strings that merely happened to satisfy the alphabet test.
    WRITABLE_PROTECT = {0x04, 0x08, 0x40, 0x80}  # RW/WC and executable variants

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
    ]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    # v27 hit ERROR_ACCESS_DENIED (5) here. Enable SeDebugPrivilege first,
    # then try the smallest useful access mask before adding query rights.
    dbg_ok, dbg_status = _tgame_enable_debug_privilege()

    # VirtualQueryEx needs query rights as well as VM_READ.  v28 accepted
    # a VM_READ-only handle, then its first VirtualQueryEx returned zero, which
    # looked like "no key candidate".  Prefer QUERY+VM_READ in v29.
    attempts = [
        ("QUERY+VM_READ", PROCESS_QUERY_INFORMATION | PROCESS_VM_READ),
        ("QUERY_LIMITED+VM_READ", 0x1000 | PROCESS_VM_READ),
    ]
    h = None
    errs = []
    for label, access in attempts:
        ctypes.set_last_error(0)
        h_try = k32.OpenProcess(access, False, int(pid))
        if h_try:
            h = h_try
            open_label = label
            break
        errs.append(f"{label}=err{ctypes.get_last_error()}")
    if not h:
        return None, None, (
            f"OpenProcess denied after privilege setup ({dbg_status}); "
            + ", ".join(errs)
        )

    candidates = []
    try:
        addr = 0x10000
        mbi = MEMORY_BASIC_INFORMATION()
        max_addr = 0x7FFF0000
        regions_seen = 0
        readable_regions = 0
        while addr < max_addr:
            ctypes.set_last_error(0)
            n = k32.VirtualQueryEx(
                h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not n:
                err = ctypes.get_last_error()
                if regions_seen == 0:
                    return None, None, (
                        f"VirtualQueryEx failed before first region err={err} "
                        f"open={open_label} privilege={dbg_status}"
                    )
                break
            regions_seen += 1
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            base_protect = int(mbi.Protect) & 0xFF
            if (mbi.State == MEM_COMMIT and
                    int(mbi.Type) == MEM_PRIVATE and
                    base_protect in WRITABLE_PROTECT and
                    size and
                    not (mbi.Protect & PAGE_GUARD) and
                    not (mbi.Protect & PAGE_NOACCESS)):
                readable_regions += 1
                # Keep reads bounded; connection objects are small and a
                # generated key cannot straddle more than our overlap.
                off = 0
                overlap = b""
                while off < size:
                    want = min(8 * 1024 * 1024, size - off)
                    buf = ctypes.create_string_buffer(want)
                    got = ctypes.c_size_t()
                    ok = k32.ReadProcessMemory(
                        h, ctypes.c_void_p(base + off), buf, want, ctypes.byref(got)
                    )
                    if ok and got.value:
                        chunk = overlap + buf.raw[:got.value]
                        origin = base + off - len(overlap)
                        # v30 FAST PATH: do not test every byte in Python.
                        # Search only 16-byte runs from ProtocalHandler's exact
                        # generator alphabet, then validate conn+0x84 mode.
                        import re
                        alphabet = b"ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
                        aset = set(alphabet)
                        key_re = re.compile(
                            rb"[ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789]{16}"
                        )
                        for m in key_re.finditer(chunk):
                            i = m.start()
                            if i + 0x38 > len(chunk):
                                continue

                            # The live key is a fixed 16-byte field at conn+0x50.
                            # v35 false positives were 16-byte windows inside
                            # longer printable identifiers ("AchievementSyste",
                            # "72a525cnpExitInt"). Reject any candidate that is
                            # immediately adjacent to another generator-alphabet
                            # byte; that makes it a substring, not a standalone
                            # 16-byte key field.
                            if i > 0 and chunk[i - 1] in aset:
                                continue
                            if i + 16 < len(chunk) and chunk[i + 16] in aset:
                                continue

                            mode = struct.unpack_from("<I", chunk, i + 0x34)[0]

                            # This TGame AUTH path advertises field0=3 on every
                            # captured cmd03.  Do not let unrelated mode-2/4
                            # coincidences enter the candidate pool.
                            if mode != 3:
                                continue

                            key = bytes(m.group(0))

                            # Generated keys should look random rather than like
                            # English/C++ identifiers.  Use diversity as a
                            # rejection filter, but do not require a digit
                            # (a legitimate random key can contain none).
                            distinct = len(set(key))
                            transitions = sum(
                                1 for a, b in zip(key, key[1:])
                                if (65 <= a <= 90) != (65 <= b <= 90)
                                or (48 <= a <= 57) != (48 <= b <= 57)
                            )
                            if distinct < 10 or transitions < 3:
                                continue

                            candidates.append((origin + i, key, mode))
                        overlap = chunk[-0x50:]
                    else:
                        overlap = b""
                    off += want
            nxt = base + max(size, 0x1000)
            if nxt <= addr:
                break
            addr = nxt
    finally:
        k32.CloseHandle(h)

    # Deduplicate exact address/key/mode tuples.
    uniq = []
    seen = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            uniq.append(item)

    if not uniq:
        return None, None, (
            "no ProtocalHandler key-layout candidate found "
            f"(regions={regions_seen} readable={readable_regions} "
            f"open={open_label} privilege={dbg_status})"
        )

    # Only mutable MEM_PRIVATE candidates reach this point. field0 in the
    # observed cmd03 is 3; prefer mode 3 when present, but never guess between
    # multiple live-looking objects.
    mode3 = [x for x in uniq if x[2] == 3]
    pool = mode3 if mode3 else uniq
    if len(pool) != 1:
        detail = ", ".join(
            f"0x{a:08X}:{k.decode('ascii','replace')}:m{m}" for a,k,m in pool[:8]
        )
        return None, None, f"ambiguous crypto-state candidates ({len(pool)}): {detail}"

    a, key, mode = pool[0]
    return key, mode, (
        f"TGame memory key@0x{a:08X} conn@0x{a-0x50:08X} "
        f"open={open_label} privilege={dbg_status}"
    )


def _tgame_mode3_cbc_encrypt(framed, key):
    """ProtocalHandler +0x8B710 direction=1: AES-CBC with IV 00..0F.

    Static translation of the DLL helper: XOR each plaintext block with the
    previous ciphertext block (the fixed IV for block 0), then AES-encrypt.
    """
    if len(framed) & 0x0F:
        raise ValueError("mode3 framed plaintext must be block aligned")
    aes = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    prev = TGAME_MODE3_IV
    out = bytearray()
    for off in range(0, len(framed), 16):
        block = bytes(a ^ b for a, b in zip(framed[off:off+16], prev))
        c = aes.update(block)
        out += c
        prev = c
    aes.finalize()
    return bytes(out)


def _tgame_mode3_cbc_decrypt(ciphertext, key):
    """Inverse of ProtocalHandler +0x8B710 direction=0."""
    if len(ciphertext) & 0x0F:
        raise ValueError("mode3 ciphertext must be block aligned")
    aes = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    prev = TGAME_MODE3_IV
    out = bytearray()
    for off in range(0, len(ciphertext), 16):
        c = bytes(ciphertext[off:off+16])
        p0 = aes.update(c)
        out += bytes(a ^ b for a, b in zip(p0, prev))
        prev = c
    aes.finalize()
    return bytes(out)


def tgame_mode3_encrypt(plain, key):
    """Exact framing used by ProtocalHandler mode-3 encoder (+0x8B8E0)."""
    if len(key) != 16:
        raise ValueError("mode3 requires a 16-byte AES key")
    rem = len(plain) & 0x0F
    pad_len = (16 if rem <= 10 else 32) - rem
    random_len = pad_len - 6
    if random_len < 0:
        raise ValueError("invalid mode3 padding calculation")
    framed = bytes(plain) + os.urandom(random_len) + b"tsf4g" + bytes([pad_len])
    if len(framed) % 16:
        raise AssertionError("mode3 framed length is not block aligned")
    return _tgame_mode3_cbc_encrypt(framed, key)


def tgame_mode3_decrypt(ciphertext, key):
    """ProtocalHandler mode-3 decoder (+0x8BAA0), inverse of +0x8B8E0."""
    if len(key) != 16:
        raise ValueError("mode3 requires a 16-byte AES key")
    if not ciphertext or (len(ciphertext) & 0x0F):
        raise ValueError("mode3 ciphertext must be a non-empty multiple of 16")
    framed = _tgame_mode3_cbc_decrypt(bytes(ciphertext), key)
    if len(framed) < 16 or framed[-6:-1] != b"tsf4g":
        raise ValueError("mode3 trailer mismatch")
    pad_len = framed[-1]
    if pad_len <= 0 or pad_len > len(framed):
        raise ValueError("mode3 invalid padding length")
    payload_len = len(framed) - pad_len
    rem = payload_len & 0x0F
    expected = (16 if rem <= 10 else 32) - rem
    if pad_len != expected:
        raise ValueError(f"mode3 padding mismatch got={pad_len} expected={expected}")
    return framed[:payload_len]

def tgame_parse_wire_encrypted_body(pkt):
    """Parse the compact cmd08/cmd09 wire form used by this TGame build."""
    if len(pkt) < 13 or pkt[0:2] != b"\x55\x0e":
        raise ValueError("not a TGame compact TPDU")
    total = struct.unpack(">I", pkt[4:8])[0]
    enc_len = pkt[12]
    if 13 + enc_len > len(pkt):
        raise ValueError(
            f"truncated encrypted body len={enc_len} packet={len(pkt)}"
        )
    return pkt[2], total, pkt[13:13 + enc_len]


def tgame_parse_generic_body(pkt):
    """Parse the normal 12-byte TPDUBase + encrypted body form.

    After CHGSKEY, TGame switches from SYN/SYNACK head-extension traffic to
    ordinary cmd00 packets whose encrypted payload length is BodyLen at +8.
    """
    if len(pkt) < 12 or pkt[0:2] != b"\x55\x0e":
        raise ValueError("not a TGame TPDU")
    cmd = pkt[2]
    head_len = struct.unpack(">I", pkt[4:8])[0]
    body_len = struct.unpack(">I", pkt[8:12])[0]
    if head_len < 12 or head_len > len(pkt):
        raise ValueError(
            f"invalid TPDU head_len={head_len} packet={len(pkt)}"
        )
    if head_len + body_len > len(pkt):
        raise ValueError(
            f"truncated TPDU body len={body_len} head={head_len} packet={len(pkt)}"
        )
    return cmd, head_len, body_len, pkt[head_len:head_len + body_len]


def tgame_split_generic_stream(data):
    """Split a TCP byte stream into complete post-CHGSKEY TGame TPDU frames.

    TCP recv() is not message-framed: one recv may contain multiple TPDUs,
    or only part of one TPDU.  Generic post-CHGSKEY frames are self-sized by
    HeadLen (+4) + BodyLen (+8), both big-endian u32 values.
    """
    data = bytes(data)
    frames = []
    off = 0

    while len(data) - off >= 12:
        if data[off:off + 2] != b"\x55\x0e":
            raise ValueError(
                f"stream desync at +0x{off:x}: "
                f"{data[off:off + 16].hex()}"
            )

        head_len = struct.unpack(">I", data[off + 4:off + 8])[0]
        body_len = struct.unpack(">I", data[off + 8:off + 12])[0]

        if head_len < 12 or head_len > 0x10000:
            raise ValueError(
                f"invalid stream HeadLen={head_len} at +0x{off:x}"
            )

        frame_len = head_len + body_len
        if frame_len < 12 or frame_len > 0x400000:
            raise ValueError(
                f"invalid stream frame_len={frame_len} at +0x{off:x}"
            )

        if len(data) - off < frame_len:
            break

        frames.append(data[off:off + frame_len])
        off += frame_len

    return frames, data[off:]


# C2GEO application protocol, confirmed from proto_c2geo.tdr:
#   magic 0x8202
#   C2GEO_REQ_PINGLIST = 0x1001
#   GEO2C_RES_PINGLIST = 0x2001
# C2GEOPkgHead is four big-endian u16 fields:
#   Magic, Cmd, HeadLen, BodyLen
# GEO2C_ResPingList with ServerCount=0 serializes to:
#   Result(u16), ServerCount(u16), MaxDelayInMs(u32)
TGAME_GEO_MAGIC = 0x8202
TGAME_GEO_REQ_ZONELIST = 0x1000
TGAME_GEO_RES_ZONELIST = 0x2000
TGAME_GEO_REQ_PINGLIST = 0x1001
TGAME_GEO_RES_PINGLIST = 0x2001

# Recovered from proto_c2geo.tdr / proto_c2zn.tdr macro tables.
GEO_ERR_SUCC = 0x8B00
ZONE_ERR_SUCC = 0x8100

TGAME_ZN_MAGIC = 0x3243
TGAME_ZN_REQ_LOGIN = 0xA000
TGAME_ZN_RES_LOGIN = 0xA001
TGAME_ZN_REQ_CREATEACCOUNT = 0xA002
TGAME_ZN_RES_CREATEACCOUNT = 0xA003
TGAME_ZN_REQ_HEARTBEAT = 0xA004
TGAME_ZN_NTF_PLAYERINFO = 0xA005
TGAME_ZN_NTF_PLAYERPROPS = 0xA006

# v88: runtime player-update sequence.
# A008/A009 are Req/ResPropOperation. The compiled enum sequence places
# NtfPropOperation immediately before NtfUpdatePlayerProperty.
TGAME_ZN_REQ_PROP_OPERATION = 0xA008
TGAME_ZN_RES_PROP_OPERATION = 0xA009
TGAME_ZN_NTF_PROP_OPERATION = 0xA00A
TGAME_ZN_NTF_UPDATE_PLAYER_PROPERTY = 0xA00B

# EUpdatePropertyFlag values recovered from proto_c2zn.tdr.
UPDATE_FLAG_TP = 0       # PH client renders this premium wallet as AP
UPDATE_FLAG_GP = 1
UPDATE_FLAG_EXP = 2
UPDATE_FLAG_PROP = 3
UPDATE_FLAG_MP = 4

# Exact EUpdatePropertyType numeric values from the compiled proto_c2zn.tdr
# enum metadata (not ordinal/string positions): BUY=0x08, TPBALANCE=0x30.
# v89 accidentally changed these to 0x01/0x27, which made the PH client
# ignore the AP/TP wallet notification even though the payload was valid.
UPDATE_REASON_BUY = 0x08
UPDATE_REASON_TP_BALANCE = 0x30

# Compiled proto_c2zn.tdr command metadata: ZN2C_NtfMoneyFlow = 0xE001.
# E004 is ZN2C_NtfFinishLocalMatch; A354 is a different request path.
TGAME_ZN_NTF_MONEYFLOW = 0xE001

# Background messages observed during the same shop flow.
TGAME_ZN_REQ_CARDINFO = 0xC00D
TGAME_ZN_RES_CARDINFO = 0xC00E
TGAME_ZN_NTF_ANTIBOTMSG_C2S = 0xFF02

# v75: shop / inventory / loadout protocol recovered from proto_c2zn.tdr.
TGAME_ZN_REQ_CHANGE_ROLE = 0xA146
TGAME_ZN_RES_CHANGE_ROLE = 0xA147
TGAME_ZN_REQ_ITEM_OPERATION = 0xA200
TGAME_ZN_RES_ITEM_OPERATION = 0xA201
TGAME_ZN_REQ_SHOPCONFHASH = 0xA361
TGAME_ZN_RES_SHOPCONFHASH = 0xA362
TGAME_ZN_REQ_DROPPROP = 0xA363
TGAME_ZN_RES_DROPPROP = 0xA364
TGAME_ZN_NTF_COMMODITYINFO = 0xA365
TGAME_ZN_REQ_UPDATECOMMODITYFILE = 0xA503
TGAME_ZN_RES_UPDATECOMMODITYFILE = 0xA504
TGAME_ZN_REQ_BUYCOMMODITY = 0xA505
TGAME_ZN_RES_BUYCOMMODITY = 0xA506
# Live TGame sends A50E with exactly one u64 UIN when the shop asks for
# the premium-currency balance.  The reply is the A00B property update.
TGAME_ZN_REQ_TP_BALANCE = 0xA50E

# PayTypeEnums.  Live captures independently confirm GP=1 and MP=3.
PAY_GP = 1
PAY_TP = 2      # PH client labels this wallet AP
PAY_MP = 3
PAY_TPMP = 4
PAY_TPVOUCHER = 5

# ShopError enum is contiguous from the known base SHOP_ERR_SUCC=0x8200.
SHOP_ERR_SUCC = 0x8200
SHOP_ERR_FAIL = 0x8201
SHOP_ERR_COMMODITY_NOTEXIST = 0x8202
SHOP_ERR_COMMODITY_PERIODINVALID = 0x8208
SHOP_ERR_SHOPCART_EMPTY = 0x820A
SHOP_ERR_NOTENOUGHMONEY = 0x820B
SHOP_ERR_PAYTYPE_INVALID = 0x820C

PROP_OP_EQUIP = 0
PROP_OP_TAKEOFF = 1
PROP_OP_DROP = 2

PROP_LOC_ROLE1 = 0x0A
PROP_LOC_ROLE2 = 0x0B
PROP_LOC_BAG = 0x0C

PROP_GAIN_BUY = 1
LOCAL_UIN = 10001
LOCAL_TP_BALANCE = 100_000  # protocol TP == PH client AP
LOCAL_GP_BALANCE = 100_000
LOCAL_MP_BALANCE = 100_000
LOCAL_ITEM_AVAIL_HOURS = 720  # 30 days; safe non-zero first-pass period

# v80: give the profile a concrete current-role PropInfo.  In the v79 live
# capture TGame sent A008 with TargetGID/OwnerPropId=0 because CurRoleGID was
# zero and the login A006 contained no role prop.  Chief is a valid role entry
# from this client's decoded commodity/item catalog (commodity 200088).
LOCAL_ROLE_ITEM_ID = 100014
LOCAL_ROLE_GID = ((LOCAL_UIN & 0xffffffff) << 32) | 1
LOCAL_ROLE_AVAIL_HOURS = 24 * 365 * 10

# v81 starter backpack entitlements decoded from DefaultItemLibrary.ini.
# 100026 ItemName=Package, ResID1=0x40000000, bDefaultItem=true, Location=Bag.
# 100063 ItemName=Bag2, ResID1=0x40100000, description=opens backpack slot 2.
LOCAL_BAG1_ITEM_ID = 100026
LOCAL_BAG2_ITEM_ID = 100063
LOCAL_BAG1_GID = ((LOCAL_UIN & 0xffffffff) << 32) | 2
LOCAL_BAG2_GID = ((LOCAL_UIN & 0xffffffff) << 32) | 3
LOCAL_BAG_AVAIL_HOURS = 24 * 365 * 10

# PlayerMoneyFlow enums recovered from proto_c2zn.tdr.
MONEYTYPE_TP = 0
MONEYTYPE_GP = 1
MONEYTYPE_MP = 2
# Exact compiled MoneyFlowReason enum metadata: NEWACCOUNT=0x0B, BUY=0x0C.
MONEYREASON_BUY = 0x0C

# v90-shopfix: E001 + DWORD Count + 26-byte PlayerMoneyFlow is now pinned by
# proto_c2zn.tdr and the TGame Consumer List handler, so emit purchase rows.
ENABLE_MONEYFLOW_NOTIFICATIONS = True

# Optional exact CommodityId -> ItemId overrides. The live shop request contains
# CommodityId but not ItemId; the client normally gets that mapping from its
# CommodityLibrary. If a SKU does not share its ItemId, put it in
# shop_item_map.json beside this server, e.g. {"123456": 7890}.
SHOP_ITEM_OVERRIDES = {
    200001: 100001,  # 'M4A1 [AF]' items=[100001]
    200002: 100002,  # 'AK47-R ' items=[100002]
    200003: 100003,  # 'MP5 ' items=[100003]
    200004: 100004,  # 'Remington MSR ' items=[100004]
    200005: 100005,  # 'Desert Eagle ' items=[100005]
    200006: 100006,  # 'AK47 [AF]' items=[100006]
    200007: 100007,  # 'Benelli Nova' items=[100007]
    200008: 100008,  # 'M249' items=[100008]
    200009: 100009,  # 'USP' items=[100009]
    200010: 100010,  # 'Frag Grenade' items=[100010]
    200011: 100011,  # 'Flashbang' items=[100011]
    200012: 100012,  # 'Smoke Bomb' items=[100012]
    200019: 100016,  # 'Falcon' items=[100016, 300012, 300013, 100023]
    200020: 100027,  # 'SCAR' items=[100027]
    200021: 100032,  # 'Bulletproof Helmet' items=[100032]
    200022: 100033,  # 'Bulletproof Vest' items=[100033]
    200026: 100035,  # 'No.3 Backpack' items=[100035]
    200027: 100036,  # 'No.4 Backpack' items=[100036]
    200028: 100037,  # 'No.5 Backpack' items=[100037]
    200029: 100069,  # 'Dutch' items=[100069, 300032, 300033, 100322]
    200031: 100041,  # 'Steyr Aug A1' items=[100041]
    200032: 200001,  # 'Borders a badge ' items=[200001]
    200033: 200002,  # 'Badges border 2 ' items=[200002]
    200034: 200003,  # 'Badges border 3 ' items=[200003]
    200035: 200004,  # 'Badges border 4 ' items=[200004]
    200036: 200005,  # 'Badges border 5 ' items=[200005]
    200037: 200006,  # 'Badges border 6 ' items=[200006]
    200038: 200007,  # 'Badges Borders 7 ' items=[200007]
    200039: 200008,  # 'Badges Borders 8 ' items=[200008]
    200040: 200009,  # 'Badges border 9 ' items=[200009]
    200041: 200010,  # 'Badges border 10 ' items=[200010]
    200042: 210001,  # 'Insignia 1 ' items=[210001]
    200043: 210002,  # 'Insignia 2 ' items=[210002]
    200044: 210003,  # 'Insignia 3 ' items=[210003]
    200045: 210004,  # 'Insignia 4 ' items=[210004]
    200046: 210005,  # 'Insignia 5 ' items=[210005]
    200047: 210006,  # 'Insignia 6 ' items=[210006]
    200048: 210007,  # 'Insignia 7 ' items=[210007]
    200049: 210008,  # 'Insignia 8 ' items=[210008]
    200050: 210009,  # 'Insignia 9 ' items=[210009]
    200051: 210010,  # 'Insignia 10 ' items=[210010]
    200052: 220001,  # 'Background a badge ' items=[220001]
    200053: 220002,  # 'Badges Background 2 ' items=[220002]
    200054: 220003,  # 'Badges background 3 ' items=[220003]
    200055: 220004,  # 'Badge background 4 ' items=[220004]
    200056: 220005,  # 'Badges background 5 ' items=[220005]
    200057: 220006,  # 'Badges background 6 ' items=[220006]
    200058: 220007,  # 'Badges background 7 ' items=[220007]
    200059: 220008,  # 'Badges background 8 ' items=[220008]
    200060: 220009,  # 'Badges background 9 ' items=[220009]
    200061: 220010,  # 'Badges Background 10 ' items=[220010]
    200062: 100054,  # 'Speakers' items=[100054]
    200064: 100056,  # 'Arctic WM' items=[100056]
    200065: 100057,  # 'Barett M95' items=[100057]
    200066: 100058,  # 'Jungle Bolo' items=[100058]
    200067: 100059,  # 'Regular EXP Bonus Card' items=[100059]
    200068: 100060,  # 'Advance EXP Bonus Card' items=[100060]
    200069: 100061,  # 'Jason' items=[100061, 300022, 300023, 100325]
    200070: 100062,  # 'Yuri' items=[100062, 300027, 300028]
    200071: 100064,  # 'HK G3/SG2' items=[100064]
    200074: 100068,  # 'RPK' items=[100068]
    200075: 100017,  # 'Advance Combat Helmet (Chief)' items=[100017]
    200076: 100018,  # 'M44 Gas Mask (Chief)' items=[100018]
    200077: 100019,  # 'Portable Belt (Chief)' items=[100019]
    200082: 100024,  # 'Electronic Eye (Falcon)' items=[100024]
    200083: 100025,  # 'Hunting Belt (Falcon)' items=[100025]
    200086: 100031,  # 'Sting Belt (Mac)' items=[100031]
    200087: 100028,  # 'MAC' items=[100028, 100029, 100030, 300017, 300018]
    200088: 100014,  # 'Chief' items=[100014, 300002, 300003]
    200089: 100070,  # 'QBZ-95' items=[100070]
    200090: 100071,  # 'Remington 700' items=[100071]
    200091: 100072,  # 'Tauras M608' items=[100072]
    200092: 100073,  # 'AN-94' items=[100073]
    200093: 100074,  # 'M60' items=[100074]
    200094: 100075,  # 'FAMAS' items=[100075]
    200095: 100076,  # 'SVD' items=[100076]
    200096: 100077,  # 'Titanium Blackblade' items=[100077]
    200097: 100078,  # 'Mountain Pick' items=[100078]
    200098: 100079,  # 'HE Grenade' items=[100079]
    200099: 100080,  # 'M134 Minigun' items=[100080]
    200100: 100081,  # 'Respiratory Mask (Yuri)' items=[100081]
    200101: 100082,  # 'Military sunglasses (Jason)' items=[100082]
    200102: 100083,  # 'Night Vision (Yuri)' items=[100083]
    200103: 100084,  # 'Diving goggles (Mac)' items=[100084]
    200104: 100085,  # 'Wind mirrors (Chief)' items=[100085]
    200105: 100086,  # 'Aviator classics (Dutch)' items=[100086]
    200106: 100087,  # 'White framed glasses (Dutch)' items=[100087]
    200107: 100088,  # 'Black-rimmed glasses (Jason)' items=[100088]
    200108: 100089,  # 'Military combat helmet (Yuri)' items=[100089]
    200109: 100090,  # 'Federal cap (Yuri)' items=[100090]
    200110: 100091,  # 'Red lightening headscarf (Mac)' items=[100091]
    200111: 100092,  # 'Guardian cap (Chief)' items=[100092]
    200112: 100093,  # 'Vodka belt (Yuri)' items=[100093]
    200113: 100094,  # 'Guardian belt (Chief)' items=[100094]
    200114: 100095,  # 'Tactical belt (Yuri)' items=[100095]
    200115: 100096,  # 'DJ Gadgets (Mac)' items=[100096]
    200116: 100097,  # 'Striped cross belt (Dutch)' items=[100097]
    200117: 100098,  # 'Bullet belt (Dutch)' items=[100098]
    200118: 100099,  # 'AR15' items=[100099]
    200119: 100100,  # 'Minimi Machine Gun' items=[100100]
    200120: 100101,  # 'Police belt (Jason)' items=[100101]
    200121: 100102,  # 'Marching belt (Jason)' items=[100102]
    200122: 100103,  # 'Hunters hat (Falcon)' items=[100103]
    200123: 100104,  # 'Skull patch (Falcon)' items=[100104]
    200124: 100105,  # 'Benelli Super 90' items=[100105]
    200128: 100111,  # 'P90' items=[100111]
    200129: 100112,  # 'JSS Sub' items=[100112]
    200130: 100113,  # 'Dual Uzi' items=[100113]
    200131: 100114,  # 'FN FAL' items=[100114]
    200132: 100115,  # 'Zhao' items=[100115, 300037, 300038, 100130]
    200133: 100116,  # 'Special combat goggles (Zhao)' items=[100116]
    200134: 100117,  # 'Dust masks (Zhao)' items=[100117]
    200135: 100118,  # 'Spec Ops Helmet (Zhao)' items=[100118]
    200136: 100119,  # 'Spec Ops Fighting Cap (Zhao)' items=[100119]
    200137: 100120,  # 'Lightweight Belt (Zhao)' items=[100120]
    200138: 100121,  # 'Eastern Alliance Belt (Zhao)' items=[100121]
    200139: 100122,  # 'XM8' items=[100122]
    200140: 100123,  # 'Omar' items=[100123, 300042, 300043, 100131]
    200141: 100124,  # 'Sandy washcloth (Omar)' items=[100124]
    200142: 100125,  # 'Desert wolf mask (Omar)' items=[100125]
    200143: 100126,  # 'Guerilla Headgear (Omar)' items=[100126]
    200144: 100127,  # 'Arab headscarf (Omar)' items=[100127]
    200145: 100128,  # 'Damascus broadsword (Omar)' items=[100128]
    200146: 100129,  # 'Bomber belt (Omar)' items=[100129]
    200147: 100133,  # 'SPAS-12' items=[100133]
    200148: 100134,  # 'Colt 1873' items=[100134]
    200159: 100143,  # 'Grenade Pack' items=[100143]
    200161: 100145,  # 'Rifle Magazine' items=[100145]
    200162: 100146,  # 'Machine gun Magazine' items=[100146]
    200163: 100147,  # 'Sniper Rifle magazine' items=[100147]
    200164: 100148,  # 'Submachine gun Magazine' items=[100148]
    200165: 100149,  # 'Shotgun Magazine' items=[100149]
    200166: 100150,  # 'Pistol Magazine' items=[100150]
    200169: 100153,  # 'Angel ' items=[100153, 300047, 300048, 100226]
    200170: 100154,  # "Wolf's Head Pattern" items=[100154]
    200171: 100155,  # "Lion's Head Pattern" items=[100155]
    200172: 100156,  # 'Shark pattern' items=[100156]
    200173: 100157,  # 'Grenade Pattern' items=[100157]
    200174: 100158,  # 'Handprint' items=[100158]
    200175: 100159,  # 'Dagger Pattern' items=[100159]
    200176: 100160,  # 'Headshot Pattern' items=[100160]
    200177: 100161,  # 'Star Pattern' items=[100161]
    200178: 100162,  # 'Demon Pattern' items=[100162]
    200179: 100163,  # 'Bullets Pattern' items=[100163]
    200180: 100164,  # 'Gear Pattern' items=[100164]
    200181: 100165,  # 'Sickle Pattern' items=[100165]
    200182: 100166,  # 'Wings Pattern' items=[100166]
    200183: 100167,  # 'Snake Pattern' items=[100167]
    200184: 100168,  # 'Poison Pattern' items=[100168]
    200185: 100169,  # 'Radiation Pattern' items=[100169]
    200186: 100170,  # 'War Pattern' items=[100170]
    200187: 100171,  # 'F2000' items=[100171]
    200188: 100172,  # 'AK74U' items=[100172]
    200190: 100174,  # 'M4A1-S' items=[100174]
    200191: 100175,  # 'M4A1-H' items=[100175]
    200192: 100176,  # 'M4A1-P' items=[100176]
    200193: 100177,  # 'AWM-S' items=[100177]
    200194: 100178,  # 'AWM-T' items=[100178]
    200195: 100179,  # 'Glock 17' items=[100179]
    200196: 100180,  # 'Boxing Gloves' items=[100180]
    200197: 100181,  # 'Rename Card' items=[100181]
    200198: 100182,  # 'K/D Record Clear Card' items=[100182]
    200199: 100183,  # 'Special Ray package ' items=[100183]
    200200: 100184,  # 'Rinvay' items=[100184, 300052, 300053]
    200201: 100196,  # 'Winlose clear card' items=[100196]
    200202: 100197,  # 'C4 Defuse Kit' items=[100197]
    200203: 100198,  # 'SIG SG 551' items=[100198]
    200204: 100199,  # 'Sato' items=[100199, 300057, 300058]
    200205: 100200,  # 'Lightning Helmet (Sato)' items=[100200]
    200206: 100201,  # 'Rider Wind Mirrors (Sato)' items=[100201]
    200207: 100202,  # 'Champion Mask (Sato)' items=[100202]
    200208: 100203,  # 'Driver Tool Pockets (Sato)' items=[100203]
    200210: 100205,  # 'Extended Skills grid ' items=[100205]
    200211: 100206,  # 'FAMAS-R' items=[100206]
    200212: 100207,  # 'Desert Eagle-A' items=[100207]
    200213: 100208,  # 'Sapper Shovel' items=[100208]
    200215: 100210,  # 'Big kill magazine ' items=[100210]
    200217: 100141,  # 'AR15-A ' items=[100141]
    200218: 100214,  # 'CT Zaytsev-1' items=[100214]
    200219: 100211,  # 'Resurrection currency ' items=[100211]
    200220: 100212,  # 'Holiday grenades ' items=[100212]
    200221: 210011,  # 'Insignia 11 ' items=[210011]
    200222: 210012,  # 'Insignia 12 ' items=[210012]
    200223: 210013,  # 'Insignia 13 ' items=[210013]
    200224: 210014,  # 'Insignia 14 ' items=[210014]
    200225: 210015,  # 'Insignia 15 ' items=[210015]
    200226: 210016,  # 'Insignia 16 ' items=[210016]
    200227: 210017,  # 'Insignia 17 ' items=[210017]
    200228: 210018,  # 'Insignia 18 ' items=[210018]
    200229: 210019,  # 'Insignia 19 ' items=[210019]
    200230: 210020,  # 'Insignia 20 ' items=[210020]
    200231: 100215,  # 'AR15-FELN' items=[100215]
    200232: 100216,  # 'Ramirez' items=[100216, 300062, 300063, 100218, 100323]
    200233: 100217,  # 'Hawkins' items=[100217, 300067, 300068, 100219, 100324]
    200234: 100220,  # 'M4A1-M' items=[100220]
    200235: 100221,  # 'Ak47-T' items=[100221]
    200236: 100222,  # 'Beretta 92' items=[100222]
    200237: 100223,  # 'Dragon Belt (Rinvay)' items=[100223]
    200238: 100224,  # 'GSDU Headset (Jason)' items=[100224]
    200244: 100230,  # 'India glasses (Rinvay)' items=[100230]
    200246: 100232,  # 'QJY-88' items=[100232]
    200247: 100238,  # 'Jackhammer M3-A2' items=[100238]
    200248: 100239,  # 'Army Hand Axe' items=[100239]
    200249: 100240,  # 'Alien lure Ray ' items=[100240]
    200250: 100241,  # 'Jetpack' items=[100241]
    200251: 100242,  # 'Super Storm Mech license I ' items=[100242]
    200252: 100243,  # 'Super Storm Mech license II' items=[100243]
    200253: 100244,  # 'Super behemoth mech license ' items=[100244]
    200254: 100245,  # 'Supply tank shells ' items=[100245]
    200255: 100246,  # 'Tank armor ' items=[100246]
    200263: 100259,  # 'Fool grenade ' items=[100259]
    200264: 100260,  # 'QBU-88' items=[100260]
    200265: 100261,  # 'UMP45' items=[100261]
    200266: 100262,  # 'AK47-B' items=[100262]
    200267: 100263,  # 'SWM629SH' items=[100263]
    200268: 100264,  # 'Pale Lightning Helmet' items=[100264]
    200269: 100265,  # 'Dragon Headband (Rinvay)' items=[100265]
    200270: 100266,  # 'Dragon Glasses (Rinvay)' items=[100266]
    200271: 100267,  # 'Beastmaster Headscarf' items=[100267]
    200272: 100268,  # 'Spotted scarf (Hawkins)' items=[100268]
    200273: 100269,  # 'Perak Pockets (Ramirez)' items=[100269]
    200274: 100270,  # 'Alpha ' items=[100270, 300072, 300073]
    200275: 100271,  # 'Perak ' items=[100271, 300077, 300078, 100273]
    200276: 100272,  # 'Gerbils wind mirror ' items=[100272]
    200279: 100275,  # 'Alpha wind mirror ' items=[100275]
    200280: 100276,  # 'Alpha Combat Helmet ' items=[100276]
    200281: 100277,  # 'International Police Belt ' items=[100277]
    200282: 100278,  # 'Lurking masks ' items=[100278]
    200283: 100279,  # 'Latent mask (Ramirez)' items=[100279]
    200287: 100283,  # 'RPK-S ' items=[100283]
    200288: 100284,  # '????MINIGUN' items=[100284]
    200291: 100287,  # 'SCAR-S ' items=[100287]
    200293: 100289,  # 'Labor shovel ' items=[100289]
    200295: 100291,  # 'AK47 ' items=[100291]
    200296: 100292,  # 'M4A1 ' items=[100292]
    200297: 100293,  # 'AWM ' items=[100293]
    200298: 100294,  # 'AWM-A ' items=[100294]
    200302: 100295,  # '92 pistol ' items=[100295]
    200303: 100296,  # 'OTs-14 ' items=[100296]
    200304: 100297,  # 'M240LW ' items=[100297]
    200305: 100298,  # 'AK47-A ' items=[100298]
    200310: 100303,  # 'Female fighting belt ' items=[100303]
    200311: 100304,  # 'Gucci glasses ' items=[100304]
    200312: 100305,  # 'Paladin cap ' items=[100305]
    200314: 100307,  # 'Mutation grenade ' items=[100307]
    200316: 100309,  # 'KACSAW ' items=[100309]
    200317: 100310,  # 'Variation of the virus ' items=[100310]
    200318: 100311,  # 'Variation magazine ' items=[100311]
    200319: 100312,  # 'Candy Bomb ' items=[100312]
    200320: 100320,  # 'Standard headphone battle ' items=[100320]
    200321: 100321,  # 'Red Devils battle headphones ' items=[100321]
    200322: 100326,  # 'Gold Medal Arctic WM-S' items=[100326]
    200323: 100327,  # 'Silver Medal Arctic WM-S' items=[100327]
    200324: 100328,  # 'Bronze Medal Arctic WM-S' items=[100328]
    200325: 100329,  # 'Gold Medal M4A1-S' items=[100329]
    200326: 100330,  # 'Silver Medal M4A1-S' items=[100330]
    200327: 100331,  # 'Bronze Medal M4A1-S' items=[100331]
    200328: 100332,  # 'Target Pattern' items=[100332]
    200329: 100333,  # 'Wolf spy ' items=[100333, 300082, 300083, 100335]
    200330: 100334,  # 'Impartial ' items=[100334, 300087, 300088]
    200331: 100336,  # 'M4A1-A ' items=[100336]
    200332: 100337,  # 'AR15-S ' items=[100337]
    200336: 100341,  # 'OPS bulletproof helmet ' items=[100341]
    200342: 100347,  # 'Championship belt ' items=[100347]
    200343: 100348,  # 'TAR21 ' items=[100348]
    200344: 100349,  # 'A-Point Pattern' items=[100349]
    200345: 100350,  # 'B-Point Pattern' items=[100350]
    200346: 100351,  # 'Mech Pattern' items=[100351]
    200347: 100352,  # 'Inverse War Pattern' items=[100352]
    200348: 100353,  # 'Cowboy Pattern' items=[100353]
    200349: 100354,  # 'Cyborg Pattern' items=[100354]
    200350: 100355,  # 'Biochemical Pattern' items=[100355]
    200351: 100356,  # 'Space pattern' items=[100356]
    200352: 100357,  # 'Clown pattern' items=[100357]
    200353: 100358,  # 'Temptation Pattern' items=[100358]
    200356: 100365,  # 'DSR-1 ' items=[100365]
    200357: 100366,  # 'MAUL ' items=[100366]
    200360: 100369,  # 'Scorpion swords ' items=[100369]
    200361: 100370,  # 'Air filter ' items=[100370]
    200362: 100371,  # "Brother's hat " items=[100371]
    200363: 100372,  # 'Riot police belt ' items=[100372]
    200364: 100373,  # 'Anti-viral respiratory masks ' items=[100373]
    200368: 100377,  # 'Red Action helmet ' items=[100377]
    200371: 100380,  # 'AK47-K' items=[100380]
    200372: 100381,  # 'M4A1-H' items=[100381]
    200373: 100382,  # 'Bella ' items=[100382, 300092, 300093, 100387]
    200375: 100384,  # 'Kevin' items=[100384, 300102, 300103, 100389, 100928]
    200378: 100390,  # 'Nepal saber ' items=[100390]
    200380: 100392,  # '03 rifle ' items=[100392]
    200388: 100399,  # 'Gear painting ' items=[100399]
    200389: 100400,  # 'Covers painting ' items=[100400]
    200390: 100401,  # 'Skull painting ' items=[100401]
    200397: 100408,  # 'Painting lure Ray ' items=[100408]
    200399: 100410,  # 'Destruction painting ' items=[100410]
    200414: 100425,  # 'Alpha Operations pockets ' items=[100425]
    200417: 100428,  # 'Reds pennant belt ' items=[100428]
    200421: 100432,  # 'SEAL combat washcloth ' items=[100432]
    200426: 100437,  # 'Camo XM8 ' items=[100437]
    200439: 100450,  # 'Outdoor canvas pockets ' items=[100450]
    200440: 100451,  # 'Players shot glasses ' items=[100451]
    200441: 100452,  # 'sound canceling headphones ' items=[100452]
    200444: 100455,  # 'SEAL Tactical Belt ' items=[100455]
    200446: 100457,  # 'Ultimax100 ' items=[100457]
    200447: 100458,  # 'Phantom' items=[100458, 300107, 300108, 100460, 100530]
    200448: 100459,  # 'Pumpkin Grenade' items=[100459]
    200457: 100470,  # 'Jasmine' items=[100470, 300112, 300113, 100490]
    200459: 100472,  # '????95??' items=[100472]
    200460: 100473,  # 'Firecracker grenade ' items=[100473]
    200465: 100478,  # 'Camo  AK74U ' items=[100478]
    200466: 100479,  # 'AR15- Black Mamba ' items=[100479]
    200467: 100480,  # 'SCAR- gold Viper ' items=[100480]
    200468: 100481,  # 'M95- Cobra ' items=[100481]
    200469: 100482,  # 'Gatlin - mad python ' items=[100482]
    200470: 100483,  # 'Snake Desert ' items=[100483]
    200471: 100484,  # 'King of the jungle - snake ' items=[100484]
    200481: 100496,  # 'FMG dual wield' items=[100496]
    200482: 100497,  # '09 style shotgun ' items=[100497]
    200483: 100479,  # 'snake Series Set' items=[100479, 100480, 100481, 100482, 100483, 100484]
    200484: 100479,  # 'snake Series Set' items=[100479, 100480, 100481, 100482, 100483, 100484]
    200485: 100498,  # 'Special 95-style ' items=[100498]
    200486: 100499,  # '10 sniper ' items=[100499]
    200489: 100500,  # 'Encryption key box arms ' items=[100500]
    200490: 100503,  # '??????MSR' items=[100503]
    200491: 100504,  # 'DSR-1' items=[100504]
    200492: 100505,  # 'M4A1-S' items=[100505]
    200493: 100506,  # 'SCAR-S' items=[100506]
    200494: 100507,  # 'M4A1-H' items=[100507]
    200495: 100508,  # 'F2000' items=[100508]
    200496: 100509,  # 'OTs-14' items=[100509]
    200497: 100510,  # 'FAMAS-R' items=[100510]
    200498: 100511,  # 'Uzi??????????' items=[100511]
    200499: 100502,  # '??????????' items=[100502]
    200500: 100512,  # 'Beretta92' items=[100512]
    200501: 100513,  # 'MAUL' items=[100513]
    200505: 100521,  # 'Camo  FAL ' items=[100521]
    200506: 100522,  # 'M4A1-H ' items=[100522]
    200507: 100523,  # 'F2000 ' items=[100523]
    200508: 100524,  # 'M4A1-S ' items=[100524]
    200509: 100525,  # 'DSR-1 ' items=[100525]
    200512: 100245,  # 'Tank Kit ' items=[100245, 100246]
    200513: 100244,  # 'Battle Set ' items=[100244, 100240, 100183, 100205]
    200514: 100241,  # 'Mech Suit ' items=[100241, 100210, 100242, 100243]
    200515: 100310,  # 'Mutation set' items=[100310, 100311, 100307]
    200516: 100527,  # 'Black fighting belt ' items=[100527]
    200517: 100528,  # 'Black fighting headphones ' items=[100528]
    200518: 100529,  # 'Black fighting glasses ' items=[100529]
    200519: 100531,  # 'Variability of serum ' items=[100531]
    200520: 100532,  # 'Gene enhancer ' items=[100532]
    200521: 100533,  # 'Enhanced virus ' items=[100533]
    200522: 100181,  # 'Variety Set ' items=[100181, 100182, 100196, 100352]
    200523: 100259,  # 'April FoolSet' items=[100259, 100238, 100060, 100357]
    200524: 100534,  # 'Camo  KACSAW ' items=[100534]
    200526: 100536,  # 'AUGA3 ' items=[100536]
    200527: 100537,  # 'A super mech license ' items=[100537]
    200537: 100547,  # 'HKG11 ' items=[100547]
    200539: 100549,  # 'Leather fashion cap ' items=[100549]
    200540: 100550,  # 'Dark visor mirror ' items=[100550]
    200541: 100551,  # 'Jungle survival knife ' items=[100551]
    200549: 100337,  # 'Cutting-edge suite ' items=[100337, 100032, 100033, 100079]
    200550: 100206,  # 'Three bursts suit ' items=[100206, 100263, 100078]
    200552: 100561,  # 'Blood crossbow ' items=[100561, 300117, 300118, 100562]
    200553: 100563,  # 'HK416 ' items=[100563]
    200554: 100564,  # 'AK12 ' items=[100564]
    200555: 100565,  # 'TPG1 ' items=[100565]
    200556: 100568,  # 'Bloodthirsty Rose ' items=[100568]
    200557: 100178,  # 'Sniper suit ' items=[100178, 100207, 100077]
    200558: 100283,  # 'Gun suit ' items=[100283, 100079, 100222]
    200559: 100568,  # '????????' items=[100568, 100531, 100532, 100533, 100310, 100311, 100307]
    200560: 100569,  # 'FN57 ' items=[100569]
    200562: 100567,  # '500AP discount coupons ' items=[100567]
    200563: 100566,  # '300AP discount coupons ' items=[100566]
    200565: 100573,  # "Children's Painting (1) " items=[100573]
    200566: 100574,  # 'Children painting (2) ' items=[100574]
    200567: 100581,  # 'Thunder 999 ' items=[100581]
    200569: 100588,  # 'Blood colored headscarf ' items=[100588]
    200570: 100589,  # 'Middle East Plaid Scarf ' items=[100589]
    200571: 100590,  # 'Wild boy standard belt ' items=[100590]
    200573: 100587,  # 'Evil Chaozong ' items=[100587]
    200574: 100591,  # 'Tower defense expert card ' items=[100591]
    200575: 100575,  # 'Turned hero ' items=[100575]
    200576: 100576,  # 'Straightforward shooting ' items=[100576]
    200578: 100578,  # 'Pilfering ' items=[100578]
    200580: 100580,  # 'Bloody Harvest ' items=[100580]
    200581: 100592,  # 'A tank license ' items=[100592]
    200582: 100593,  # 'Dual wield ACP ' items=[100593]
    200583: 100594,  # 'ARX160 ' items=[100594]
    200584: 100595,  # 'Knuckles ' items=[100595]
    200588: 100517,  # 'Powerful physique ' items=[100517]
    200592: 100599,  # 'Angela ' items=[100599, 300119, 300120, 100601]
    200593: 100600,  # 'Sofia ' items=[100600, 300121, 300122, 100602]
    200594: 100603,  # 'SCAR Megalodon ' items=[100603]
    200595: 100604,  # 'Flames fighting spirit ' items=[100604]
    200596: 100605,  # 'DE shark ' items=[100605]
    200597: 100606,  # 'Mood headdress ' items=[100606]
    200598: 100607,  # ' brown sunglasses ' items=[100607]
    200599: 100608,  # 'Fashion fight purse ' items=[100608]
    200600: 100609,  # 'American cap ' items=[100609]
    200601: 100610,  # 'Rimless sunglasses gray ' items=[100610]
    200602: 100611,  # 'American Police pockets ' items=[100611]
    200605: 100614,  # 'Camo  Brothers ' items=[100614]
    200607: 100616,  # 'Bullet Time ' items=[100616]
    200608: 100617,  # 'LSAT ' items=[100617]
    200609: 100618,  # 'Polar ice flame ' items=[100618]
    200611: 100620,  # 'L85 ' items=[100620]
    200612: 100621,  # 'MP5SD10 ' items=[100621]
    200614: 100623,  # 'Zhang Jie - Police Pioneer ' items=[100623, 300123, 300124, 100645]
    200615: 100624,  # 'Hurricane Hammer ' items=[100624]
    200616: 100599,  # 'Sofia & Angela ' items=[100599, 300119, 300120, 100601, 100600, 300121, 300122, 100602]
    200619: 100626,  # 'Zhang Jie - King City ' items=[100626, 300125, 300126, 100648, 100649]
    200620: 100627,  # 'Super Compound Bow ' items=[100627]
    200622: 100629,  # 'Explosion arrow ' items=[100629]
    200623: 100627,  # 'Compound Bow Package ' items=[100627, 100629]
    200626: 100638,  # 'Barrett M107 ' items=[100638]
    200627: 100639,  # 'MINI14 ' items=[100639]
    200628: 100640,  # 'ACE32 ' items=[100640]
    200630: 100642,  # 'M1911 ' items=[100642]
    200631: 100643,  # 'Bat ' items=[100643]
    200632: 100646,  # 'Nether Duwang ' items=[100646]
    200633: 100647,  # 'Huang Jin Zunlong Nepal ' items=[100647]
    200634: 100623,  # 'Zhang Jie - double camp ' items=[100623, 300123, 300124, 100645, 100626, 300125, 300126, 100648, 100649]
    210001: 110001,  # 'AK74U-KOS' items=[110001]
    210002: 110002,  # 'AR15-KOS' items=[110002]
    210006: 110004,  # 'The Razorback' items=[110004]
    210007: 110005,  # 'Boar Hooves' items=[110005]
}

# v91-shop-lobby: channel + match-room browser path recovered from proto_c2zn.tdr.
# The client asks A355/A132 for channel discovery, then A100 for the visible
# room/lobby browser.  A102 carries BasicMatchRoomInfo rows.
TGAME_ZN_REQ_MATCHROOMLIST = 0xA100
TGAME_ZN_RES_MATCHROOMLIST = 0xA102
TGAME_ZN_REQ_CREATEMATCHROOM = 0xA10A
TGAME_ZN_RES_CREATEMATCHROOM = 0xA10B

TGAME_ZN_REQ_ZONECHANNEL_LIST = 0xA132
TGAME_ZN_RES_ZONECHANNEL_LIST = 0xA133
TGAME_ZN_REQ_MAINCHNLLIST = 0xA355
TGAME_ZN_RES_MAINCHNLLIST = 0xA356

# v92-social: PH-client social/chat IDs.  A303 and A405 are not inferred from
# the generic TDR macro order: both were recovered directly from this PH
# TGame build's native request builders (0x014BF85A and 0x014C6E01).
TGAME_ZN_REQ_FRIEND_STATUS = 0xA303
TGAME_ZN_RES_FRIEND_STATUS = 0xA304
TGAME_ZN_REQ_ADD_FRIEND = 0xA305
TGAME_ZN_NTF_ADD_FRIEND_REQUEST = 0xA306
TGAME_ZN_RES_ADD_FRIEND_C2S = 0xA307
TGAME_ZN_RES_ADD_FRIEND_S2C = 0xA308
TGAME_ZN_REQ_DEL_FRIEND = 0xA309
TGAME_ZN_RES_DEL_FRIEND = 0xA30A
TGAME_ZN_REQ_CHAT_P2P = 0xA405
TGAME_ZN_NTF_CHAT_P2P = 0xA406

SNS_ERR_SUCC = 0x8300
LOCAL_FRIEND_UIN = 10002
LOCAL_FRIEND_NICKNAME = "LocalFriend"
LOCAL_FRIEND_REMARK = "Local emulator friend"
ENABLE_LOCAL_FRIEND_BOT = True

# v94-clan: clan command family recovered from the compiled proto_c2zn.tdr
# message table.  Unlike the internal ID_* enum (B008/B009/...), these are
# the on-wire C2ZN/ZN2C command numbers.  The simple create/name-verification
# packets are implemented fully; the large nested detail/member/common
# packets are recognized and logged but deliberately not fabricated until a
# live PH decode validates their nested record widths.
TGAME_ZN_REQ_CREATE_CLAN = 0xA601
TGAME_ZN_RES_CREATE_CLAN = 0xA602
TGAME_ZN_REQ_PUBLISH_RECRUIT = 0xA603
TGAME_ZN_RES_PUBLISH_RECRUIT = 0xA604
TGAME_ZN_REQ_SEARCH_CLAN_BY_NAME = 0xAA01
TGAME_ZN_RES_SEARCH_CLAN_BY_NAME = 0xAA02
TGAME_ZN_REQ_RECRUIT_LIST = 0xAA03
TGAME_ZN_RES_RECRUIT_LIST = 0xAA04
TGAME_ZN_REQ_CLAN_DETAIL = 0xAA05
TGAME_ZN_RES_CLAN_DETAIL = 0xAA06
TGAME_ZN_REQ_CLAN_MEMBERS = 0xAA07
TGAME_ZN_RES_CLAN_MEMBERS = 0xAA08
TGAME_ZN_REQ_CLAN_COMMON = 0xAA09
TGAME_ZN_RES_CLAN_COMMON = 0xAA0A
TGAME_ZN_REQ_VERIFY_CLAN_NAME = 0xAB02
TGAME_ZN_RES_VERIFY_CLAN_NAME = 0xAB03

# Error-code namespace recovered from ClanErrorEnums in proto_c2zn.tdr.
CLAN_ERR_SUCC = 0x8400
CLAN_ERR_FAIL = 0x8401

MAX_CLAN_NAME_LEN = 40
MAX_CLAN_SAFECODE_LEN = 128
LOCAL_CLAN_ID = 0x0000000000010001
LOCAL_CLAN_DEFAULT_NAME = "LocalClan"

# v94: clan membership is persisted independently from the hardened shop save
# so the older wallet/inventory state writer cannot accidentally erase it.
CLAN_STATE_PATH = Path(__file__).with_name("assaultfire_clan_state.json")
_CLAN_STATE_LOCK = threading.RLock()
CLAN_STATE_VERSION = 1


def _v94_default_clan_state():
    return {
        "version": CLAN_STATE_VERSION,
        "clan_id": 0,
        "clan_name": "",
        "captain_uin": 0,
        "captain_name": "",
        "safe_code": "",
        "certified_mail": "",
        "max_members": 50,
        "cur_members": 0,
        "recruit_type": 0,
        "level_limit": 1,
        "introduction": "",
        "created_unix": 0,
    }


def _v94_normalize_clan_state(raw):
    base = _v94_default_clan_state()
    if not isinstance(raw, dict):
        return base
    clan_id = _v89_u64(raw.get("clan_id", 0), 0)
    if clan_id == 0:
        return base
    name = str(raw.get("clan_name") or LOCAL_CLAN_DEFAULT_NAME)[:39]
    captain_uin = _v89_u64(raw.get("captain_uin", LOCAL_UIN), LOCAL_UIN)
    return {
        "version": CLAN_STATE_VERSION,
        "clan_id": clan_id,
        "clan_name": name,
        "captain_uin": captain_uin,
        "captain_name": str(raw.get("captain_name") or "LocalPlayer")[:31],
        "safe_code": str(raw.get("safe_code") or "")[:127],
        "certified_mail": str(raw.get("certified_mail") or "")[:255],
        "max_members": max(1, min(255, _v89_int(raw.get("max_members", 50), 50))),
        "cur_members": max(1, min(255, _v89_int(raw.get("cur_members", 1), 1))),
        "recruit_type": _v89_u8(raw.get("recruit_type", 0), 0),
        "level_limit": max(0, min(0xffff, _v89_int(raw.get("level_limit", 1), 1))),
        "introduction": str(raw.get("introduction") or "Local Assault Fire clan")[:255],
        "created_unix": max(0, _v89_int(raw.get("created_unix", int(time.time())), int(time.time()))),
    }


def _v94_load_clan_state():
    with _CLAN_STATE_LOCK:
        if not CLAN_STATE_PATH.exists():
            return _v94_default_clan_state(), "new-default"
        try:
            raw = json.loads(CLAN_STATE_PATH.read_text(encoding="utf-8"))
            return _v94_normalize_clan_state(raw), "disk"
        except Exception as e:
            bad = CLAN_STATE_PATH.with_suffix(
                CLAN_STATE_PATH.suffix + f".corrupt-{int(time.time())}"
            )
            try:
                os.replace(str(CLAN_STATE_PATH), str(bad))
            except Exception:
                pass
            return _v94_default_clan_state(), f"corrupt-reset:{type(e).__name__}:{e}"


def _v94_save_clan_state(state, reason="update"):
    state = _v94_normalize_clan_state(state)
    tmp = CLAN_STATE_PATH.with_suffix(CLAN_STATE_PATH.suffix + ".tmp")
    data = json.dumps(state, indent=2, sort_keys=True) + "\n"
    with _CLAN_STATE_LOCK:
        tmp.write_text(data, encoding="utf-8")
        os.replace(str(tmp), str(CLAN_STATE_PATH))
    log(
        "CLAN",
        f"saved reason={reason} clan_id=0x{state['clan_id']:016x} "
        f"name={state['clan_name']!r} members={state['cur_members']}/{state['max_members']} "
        f"path={CLAN_STATE_PATH}",
    )
    return state

TGAME_ZN_RES_HEARTBEAT = 0xFF10
TGAME_ZN_NTF_ZONE_HINTS = 0xFF13

# v72: room-allocation family recovered from proto_c2zn.tdr and confirmed
# by the live 46-byte Start request emitted by the Match -> Start button.
TGAME_ZN_REQ_STARTROOMALLOC = 0xA3A0
TGAME_ZN_NTF_ENTERROOMALLOC = 0xA3A1
TGAME_ZN_RES_STARTROOMALLOC = 0xA3A2
TGAME_ZN_REQ_QUITROOMALLOC = 0xA3A3
TGAME_ZN_RES_QUITROOMALLOC = 0xA3A4
TGAME_ZN_NTF_STARTROOMALLOCMATCH = 0xA3A5
TGAME_ZN_NTF_QUITRAMATCH = 0xA3A6

TGAME_ZONE_PORT = 65006


def tgame_parse_geo_app(plain):
    """Parse sequence + C2GEOPkg from decrypted cmd00 plaintext."""
    if len(plain) < 12:
        raise ValueError(f"short GEO plaintext {len(plain)}B")
    seq = struct.unpack(">I", plain[:4])[0]
    magic, cmd, head_len, body_len = struct.unpack(">HHHH", plain[4:12])
    if head_len < 8:
        raise ValueError(f"invalid GEO head_len={head_len}")
    app_total = 4 + head_len + body_len
    if app_total > len(plain):
        raise ValueError(
            f"truncated GEO packet head={head_len} body={body_len} plain={len(plain)}"
        )
    body_off = 4 + head_len
    return {
        "seq": seq,
        "magic": magic,
        "cmd": cmd,
        "head_len": head_len,
        "body_len": body_len,
        "body": plain[body_off:body_off + body_len],
    }


def _tdr_string_ascii(text):
    """Wire encoding used by GEO PingInfo.Domain.

    Runtime-verified against ProtocalHandler.dll's GEO2C_ResPingList decoder:
    the wire field is a big-endian u32 byte length (including the terminating
    NUL), followed by the NUL-terminated ASCII bytes.  The decoder consumes
    the length and stores only the string in the host-side structure.
    """
    raw = text.encode("ascii") + b"\x00"
    return struct.pack(">I", len(raw)) + raw

def tgame_build_geo_pinglist_response(seq, max_delay_ms=1000):
    """Build GEO2C_ResPingList with one local PingInfo entry.

    Static reconstruction from proto_c2geo.tdr:
      PingInfo internal size = 0x8C
      Group     : u32, offset 0x00
      Ipv4      : u32, offset 0x04
      Domain    : char[128], offset 0x08
      PingInMs  : u32, offset 0x88

    GEO2C_ResPingList:
      Result      : u16
      ServerCount : u16
      ServerArray : PingInfo[ServerCount]
      MaxDelayInMs: u32

    Runtime v60 verification in x32dbg:
      * ProtocalHandler's TDR decoder must see the GEO header (0x8202) at
        input offset 0; the 4-byte application sequence prefix must therefore
        NOT be serialized in this response plaintext.
      * Domain is encoded as u32_be(strlen+1) followed by NUL-terminated ASCII.
    """
    group = 0
    ipv4 = 0x7F000001       # semantic 127.0.0.1
    domain = "127.0.0.1"
    ping_ms = 0

    ping_info = (
        struct.pack(">I", group)
        + struct.pack(">I", ipv4)
        + _tdr_string_ascii(domain)
        + struct.pack(">I", ping_ms)
    )

    body = (
        struct.pack(">H", GEO_ERR_SUCC)   # success is 0x8B00, NOT zero
        + struct.pack(">H", 1)            # ServerCount
        + ping_info
        + struct.pack(">I", max_delay_ms & 0xffffffff)
    )
    # Domain="127.0.0.1\0" is 10 bytes plus a 4-byte BE length prefix.
    # PingInfo is therefore 26 bytes and the complete response body is 34
    # bytes (0x22).  This exact layout returned EAX=0 from the live TDR decoder.
    if len(ping_info) != 26 or len(body) != 34:
        raise AssertionError(
            f"unexpected GEO ping sizes: ping_info={len(ping_info)} body={len(body)}"
        )
    app = struct.pack(
        ">HHHH",
        TGAME_GEO_MAGIC,
        TGAME_GEO_RES_PINGLIST,
        8,
        len(body),
    ) + body
    # IMPORTANT: do not prepend seq here.  Runtime verification showed the
    # decoder must receive 82 02 ... at byte 0; prepending seq caused the
    # decoder to consume the sequence as struct data and fail with 0x82010402.
    # Keep seq in the signature only so older call sites remain compatible.
    return app


def tgame_build_cmd00_mode3(plain, key):
    enc = tgame_mode3_encrypt(plain, key)
    pkt = (
        b"\x55\x0e\x00\x04"
        + struct.pack(">I", 12)
        + struct.pack(">I", len(enc))
        + enc
    )
    return pkt, enc


def tgame_build_cmd02_mode3_body(plain, key):
    """Build server->client delivery using TPDU cmd02 with normal encrypted body.

    Static receive path finding:
      * cmd00 decrypted successfully but +12E9/default returns 0, so the
        higher wrapper does not enter the normal delivery path.
      * cmd02 is an explicit downlink branch that returns 1.
      * +754E0 still decrypts body payloads before +12E9, so keep the body
        as the normal mode3 application payload.

    Wire:
      55 0e 02 04
      BE32 head_len = 12
      BE32 body_len = len(mode3(app_plain))
      body = mode3(app_plain)
    """
    enc = tgame_mode3_encrypt(plain, key)
    pkt = (
        b"\x55\x0e\x02\x04"
        + struct.pack(">I", 12)
        + struct.pack(">I", len(enc))
        + enc
    )
    return pkt, enc


# ---------------------------------------------------------------------------
# v48: verified GEO -> ZONE application layer
# ---------------------------------------------------------------------------

def _v48_u8(v):  return struct.pack(">B", v & 0xff)
def _v48_i8(v):  return struct.pack(">b", v)
def _v48_u16(v): return struct.pack(">H", v & 0xffff)
def _v48_i16(v): return struct.pack(">h", v)
def _v48_u32(v): return struct.pack(">I", v & 0xffffffff)
def _v48_i32(v): return struct.pack(">i", v)
def _v48_u64(v): return struct.pack(">Q", v & 0xffffffffffffffff)
def _v48_i64(v): return struct.pack(">q", v)
def _v48_f64(v): return struct.pack(">d", float(v))


def _v48_tdr_string(s, maxlen=None):
    """TDR v11 type-21 string: raw NUL-terminated bytes, no length prefix."""
    b = s.encode("ascii") if isinstance(s, str) else bytes(s)
    if b.endswith(b"\x00"):
        b = b[:-1]
    if maxlen is not None and len(b) + 1 > maxlen:
        raise ValueError(f"TDR string too long ({len(b)+1}>{maxlen})")
    return b + b"\x00"


def _v50_geo_tdr_string(s, maxlen=None):
    """GEO string field: u32_be(strlen+1) followed by NUL-terminated bytes."""
    b = s.encode("ascii") if isinstance(s, str) else bytes(s)
    if b.endswith(b"\x00"):
        b = b[:-1]
    raw = b + b"\x00"
    if maxlen is not None and len(raw) > maxlen:
        raise ValueError(f"GEO TDR string too long ({len(raw)}>{maxlen})")
    return _v48_u32(len(raw)) + raw


def _v48_build_app(seq, magic, cmd, body):
    if len(body) > 0xffff:
        raise ValueError("application body exceeds u16 BodyLen")
    return (
        _v48_u32(seq)
        + _v48_u16(magic)
        + _v48_u16(cmd)
        + _v48_u16(8)
        + _v48_u16(len(body))
        + body
    )


def _v62_build_server_app(magic, cmd, body):
    """Server->TGame application payload.

    Runtime verification on GEO showed that downstream cmd00 plaintext starts
    directly at the TDR package header; the client's 4-byte app sequence is a
    client->server prefix and must not be prepended to server responses.
    """
    if len(body) > 0xffff:
        raise ValueError("application body exceeds u16 BodyLen")
    return (
        _v48_u16(magic)
        + _v48_u16(cmd)
        + _v48_u16(8)
        + _v48_u16(len(body))
        + body
    )


def _v48_parse_app(plain):
    if len(plain) < 12:
        raise ValueError(f"short app plaintext {len(plain)}B")
    seq = struct.unpack_from(">I", plain, 0)[0]
    magic, cmd, head_len, body_len = struct.unpack_from(">HHHH", plain, 4)
    if head_len < 8:
        raise ValueError(f"bad app HeadLen={head_len}")
    off = 4 + head_len
    if off + body_len > len(plain):
        raise ValueError(
            f"truncated app packet head={head_len} body={body_len} plain={len(plain)}"
        )
    return {
        "seq": seq, "magic": magic, "cmd": cmd,
        "head_len": head_len, "body_len": body_len,
        "body": plain[off:off + body_len],
    }


def _v48_parse_pinginfo(body, off):
    """Parse GEO PingInfo using the runtime-observed GEO string encoding.

    Wire:
      u32 Group | u32 Ipv4 | u32 DomainLen | Domain[DomainLen] | u32 PingInMs

    DomainLen includes the terminating NUL.  This is confirmed by the live
    C2GEO_ReqZoneList emitted after the v60 PingList response was accepted.
    """
    if off + 12 > len(body):
        raise ValueError("short PingInfo fixed prefix")
    group, addr = struct.unpack_from(">II", body, off)
    off += 8

    n = struct.unpack_from(">I", body, off)[0]
    off += 4
    if n < 1 or n > 128:
        raise ValueError(f"bad PingInfo.Domain wire length={n}")
    if off + n + 4 > len(body):
        raise ValueError("truncated PingInfo.Domain/PingInMs")

    raw_domain = body[off:off + n]
    off += n
    if not raw_domain.endswith(b"\x00"):
        raise ValueError("PingInfo.Domain missing terminal NUL")
    domain = raw_domain[:-1].decode("latin1", "replace")

    ping_ms = struct.unpack_from(">I", body, off)[0]
    off += 4
    iptxt = ".".join(str((addr >> sh) & 0xff) for sh in (24, 16, 8, 0))
    return {
        "group": group, "ipv4": iptxt, "domain": domain, "ping_ms": ping_ms,
        "domain_wire_len": n,
    }, off


def _v48_parse_geo_req_zonelist(body):
    if len(body) < 6:
        raise ValueError("short C2GEO_ReqZoneList")
    count = struct.unpack_from(">h", body, 0)[0]
    if count < 0 or count > 64:
        raise ValueError(f"bad ServerCount={count}")
    off = 2
    servers = []
    for _ in range(count):
        pi, off = _v48_parse_pinginfo(body, off)
        servers.append(pi)
    if off + 4 > len(body):
        raise ValueError("ReqZoneList missing MaxDelayInMs")
    max_delay = struct.unpack_from(">I", body, off)[0]
    off += 4
    return {
        "count": count, "servers": servers, "max_delay_ms": max_delay,
        "consumed": off, "body_len": len(body)
    }


def _v48_build_geo_zonelist(seq, port=TGAME_ZONE_PORT):
    """Build GEO2C_ResZoneList using the framing learned from the live GEO path.

    Like the runtime-verified PingList response, this GEO response starts at
    the 0x8202 GEO header (no 4-byte application sequence prefix).  ZoneInfo's
    Domain uses u32_be(strlen+1) followed by NUL-terminated ASCII, matching
    the C2GEO_ReqZoneList wire encoding observed from the real client.

    ``seq`` is retained only for call-site compatibility; it is not serialized.
    """
    # ZoneInfo:
    # u32 Ipv4 | GEO string Domain | u16 Port | i32 OnlineNum | u32 PingInMs |
    # u32 MainChannelId | i32 LoadExts[6]
    zone = (
        # ZoneInfo.Ipv4 is copied by TGame directly into sockaddr.sin_addr.
        # TDR decodes uint32 into little-endian host memory, so 127.0.0.1 must
        # be serialized numerically as 0x0100007F to leave bytes 7F 00 00 01
        # in the decoded object. 0x7F000001 produced 1.0.0.127 at connect().
        _v48_u32(0x0100007f)
        + _v50_geo_tdr_string("127.0.0.1", 128)
        + _v48_u16(port)
        + _v48_i32(1)
        + _v48_u32(1)
        + _v48_u32(1)
        + b"".join(_v48_i32(0) for _ in range(6))
    )
    body = (
        _v48_u16(GEO_ERR_SUCC)
        + _v48_i16(1)
        + zone
        + _v48_i16(1)  # EGEODecisionMethod_Sequential
    )
    # Old raw-string body was 0x3A.  The u32 DomainLen adds four bytes.
    if len(body) != 62:
        raise AssertionError(f"unexpected GEO ZoneList body len={len(body)}")
    return (
        _v48_u16(TGAME_GEO_MAGIC)
        + _v48_u16(TGAME_GEO_RES_ZONELIST)
        + _v48_u16(8)
        + _v48_u16(len(body))
        + body
    )


def _v48_parse_zn_login(body):
    if len(body) < 12:
        raise ValueError(f"short C2ZN_ReqLogin {len(body)}B")
    sub, pref, syscrc = struct.unpack_from(">III", body, 0)
    return {
        "sub_channel_id": sub,
        "preference_crc": pref,
        "system_crc": syscrc,
    }


def _v48_build_zn_login_response(seq, tgame_point=LOCAL_TP_BALANCE,
                                   gold_point=LOCAL_GP_BALANCE):
    # ZN2C_ResLogin:
    # u16 Result | u32 MainChannelId | u32 SubChannelId | double ServerTime |
    # i32 TGamePoint | i32 GoldPoint | i16 FreePropCount
    # PH labels TGamePoint as AP in the shop UI; keep the wire name for protocol clarity.
    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_u32(1)
        + _v48_u32(1)
        + _v48_f64(float(int(time.time())))
        + _v48_i32(int(tgame_point))
        + _v48_i32(int(gold_point))
        + _v48_i16(0)
    )
    if len(body) != 28:
        raise AssertionError(f"unexpected ZN login response body len={len(body)}")
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_RES_LOGIN, body)


def _v48_dt_zero():
    # TDR datetime is 8 bytes. Internal semantic layout remains unproven; zero
    # is deliberately used as the conservative unset value for this first pass.
    return b"\x00" * 8


def _v48_player_info(uin=10001, nickname="LocalPlayer",
                     tgame_point=LOCAL_TP_BALANCE, gold_point=LOCAL_GP_BALANCE,
                     month_point=LOCAL_MP_BALANCE, cur_role_gid=LOCAL_ROLE_GID,
                     clan_id=0):
    # Exact field order recovered from PlayerInfo metalib. v70 uses the runtime-verified\n    # TDR string form for NickName: u32_be(strlen+1) + NUL-terminated bytes.\n    # v80: CurRoleGID points at the role PropInfo sent in A006.
    # RoleType remains zero; TGame resolves the concrete role through the prop.
    return (
        _v48_u64(uin)
        + _v48_u32(0)
        + _v50_geo_tdr_string(nickname, 32)
        + _v48_i32(int(tgame_point)) + _v48_i32(int(gold_point))
        + _v48_i32(int(month_point)) + _v48_i32(0)
        + _v48_u32(0) + _v48_u16(0)
        + _v48_i32(0)
        + _v48_dt_zero() + _v48_dt_zero()
        + _v48_u64(int(cur_role_gid))  # CurRoleGID
        + _v48_u64(0)       # RoleType
        + _v48_u64(int(clan_id))  # ClanID
        + _v48_u32(0) + _v48_u32(0) + _v48_u32(0) + _v48_u32(0)
        + _v48_u16(0)
        + _v48_dt_zero() + _v48_dt_zero()
        + _v48_u32(0) + _v48_u32(0)
        + _v48_u32(1)       # Level
        + _v48_i32(0) + _v48_i32(0) + _v48_i32(0)
        + _v48_u32(0)
        + _v48_dt_zero()
        + _v48_u64(0) + _v48_u64(0)
        + _v48_i32(0) + _v48_u32(0)
        + _v48_u16(0) + _v48_u16(0)
        + _v48_i32(0) + _v48_i32(0)
        + _v48_dt_zero()
        + _v48_u16(0) + _v48_u16(0) + _v48_u16(0) + _v48_u16(0)
        + _v48_dt_zero()
        + _v48_i32(0) + _v48_u32(0)
        + _v48_u16(0) + _v48_u16(0)
        + _v48_u64(0)
        + _v48_u16(0)
        + _v48_dt_zero()
        + _v48_u32(0)
    )


def _v48_build_playerinfo(seq, uin=10001,
                          tgame_point=LOCAL_TP_BALANCE,
                          gold_point=LOCAL_GP_BALANCE,
                          month_point=LOCAL_MP_BALANCE,
                          cur_role_gid=LOCAL_ROLE_GID,
                          nickname="LocalPlayer", clan_id=0):
    info = _v48_player_info(
        uin=uin, nickname=nickname,
        tgame_point=tgame_point, gold_point=gold_point,
        month_point=month_point, cur_role_gid=cur_role_gid, clan_id=clan_id,
    )
    body = _v48_u16(ZONE_ERR_SUCC) + info
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_NTF_PLAYERINFO, body)


def _v48_build_empty_playerprops(seq):
    # ZN2C_NtfPlayerProps:
    # u16 Result | u8 IsLastPkg | i16 PropCount | PropInfo[N]
    body = _v48_u16(ZONE_ERR_SUCC) + _v48_u8(1) + _v48_i16(0)
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_NTF_PLAYERPROPS, body)


def _v88_build_update_player_property(
        update_flag,
        reason,
        tgame_point,
        gold_point,
        month_point,
        happy_point=0,
        experience=0,
        evolution_point=0,
        card_point=0):
    """ZN2C_NtfUpdatePlayerProperty, wallet-only form (Count=0).

    Metalib order:
      u16 UpdateFlag
      u32 Reason
      i32 TGamePoint
      i32 HappyPoint
      i32 GoldPoint
      i32 MonthPoint
      i32 Experience
      i32 EvolutionPoint
      i32 CardPoint
      u16 Count
      UpdateProp_ToClient Props[Count]
    """
    body = (
        _v48_u16(update_flag)
        + _v48_u32(reason)
        + _v48_i32(tgame_point)
        + _v48_i32(happy_point)
        + _v48_i32(gold_point)
        + _v48_i32(month_point)
        + _v48_i32(experience)
        + _v48_i32(evolution_point)
        + _v48_i32(card_point)
        + _v48_u16(0)
    )
    if len(body) != 36:
        raise AssertionError(f"unexpected UpdatePlayerProperty body len={len(body)}")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_UPDATE_PLAYER_PROPERTY, body
    )


def _v88_send_wallet_sync(conn, key, label, ap, gp, mp,
                           reason=UPDATE_REASON_BUY,
                           prefix="v89 wallet-sync"):
    """Push AP/GP/MP through the client's live HUD update path."""
    for flag, name in (
        (UPDATE_FLAG_TP, "AP"),
        (UPDATE_FLAG_GP, "GP"),
        (UPDATE_FLAG_MP, "MP"),
    ):
        why = (
            UPDATE_REASON_TP_BALANCE
            if flag == UPDATE_FLAG_TP and reason != UPDATE_REASON_BUY
            else reason
        )
        pkt = _v88_build_update_player_property(flag, why, ap, gp, mp)
        _v48_send_app(
            conn, key, pkt, label,
            f"ZN2C_NTF_UPDATEPLAYERPROPERTY {prefix} flag={name} "
            f"AP={ap} GP={gp} MP={mp} reason=0x{why:02x}"
        )


def _v75_read_tdr_string(body, off, maxlen):
    """Read the live ZONE TDR string form: BE32 length including trailing NUL."""
    if off + 4 > len(body):
        raise ValueError("truncated TDR string length")
    n = struct.unpack_from(">I", body, off)[0]
    off += 4
    if n < 1 or n > maxlen:
        raise ValueError(f"bad TDR string length={n} max={maxlen}")
    if off + n > len(body):
        raise ValueError("truncated TDR string data")
    raw = body[off:off + n]
    off += n
    if raw[-1:] != b"\x00":
        raise ValueError("TDR string missing terminal NUL")
    return raw[:-1].decode("latin1", "replace"), off


def _v75_load_shop_item_map():
    """Reload optional CommodityId -> ItemId overrides on every purchase."""
    mapping = dict(SHOP_ITEM_OVERRIDES)
    p = Path(__file__).with_name("shop_item_map.json")
    if not p.exists():
        return mapping, None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("top level must be an object")
        for k, v in raw.items():
            mapping[int(str(k), 0)] = int(v)
        return mapping, str(p)
    except Exception as e:
        return mapping, f"{p} ERROR={e}"


# v78: authoritative currency/price table decoded from DefaultCommodityLibrary.ini.
REAL_SHOP_PRICES = {
    200001: ('GP', (18750,)),
    200002: ('MP', (750, 1500, 4500)),
    200003: ('GP', (14250,)),
    200004: ('TP', (5, 9, 18, 30)),
    200005: ('GP', (15000,)),
    200006: ('GP', (18000,)),
    200007: ('GP', (21750,)),
    200008: ('MP', (750, 1500, 4500)),
    200009: ('GP', (4000,)),
    200010: ('GP', (4000,)),
    200011: ('GP', (7500,)),
    200012: ('GP', (6000,)),
    200019: ('TP', (200,)),
    200020: ('MP', (750, 1500, 4500)),
    200021: ('TP', (5, 10, 20)),
    200022: ('TP', (5, 10, 20)),
    200026: ('GP', (8000,)),
    200027: ('GP', (7500,)),
    200028: ('GP', (10000,)),
    200029: ('MP', (2500,)),
    200031: ('GP', (21000,)),
    200032: ('GP', (1,)),
    200033: ('GP', (1,)),
    200034: ('GP', (1,)),
    200035: ('GP', (1,)),
    200036: ('GP', (1,)),
    200037: ('GP', (1,)),
    200038: ('GP', (1,)),
    200039: ('GP', (1,)),
    200040: ('GP', (1,)),
    200041: ('GP', (1,)),
    200042: ('GP', (1,)),
    200043: ('GP', (1,)),
    200044: ('GP', (1,)),
    200045: ('GP', (1,)),
    200046: ('GP', (1,)),
    200047: ('GP', (1,)),
    200048: ('GP', (1,)),
    200049: ('GP', (1,)),
    200050: ('GP', (1,)),
    200051: ('GP', (1,)),
    200052: ('GP', (1,)),
    200053: ('GP', (1,)),
    200054: ('GP', (1,)),
    200055: ('GP', (1,)),
    200056: ('GP', (1,)),
    200057: ('GP', (1,)),
    200058: ('GP', (1,)),
    200059: ('GP', (1,)),
    200060: ('GP', (1,)),
    200061: ('GP', (1,)),
    200062: ('TP', (15,)),
    200064: ('GP', (26250,)),
    200065: ('TP', (7, 13, 35, 60)),
    200066: ('TP', (6, 12, 24, 42)),
    200067: ('TP', (9, 18, 49, 88)),
    200068: ('TP', (13, 25, 68, 123)),
    200069: ('GP', (25000,)),
    200070: ('MP', (2500,)),
    200071: ('MP', (750, 1500, 4500)),
    200074: ('MP', (900, 1800, 5400)),
    200075: ('TP', (5, 14, 25, 72)),
    200076: ('TP', (5, 14, 25, 72)),
    200077: ('TP', (5, 14, 25, 72)),
    200082: ('TP', (5, 14, 25, 72)),
    200083: ('TP', (5, 14, 25, 72)),
    200086: ('TP', (5, 14, 25, 72)),
    200087: ('GP', (25000,)),
    200088: ('MP', (5000,)),
    200089: ('GP', (13000,)),
    200090: ('GP', (9000,)),
    200091: ('GP', (12000,)),
    200092: ('GP', (34500,)),
    200093: ('GP', (18000,)),
    200094: ('GP', (24000,)),
    200095: ('GP', (23000,)),
    200096: ('TP', (4, 8, 28, 37)),
    200097: ('TP', (6, 12, 24, 42)),
    200098: ('TP', (6, 12, 24, 42)),
    200099: ('TP', (5, 9, 23, 42)),
    200100: ('TP', (5, 14, 25, 72)),
    200101: ('TP', (5, 14, 25, 72)),
    200102: ('TP', (5, 14, 25, 72)),
    200103: ('TP', (5, 14, 25, 72)),
    200104: ('TP', (5, 14, 25, 72)),
    200105: ('TP', (5, 14, 25, 72)),
    200106: ('TP', (5, 14, 25, 72)),
    200107: ('TP', (5, 14, 25, 72)),
    200108: ('TP', (5, 14, 25, 72)),
    200109: ('TP', (5, 14, 25, 72)),
    200110: ('TP', (5, 14, 25, 72)),
    200111: ('TP', (5, 14, 25, 72)),
    200112: ('TP', (5, 14, 25, 72)),
    200113: ('TP', (5, 14, 25, 72)),
    200114: ('TP', (5, 14, 25, 72)),
    200115: ('TP', (5, 14, 25, 72)),
    200116: ('TP', (5, 14, 25, 72)),
    200117: ('TP', (5, 14, 25, 72)),
    200118: ('GP', (10000,)),
    200119: ('GP', (10000,)),
    200120: ('TP', (5, 14, 25, 72)),
    200121: ('TP', (5, 14, 25, 72)),
    200122: ('TP', (5, 14, 25, 72)),
    200123: ('TP', (5, 14, 25, 72)),
    200124: ('GP', (15500,)),
    200128: ('GP', (11500,)),
    200129: ('GP', (15000,)),
    200130: ('TP', (4, 8, 21, 37)),
    200131: ('GP', (25500,)),
    200132: ('TP', (200,)),
    200133: ('TP', (5, 14, 25, 72)),
    200134: ('TP', (5, 14, 25, 72)),
    200135: ('TP', (5, 14, 25, 72)),
    200136: ('TP', (5, 14, 25, 72)),
    200137: ('TP', (5, 14, 25, 72)),
    200138: ('TP', (5, 14, 25, 72)),
    200139: ('GP', (18000,)),
    200140: ('MP', (2500,)),
    200141: ('TP', (5, 14, 25, 72)),
    200142: ('TP', (5, 14, 25, 72)),
    200143: ('TP', (5, 14, 25, 72)),
    200144: ('TP', (5, 14, 25, 72)),
    200145: ('TP', (5, 14, 25, 72)),
    200146: ('TP', (5, 14, 25, 72)),
    200147: ('GP', (30000,)),
    200148: ('MP', (450, 900, 2700)),
    200159: ('TP', (8, 1500, 3000)),
    200161: ('TP', (5, 14, 72, 116)),
    200162: ('TP', (5, 14, 72, 116)),
    200163: ('TP', (5, 14, 72, 116)),
    200164: ('TP', (5, 14, 72, 116)),
    200165: ('TP', (5, 14, 72, 116)),
    200166: ('TP', (5, 14, 72, 116)),
    200169: ('TP', (12, 29, 55)),
    200170: ('GP', (16500,)),
    200171: ('GP', (16500,)),
    200172: ('GP', (16500,)),
    200173: ('GP', (16500,)),
    200174: ('GP', (16500,)),
    200175: ('GP', (16500,)),
    200176: ('GP', (16500,)),
    200177: ('GP', (16500,)),
    200178: ('GP', (16500,)),
    200179: ('GP', (16500,)),
    200180: ('GP', (16500,)),
    200181: ('GP', (16500,)),
    200182: ('GP', (16500,)),
    200183: ('GP', (16500,)),
    200184: ('GP', (16500,)),
    200185: ('GP', (16500,)),
    200186: ('GP', (16500,)),
    200187: ('TP', (4, 9, 18, 35)),
    200188: ('MP', (300, 1500, 4500)),
    200190: ('TP', (1490, 4500, 7000, 8800)),
    200191: ('TP', (4, 8, 16, 26)),
    200192: ('MP', (400, 700, 1400, 2800)),
    200193: ('TP', (4, 8, 16, 26)),
    200194: ('TP', (6, 12, 24, 42)),
    200195: ('GP', (13500,)),
    200196: ('GP', (22500,)),
    200197: ('TP', (250,)),
    200198: ('TP', (0,)),
    200199: ('TP', (300, 600, 1800, 3200)),
    200200: ('TP', (150,)),
    200201: ('TP', (200,)),
    200202: ('TP', (4, 7, 19, 37)),
    200203: ('GP', (22500,)),
    200204: ('TP', (300,)),
    200205: ('TP', (500,)),
    200206: ('TP', (500,)),
    200207: ('TP', (500,)),
    200208: ('TP', (500,)),
    200210: ('TP', (500, 1000, 3000, 5500)),
    200211: ('TP', (4, 8, 16, 26)),
    200212: ('TP', (4, 8, 21, 37)),
    200213: ('MP', (750, 1500, 4500)),
    200215: ('TP', (400, 800, 2400, 4500)),
    200217: ('MP', (900, 1800, 5400)),
    200218: ('GP', (42000,)),
    200219: ('TP', (100, 800, 1400, 2500)),
    200220: ('MP', (100, 300, 500, 800)),
    200221: ('GP', (1,)),
    200222: ('GP', (1,)),
    200223: ('GP', (1,)),
    200224: ('GP', (1,)),
    200225: ('GP', (1,)),
    200226: ('GP', (1,)),
    200227: ('GP', (1,)),
    200228: ('GP', (1,)),
    200229: ('GP', (1,)),
    200230: ('GP', (1,)),
    200231: ('TP', (800, 1800, 2800, 3800)),
    200232: ('GP', (5000,)),
    200233: ('GP', (5000,)),
    200234: ('MP', (750, 1500, 4500)),
    200235: ('MP', (750, 1500, 4500)),
    200236: ('TP', (3, 5, 12, 22)),
    200237: ('TP', (5, 14, 25, 72)),
    200238: ('TP', (5, 14, 25, 72)),
    200244: ('TP', (0,)),
    200246: ('GP', (25000,)),
    200247: ('TP', (5, 9, 18, 30)),
    200248: ('MP', (750, 1500, 4500)),
    200249: ('TP', (500, 1000, 3000, 5500)),
    200250: ('TP', (500, 1000, 3000, 5500)),
    200251: ('TP', (4, 7, 19, 36)),
    200252: ('TP', (4, 7, 19, 36)),
    200253: ('TP', (4, 7, 19, 36)),
    200254: ('TP', (0,)),
    200255: ('TP', (0,)),
    200263: ('TP', (4900,)),
    200264: ('GP', (37500,)),
    200265: ('GP', (19500,)),
    200266: ('TP', (4, 8, 16, 26)),
    200267: ('TP', (4, 8, 21, 21)),
    200268: ('TP', (500,)),
    200269: ('TP', (5, 14, 25, 72)),
    200270: ('TP', (5, 14, 25, 72)),
    200271: ('TP', (5, 14, 25, 72)),
    200272: ('TP', (5, 14, 25, 72)),
    200273: ('TP', (5, 14, 25, 72)),
    200274: ('TP', (0,)),
    200275: ('TP', (0,)),
    200276: ('TP', (5, 14, 25, 72)),
    200279: ('TP', (5, 14, 25, 72)),
    200280: ('TP', (5, 14, 25, 72)),
    200281: ('TP', (5, 14, 25, 72)),
    200282: ('TP', (5, 14, 25, 72)),
    200283: ('MP', (500,)),
    200287: ('TP', (1500, 4500, 7000, 8800)),
    200288: ('TP', (10, 17, 46, 83)),
    200291: ('TP', (5, 10, 18, 30)),
    200293: ('TP', (3200,)),
    200295: ('GP', (22500,)),
    200296: ('GP', (22500,)),
    200297: ('GP', (21000,)),
    200298: ('MP', (750, 1500, 4500)),
    200302: ('MP', (450, 900, 2700)),
    200303: ('TP', (5, 9, 18, 30)),
    200304: ('MP', (400, 800, 2400)),
    200305: ('MP', (900, 1800, 5400)),
    200310: ('TP', (800,)),
    200311: ('TP', (800,)),
    200312: ('TP', (800,)),
    200314: ('TP', (400, 800, 2400, 4500)),
    200316: ('MP', (600, 1200, 2400, 4800)),
    200317: ('TP', (500, 1000, 3000, 5500)),
    200318: ('TP', (400, 800, 2400, 4500)),
    200319: ('TP', (5000,)),
    200320: ('TP', (5, 14, 25, 72)),
    200321: ('TP', (5, 14, 25, 72)),
    200322: ('TP', (1200, 3600, 6000, 7500)),
    200323: ('TP', (1200, 3600, 6000, 7500)),
    200324: ('TP', (1200, 3600, 6000, 7500)),
    200325: ('TP', (1500, 4500, 7000, 8800)),
    200326: ('TP', (1500, 4500, 7000, 8800)),
    200327: ('TP', (1500, 4500, 7000, 8800)),
    200328: ('GP', (8000,)),
    200329: ('TP', (2900,)),
    200330: ('TP', (0,)),
    200331: ('MP', (900, 1800, 5400)),
    200332: ('TP', (10, 27, 49, 80)),
    200336: ('TP', (600,)),
    200342: ('TP', (500,)),
    200343: ('GP', (30000,)),
    200344: ('TP', (10, 27, 74, 119)),
    200345: ('TP', (10, 27, 74, 119)),
    200346: ('TP', (10, 27, 74, 119)),
    200347: ('TP', (10, 27, 74)),
    200348: ('TP', (10, 27, 74, 119)),
    200349: ('TP', (10, 27, 74, 119)),
    200350: ('TP', (10, 27, 74)),
    200351: ('TP', (10, 27, 74, 119)),
    200352: ('TP', (10, 27, 74, 119)),
    200353: ('TP', (10, 27, 74)),
    200356: ('TP', (10, 17, 46, 83)),
    200357: ('TP', (3, 6, 12, 28)),
    200360: ('MP', (500,)),
    200361: ('MP', (500,)),
    200362: ('MP', (500,)),
    200363: ('MP', (500,)),
    200364: ('MP', (500,)),
    200368: ('TP', (600,)),
    200371: ('TP', (9, 17, 46, 83)),
    200372: ('TP', (1500, 4500, 7000, 8800)),
    200373: ('TP', (12, 29, 55)),
    200375: ('TP', (12, 29, 55)),
    200378: ('TP', (1200, 3600, 6500, 8200)),
    200380: ('MP', (800, 1600, 3200, 6400)),
    200388: ('TP', (1000,)),
    200389: ('TP', (1000,)),
    200390: ('TP', (1000,)),
    200397: ('TP', (1000,)),
    200399: ('TP', (2000,)),
    200414: ('TP', (600,)),
    200417: ('TP', (600,)),
    200421: ('TP', (600,)),
    200426: ('TP', (4, 8, 16, 26)),
    200439: ('TP', (800,)),
    200440: ('TP', (800,)),
    200441: ('TP', (800,)),
    200444: ('TP', (600,)),
    200446: ('TP', (1500, 4600, 7200, 9000)),
    200447: ('TP', (400,)),
    200448: ('TP', (0,)),
    200457: ('TP', (400,)),
    200459: ('TP', (1300, 3900, 6800, 8800)),
    200460: ('TP', (1000, 2500, 4500, 6500)),
    200465: ('TP', (1200, 3600, 6500, 8200)),
    200466: ('TP', (1800, 5500, 8500)),
    200467: ('TP', (1700, 5200, 8200)),
    200468: ('TP', (1900, 5600, 8800)),
    200469: ('TP', (1800, 5000, 8800)),
    200470: ('TP', (1200, 3500, 6000)),
    200471: ('TP', (1500, 4500, 7500)),
    200481: ('TP', (800, 2000, 4200, 7500)),
    200482: ('TP', (1200, 3600, 7000, 9800)),
    200483: ('TP', (0,)),
    200484: ('TP', (0,)),
    200485: ('TP', (1400, 4300, 6700, 8500)),
    200486: ('TP', (1500, 4500, 7200, 9000)),
    200489: ('TP', (600, 5000, 24000)),
    200490: ('TP', (0,)),
    200491: ('TP', (0,)),
    200492: ('TP', (0,)),
    200493: ('TP', (0,)),
    200494: ('TP', (0,)),
    200495: ('TP', (0,)),
    200496: ('TP', (0,)),
    200497: ('TP', (0,)),
    200498: ('TP', (0,)),
    200499: ('TP', (0,)),
    200500: ('TP', (0,)),
    200501: ('TP', (0,)),
    200505: ('TP', (4, 8, 16, 26)),
    200506: ('MP', (3000, 6000, 12000)),
    200507: ('MP', (2500, 5000, 10000)),
    200508: ('MP', (3750, 7500, 15000)),
    200509: ('MP', (3000, 6000, 12000)),
    200512: ('TP', (0,)),
    200513: ('TP', (0,)),
    200514: ('TP', (0,)),
    200515: ('TP', (50, 135, 255)),
    200516: ('TP', (800,)),
    200517: ('TP', (800,)),
    200518: ('TP', (500, 1000, 3000, 5500)),
    200519: ('TP', (500, 1000, 3000, 5500)),
    200520: ('TP', (500, 1000, 3000, 5500)),
    200521: ('TP', (3200,)),
    200522: ('TP', (3200,)),
    200523: ('TP', (0,)),
    200524: ('TP', (4, 8, 16, 26)),
    200526: ('TP', (1500, 4500, 7000, 8800)),
    200527: ('TP', (2000, 6000, 9900)),
    200537: ('TP', (20, 40, 100, 150)),
    200539: ('TP', (800,)),
    200540: ('TP', (800,)),
    200541: ('TP', (800,)),
    200549: ('TP', (3100, 9500)),
    200550: ('TP', (2200, 6900)),
    200552: ('TP', (2900,)),
    200553: ('TP', (20, 40, 100, 150)),
    200554: ('TP', (20, 40, 100, 150)),
    200555: ('TP', (1300, 4000, 6500, 8500)),
    200556: ('TP', (1000, 3000)),
    200557: ('TP', (1500, 2600, 8000)),
    200558: ('TP', (1500, 2600, 8500)),
    200559: ('TP', (0,)),
    200560: ('TP', (6, 12, 24, 42)),
    200562: ('MP', (1200,)),
    200563: ('MP', (750,)),
    200565: ('TP', (1000,)),
    200566: ('TP', (1000,)),
    200567: ('TP', (0,)),
    200569: ('TP', (600,)),
    200570: ('TP', (600,)),
    200571: ('TP', (600,)),
    200573: ('TP', (8000,)),
    200574: ('TP', (800, 2400, 5200)),
    200575: ('TP', (0,)),
    200576: ('TP', (2000,)),
    200578: ('TP', (3000,)),
    200580: ('TP', (2000,)),
    200581: ('TP', (0,)),
    200582: ('TP', (1000, 3000, 6000, 8000)),
    200583: ('GP', (100000,)),
    200584: ('TP', (1200, 3600, 6500, 8200)),
    200588: ('TP', (6000,)),
    200592: ('TP', (0,)),
    200593: ('TP', (0,)),
    200594: ('TP', (1000, 2000, 6000, 12000)),
    200595: ('TP', (26900,)),
    200596: ('TP', (800, 2600, 5800, 8000)),
    200597: ('TP', (800,)),
    200598: ('TP', (800,)),
    200599: ('TP', (800,)),
    200600: ('TP', (800,)),
    200601: ('TP', (800,)),
    200602: ('TP', (800,)),
    200605: ('TP', (0,)),
    200607: ('TP', (0,)),
    200608: ('GP', (30000,)),
    200609: ('TP', (0,)),
    200611: ('TP', (1300, 4000, 6800, 8800)),
    200612: ('TP', (6, 12, 24, 42)),
    200614: ('TP', (0,)),
    200615: ('TP', (19900,)),
    200616: ('TP', (6000,)),
    200619: ('TP', (0,)),
    200620: ('TP', (16900,)),
    200622: ('TP', (6000,)),
    200623: ('TP', (19900,)),
    200626: ('TP', (1600, 4800, 7500, 9500)),
    200627: ('TP', (800, 2400, 4000, 4800)),
    200628: ('TP', (2000, 5000, 8000, 10000)),
    200630: ('TP', (500, 1500, 2500, 3000)),
    200631: ('GP', (50000,)),
    200632: ('TP', (28800,)),
    200633: ('TP', (0,)),
    200634: ('TP', (500,)),
    210001: ('GP', (10000,)),
    210002: ('GP', (10000,)),
    210006: ('TP', (4, 8, 16, 26)),
    210007: ('TP', (4, 8, 21, 37)),
}


def _v75_item_id_for_commodity(commodity_id):
    mapping, source = _v75_load_shop_item_map()
    if commodity_id in mapping:
        return mapping[commodity_id] & 0xFFFFFFFF, "override:" + str(source or "builtin")
    # Best-effort default. Some Assault Fire data sets reuse the resource ItemId
    # as CommodityId. If this SKU does not, the server log prints both IDs and
    # the mapping can be corrected without changing code.
    return commodity_id & 0xFFFFFFFF, "fallback:commodity_id"


def _v78_price_for_commodity(commodity_id, price_index):
    row = REAL_SHOP_PRICES.get(int(commodity_id))
    if not row:
        return "", 0, "catalog-miss"
    currency, prices = row
    if not prices:
        return currency, 0, "no-prices"
    idx = int(price_index)
    if idx < 0 or idx >= len(prices):
        return currency, 0, f"bad-price-index:{idx}/{len(prices)}"
    return currency, int(prices[idx]), "catalog"


class _v89_ShopReject(Exception):
    def __init__(self, result, message):
        super().__init__(message)
        self.result = int(result) & 0xffff
        self.message = str(message)


def _v89_expected_pay_type(currency):
    return {"GP": PAY_GP, "TP": PAY_TP, "MP": PAY_MP}.get(str(currency))


def _v89_next_free_gid(candidate, used_gids):
    """Return a non-zero u64 GID not already present in this inventory."""
    candidate = int(candidate) & 0xffffffffffffffff
    for _ in range(0x100000):
        if candidate and candidate not in used_gids:
            return candidate
        candidate = (candidate + 1) & 0xffffffffffffffff
    raise _v89_ShopReject(SHOP_ERR_FAIL, "unable to allocate a free property GID")


def _v89_plan_buy(req, inventory, next_gid, ap_balance, gp_balance, mp_balance):
    """Validate an A505 transaction without mutating player state.

    The old shop granted props first and only afterwards clamped balances to
    zero.  A malformed/expensive request could therefore create free items or
    partially mutate inventory.  This function stages the full transaction,
    validates catalog mapping/pay type/funds, then returns a commit plan.
    """
    if int(req.get("count", 0)) <= 0 or not req.get("commodities"):
        raise _v89_ShopReject(SHOP_ERR_SHOPCART_EMPTY, "empty shop cart")

    # The local preservation backend currently implements the normal single-
    # currency shop paths.  Do not silently mis-account mixed/voucher requests.
    pay_type = int(req.get("pay_type", 0))
    if pay_type not in (PAY_GP, PAY_TP, PAY_MP):
        raise _v89_ShopReject(
            SHOP_ERR_PAYTYPE_INVALID,
            f"unsupported pay_type={pay_type} (mixed/voucher payment not implemented)",
        )
    if int(req.get("convert_mp", 0)) != 0:
        raise _v89_ShopReject(
            SHOP_ERR_PAYTYPE_INVALID,
            f"ConvertMP={int(req.get('convert_mp', 0))} not supported by local wallet",
        )

    # Live normal self-purchases are BuyType=1 and Consignne=self.  Reject gift
    # semantics rather than incorrectly placing another player's gift in the
    # local inventory.
    consignne = int(req.get("consignne") or LOCAL_UIN)
    if int(req.get("buy_type", 0)) != 1 or consignne != LOCAL_UIN:
        raise _v89_ShopReject(
            SHOP_ERR_FAIL,
            f"unsupported buy target/type buy_type={req.get('buy_type')} consignne={consignne}",
        )

    used_gids = {int(p.get("gid", 0)) & 0xffffffffffffffff for p in inventory}
    cursor = int(next_gid) & 0xffffffffffffffff
    staged = []
    totals = {"TP": 0, "GP": 0, "MP": 0}

    for c in req["commodities"]:
        commodity_id = int(c["commodity_id"])
        price_index = int(c["price_index"])
        currency, server_price, price_source = _v78_price_for_commodity(
            commodity_id, price_index
        )
        if price_source.startswith("bad-price-index"):
            raise _v89_ShopReject(
                SHOP_ERR_COMMODITY_PERIODINVALID,
                f"commodity={commodity_id} {price_source}",
            )
        if price_source != "catalog" or currency not in ("TP", "GP", "MP"):
            raise _v89_ShopReject(
                SHOP_ERR_COMMODITY_NOTEXIST,
                f"commodity={commodity_id} has no authoritative catalog price ({price_source})",
            )

        item_id, map_source = _v75_item_id_for_commodity(commodity_id)
        if not str(map_source).startswith("override:"):
            raise _v89_ShopReject(
                SHOP_ERR_COMMODITY_NOTEXIST,
                f"commodity={commodity_id} has no authoritative item mapping ({map_source})",
            )

        expected_pay = _v89_expected_pay_type(currency)
        if pay_type != expected_pay:
            raise _v89_ShopReject(
                SHOP_ERR_PAYTYPE_INVALID,
                f"commodity={commodity_id} currency={currency} requires pay_type={expected_pay}, got {pay_type}",
            )
        if int(c.get("voucher_id", 0)) != 0:
            raise _v89_ShopReject(
                SHOP_ERR_PAYTYPE_INVALID,
                f"voucher_id={int(c.get('voucher_id', 0))} is not implemented by local wallet",
            )

        server_price = int(server_price)
        if server_price < 0 or server_price > 0xffffffff:
            raise _v89_ShopReject(SHOP_ERR_FAIL, f"invalid catalog price={server_price}")
        totals[currency] += server_price
        if totals[currency] > 0xffffffff:
            raise _v89_ShopReject(SHOP_ERR_FAIL, f"transaction total overflow for {currency}")

        gid = _v89_next_free_gid(cursor, used_gids)
        used_gids.add(gid)
        cursor = (gid + 1) & 0xffffffffffffffff
        if cursor == 0:
            cursor = ((LOCAL_UIN & 0xffffffff) << 32) | 4

        prop = _v75_make_prop(gid, item_id)
        staged.append({
            "commodity_id": commodity_id,
            "price_index": price_index,
            "client_price": int(c.get("price", 0)),
            "voucher_id": int(c.get("voucher_id", 0)),
            "currency": currency,
            "server_price": server_price,
            "price_source": price_source,
            "map_source": map_source,
            "prop": prop,
        })

    if totals["TP"] > int(ap_balance):
        raise _v89_ShopReject(
            SHOP_ERR_NOTENOUGHMONEY,
            f"not enough AP: need={totals['TP']} have={int(ap_balance)}",
        )
    if totals["GP"] > int(gp_balance):
        raise _v89_ShopReject(
            SHOP_ERR_NOTENOUGHMONEY,
            f"not enough GP: need={totals['GP']} have={int(gp_balance)}",
        )
    if totals["MP"] > int(mp_balance):
        raise _v89_ShopReject(
            SHOP_ERR_NOTENOUGHMONEY,
            f"not enough MP: need={totals['MP']} have={int(mp_balance)}",
        )

    return {
        "bought": staged,
        "consume_tp": totals["TP"],
        "consume_gp": totals["GP"],
        "consume_mp": totals["MP"],
        "next_gid": cursor,
    }


def _v89_parse_tp_balance_request(body):
    # Live A50E body observed from TGame is exactly one u64 PlayerUin.
    if len(body) != 8:
        raise ValueError(f"TPBalance request must be 8B, got {len(body)}")
    return struct.unpack(">Q", body)[0]


def _v75_parse_shop_conf_hash(body):
    if len(body) != 4:
        raise ValueError(f"ShopConfHash request must be 4B, got {len(body)}")
    return struct.unpack(">I", body)[0]


def _v75_build_shop_conf_hash_response(client_hash):
    # ZN2C_ResShopConfHash: Result u16 | ServerHash u32 | Url string[256]
    # Echoing the hash tells TGame its local CommodityLibrary is current.
    body = (
        _v48_u16(SHOP_ERR_SUCC)
        + _v48_u32(client_hash)
        + _v50_geo_tdr_string("", 256)
    )
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_RES_SHOPCONFHASH, body)


def _v75_parse_buy_commodity(body):
    # C2ZN_ReqBuyCommodity:
    # u16 BuyType | u64 Consignne | string[32] ConsignneNickName | u16 Count |
    # ShopCommodity[Count] | u16 PayType | u32 ConvertMP | string[256] Remark
    if len(body) < 16:
        raise ValueError(f"BuyCommodity body too short: {len(body)}")
    off = 0
    buy_type = struct.unpack_from(">H", body, off)[0]; off += 2
    consignne = struct.unpack_from(">Q", body, off)[0]; off += 8
    nickname, off = _v75_read_tdr_string(body, off, 32)
    if off + 2 > len(body):
        raise ValueError("BuyCommodity missing Count")
    count = struct.unpack_from(">H", body, off)[0]; off += 2
    if count > 20:
        raise ValueError(f"BuyCommodity Count={count} exceeds 20")
    commodities = []
    for _ in range(count):
        if off + 14 > len(body):
            raise ValueError("BuyCommodity truncated ShopCommodity")
        commodity_id = struct.unpack_from(">I", body, off)[0]; off += 4
        price_index = struct.unpack_from(">H", body, off)[0]; off += 2
        price = struct.unpack_from(">I", body, off)[0]; off += 4
        voucher_id = struct.unpack_from(">I", body, off)[0]; off += 4
        commodities.append({
            "commodity_id": commodity_id,
            "price_index": price_index,
            "price": price,
            "voucher_id": voucher_id,
        })
    if off + 6 > len(body):
        raise ValueError("BuyCommodity missing PayType/ConvertMP")
    pay_type = struct.unpack_from(">H", body, off)[0]; off += 2
    convert_mp = struct.unpack_from(">I", body, off)[0]; off += 4
    remark, off = _v75_read_tdr_string(body, off, 256)
    if off != len(body):
        raise ValueError(f"BuyCommodity trailing bytes: {len(body)-off}")
    return {
        "buy_type": buy_type,
        "consignne": consignne,
        "nickname": nickname,
        "count": count,
        "commodities": commodities,
        "pay_type": pay_type,
        "convert_mp": convert_mp,
        "remark": remark,
    }


def _v75_make_prop(gid, item_id, owner_gid=0, location=PROP_LOC_BAG,
                   uin=LOCAL_UIN, avail_hours=LOCAL_ITEM_AVAIL_HOURS,
                   durability=100, durability_max=100, gain_type=PROP_GAIN_BUY):
    return {
        "uin": int(uin), "gid": int(gid), "item_id": int(item_id),
        "res_flag": 0, "stack_num": 1, "obtain_time": 0,
        # Weapons use a sane non-zero durability. Hidden backpack entitlement
        # props are non-repairable in the item library and use 0/0.
        "validity": int(avail_hours),
        "durability": int(durability), "durability_max": int(durability_max),
        "owner_gid": int(owner_gid), "location": int(location),
        "avail_hours": int(avail_hours), "use_hour": 0, "gain_type": int(gain_type),
    }


def _v75_pack_prop_info(p):
    # PropInfo is exactly 70 bytes in proto_c2zn.tdr.
    raw = (
        _v48_u64(p["uin"])
        + _v48_u64(p["gid"])
        + _v48_u32(p["item_id"])
        + _v48_u64(p.get("res_flag", 0))
        + _v48_u32(p.get("stack_num", 1))
        + _v48_u64(p.get("obtain_time", 0))
        + _v48_u32(p.get("validity", LOCAL_ITEM_AVAIL_HOURS))
        + _v48_u32(p.get("durability", 0))
        + _v48_u32(p.get("durability_max", 0))
        + _v48_u64(p.get("owner_gid", 0))
        + _v48_u8(p.get("location", PROP_LOC_BAG))
        + _v48_u32(p.get("avail_hours", LOCAL_ITEM_AVAIL_HOURS))
        + _v48_u32(p.get("use_hour", 0))
        + _v48_u8(p.get("gain_type", PROP_GAIN_BUY))
    )
    if len(raw) != 70:
        raise AssertionError(f"PropInfo packed size {len(raw)} != 70")
    return raw


def _v75_build_playerprops_packets(props):
    # The schema caps Props at 5 entries per ZN2C_NtfPlayerProps packet.
    props = list(props)
    chunks = [props[i:i+5] for i in range(0, len(props), 5)] or [[]]
    out = []
    for idx, chunk in enumerate(chunks):
        is_last = 1 if idx == len(chunks) - 1 else 0
        body = (
            _v48_u16(ZONE_ERR_SUCC)
            + _v48_u8(is_last)
            + _v48_i16(len(chunk))
            + b"".join(_v75_pack_prop_info(p) for p in chunk)
        )
        out.append(_v62_build_server_app(
            TGAME_ZN_MAGIC, TGAME_ZN_NTF_PLAYERPROPS, body
        ))
    return out


def _v75_parse_prop_operation(body):
    # C2ZN_ReqPropOperation = u16 + u64 + u64 + u8 = 19 bytes.
    if len(body) != 19:
        raise ValueError(f"PropOperation must be 19B, got {len(body)}")
    return {
        "operation": struct.unpack_from(">H", body, 0)[0],
        "subject_gid": struct.unpack_from(">Q", body, 2)[0],
        "target_gid": struct.unpack_from(">Q", body, 10)[0],
        "location": body[18],
    }


def _v75_build_prop_operation_response(req_body):
    # Legacy A200/A201 diagnostic path retained untouched.  Do not use this
    # builder for live A008: the verified A009 form is Result + operation and
    # is built by _v79_build_live_prop_operation_response below.
    body = _v48_u16(ZONE_ERR_SUCC) + bytes(req_body)
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_RES_ITEM_OPERATION, body)


def _v79_build_live_prop_operation_response(req_body):
    """Build the real A009 response for a live A008 equip/takeoff request.

    Re-reading the compiled proto_c2zn.tdr string table shows the three
    PropOperation structures consecutively:

      C2ZN_ReqPropOperation:  Operation, SubjectGID, TargetGID, Location
      ZN2C_ResPropOperation:  Result, Operation, SubjectGID, TargetGID, Location
      ZN2C_NtfPropOperation:  Operation, SubjectGID, TargetGID, Location

    The live request body is exactly 19 bytes (u16 + u64 + u64 + u8).
    Therefore A009 is Result(u16) followed by the exact 19-byte operation.
    """
    req_body = bytes(req_body)
    if len(req_body) != 19:
        raise ValueError(f"PropOperation request must be exactly 19B, got {len(req_body)}")
    body = _v48_u16(ZONE_ERR_SUCC) + req_body
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_PROP_OPERATION, body
    )


def _v79_build_live_prop_operation_notification(req_body):
    """Build A00A notification carrying the accepted operation itself."""
    req_body = bytes(req_body)
    if len(req_body) != 19:
        raise ValueError(f"PropOperation notification must be exactly 19B, got {len(req_body)}")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_PROP_OPERATION, req_body
    )


def _v83_moneyflow_datetime(dt=None):
    """Serialize the 8-byte TDR datetime used by Consumer List rows.

    TGame's formatter at 0x016BD7D0 reads the decoded layout as:
      int16 year, uint8 month, uint8 day, int16 hour, uint8 minute, uint8 second.
    Multi-byte TDR fields are big-endian on the wire.
    """
    import datetime as _datetime
    if dt is None:
        dt = _datetime.datetime.now()
    raw = struct.pack(
        ">hBBhBB",
        int(dt.year), int(dt.month), int(dt.day),
        int(dt.hour), int(dt.minute), int(dt.second),
    )
    if len(raw) != 8:
        raise AssertionError(f"moneyflow datetime wire size {len(raw)} != 8")
    return raw


def _v81_pack_moneyflow_record(money_type, number, current, reason=MONEYREASON_BUY,
                               uin=LOCAL_UIN, dt=None):
    """Serialize one 26-byte PlayerMoneyFlow record for ZN2C_NtfMoneyFlow.

    Exact decoded record layout recovered from
    UTGOnlineClient::HandleMessage_Notification_ConsumList at 0x014F4370:
      u64 Uin | datetime Time(8) | u8 MoneyType |
      i32 Number | i32 Current | u8 Reason

    v84 money-flow record semantics:
      * MoneyFlowReasonEnums is zero-based, so BUY=1
      * Time is a real calendar datetime instead of eight zero bytes
    """
    raw = (
        _v48_u64(uin)
        + _v83_moneyflow_datetime(dt)
        + _v48_u8(money_type)
        + _v48_i32(number)
        + _v48_i32(current)
        + _v48_u8(reason)
    )
    if len(raw) != 26:
        raise AssertionError(f"PlayerMoneyFlow wire size {len(raw)} != 26")
    return raw

def _v81_build_moneyflow_notification(records):
    """Build ZN2C_NtfMoneyFlow (0xE001).

    v85 correction: the decoded Consumer List object stores Count as a DWORD,
    and the original v81-v83 u32 count matches the compiled schema shape.
    A one-row body is therefore 4-byte Count + one 26-byte PlayerMoneyFlow
    record = 30 bytes (0x001E).
    """
    records = list(records)
    if len(records) > 0xffffffff:
        raise ValueError("too many money-flow rows")
    body = _v48_u32(len(records)) + b"".join(records)
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_NTF_MONEYFLOW, body)


def _v77_parse_cardinfo_request(body):
    # Live C2ZN_ReqCardInfo is a single u64 PlayerUin.  We intentionally do
    # not synthesize C00E until its nested CardInfo resource fields are mapped.
    if len(body) != 8:
        raise ValueError(f"CardInfo request must be 8B, got {len(body)}")
    return struct.unpack(">Q", body)[0]


def _v75_parse_change_role(body):
    if len(body) != 4:
        raise ValueError(f"ChangeRole must be 4B, got {len(body)}")
    return struct.unpack(">HH", body)


def _v75_build_change_role_response():
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_CHANGE_ROLE, _v48_u16(ZONE_ERR_SUCC)
    )


def _v75_build_buy_commodity_response(req, bought, consume_tp=0, tp_balance=LOCAL_TP_BALANCE, consume_gp=0, consume_mp=0, result=SHOP_ERR_SUCC):
    # ZN2C_ResBuyCommodity:
    # Result, BuyType, PayType, NickName, ConsumeTP, TPBalance, ConsumeGP,
    # ConsumeMP, Count, ShopResBuyCommodity[Count], ConsignneUin.
    commodity_parts = []
    for row in bought:
        prop = row["prop"]
        buy_prop = (
            _v48_u64(prop["gid"])
            + _v48_u32(prop["item_id"])
            + _v48_u32(prop.get("avail_hours", LOCAL_ITEM_AVAIL_HOURS))
        )
        commodity_parts.append(
            _v48_u32(row["commodity_id"])
            + _v48_u16(row["price_index"])
            + _v48_u32(1)  # one ShopResBuyProp
            + buy_prop
        )
    body = (
        _v48_u16(result)
        + _v48_u16(req["buy_type"])
        + _v48_u16(req["pay_type"])
        + _v50_geo_tdr_string(req.get("nickname", ""), 32)
        + _v48_u32(consume_tp)
        + _v48_u32(tp_balance)
        + _v48_u32(consume_gp)
        + _v48_u32(consume_mp)
        + _v48_u16(len(commodity_parts))
        + b"".join(commodity_parts)
        + _v48_u64(req.get("consignne") or LOCAL_UIN)
    )
    return _v62_build_server_app(TGAME_ZN_MAGIC, TGAME_ZN_RES_BUYCOMMODITY, body)


def _v80_pack_prop_operation(op):
    return struct.pack(
        ">HQQB",
        int(op["operation"]) & 0xffff,
        int(op["subject_gid"]) & 0xffffffffffffffff,
        int(op["target_gid"]) & 0xffffffffffffffff,
        int(op["location"]) & 0xff,
    )


REAL_ITEM_DEFAULT_LOCATIONS = {
    100001: 0,
    100002: 0,
    100003: 0,
    100004: 0,
    100005: 1,
    100006: 0,
    100007: 0,
    100008: 0,
    100009: 1,
    100010: 3,
    100011: 4,
    100012: 5,
    100014: 10,
    100016: 11,
    100017: 0,
    100018: 1,
    100019: 2,
    100023: 0,
    100024: 1,
    100025: 2,
    100027: 0,
    100028: 11,
    100029: 0,
    100030: 1,
    100031: 2,
    100032: 3,
    100033: 4,
    100035: 12,
    100036: 12,
    100037: 12,
    100041: 0,
    100054: -1,
    100056: 0,
    100057: 0,
    100058: 2,
    100059: 13,
    100060: 14,
    100061: 10,
    100062: 10,
    100064: 0,
    100068: 0,
    100069: 11,
    100070: 0,
    100071: 0,
    100072: 1,
    100073: 0,
    100074: 0,
    100075: 0,
    100076: 0,
    100077: 2,
    100078: 2,
    100079: 3,
    100080: 0,
    100081: 1,
    100082: 1,
    100083: 1,
    100084: 1,
    100085: 1,
    100086: 1,
    100087: 1,
    100088: 1,
    100089: 0,
    100090: 0,
    100091: 0,
    100092: 0,
    100093: 2,
    100094: 2,
    100095: 2,
    100096: 2,
    100097: 2,
    100098: 2,
    100099: 0,
    100100: 0,
    100101: 2,
    100102: 2,
    100103: 0,
    100104: 1,
    100105: 0,
    100111: 0,
    100112: 0,
    100113: 0,
    100114: 0,
    100115: 10,
    100116: 1,
    100117: 1,
    100118: 0,
    100119: 0,
    100120: 2,
    100121: 2,
    100122: 0,
    100123: 11,
    100124: 1,
    100125: 1,
    100126: 0,
    100127: 0,
    100128: 2,
    100129: 2,
    100130: 0,
    100131: 0,
    100133: 0,
    100134: 1,
    100141: 0,
    100143: 18,
    100145: -1,
    100146: -1,
    100147: -1,
    100148: -1,
    100149: -1,
    100150: -1,
    100153: 10,
    100154: 9,
    100155: 9,
    100156: 9,
    100157: 9,
    100158: 9,
    100159: 9,
    100160: 9,
    100161: 9,
    100162: 9,
    100163: 9,
    100164: 9,
    100165: 9,
    100166: 9,
    100167: 9,
    100168: 9,
    100169: 9,
    100170: 9,
    100171: 0,
    100172: 0,
    100174: 0,
    100175: 0,
    100176: 0,
    100177: 0,
    100178: 0,
    100179: 1,
    100180: 2,
    100181: -1,
    100182: -1,
    100183: 15,
    100184: 10,
    100196: -1,
    100197: 17,
    100198: 0,
    100199: 11,
    100200: 0,
    100201: 1,
    100202: 1,
    100203: 2,
    100205: 8,
    100206: 0,
    100207: 1,
    100208: 2,
    100210: -1,
    100211: 19,
    100212: 3,
    100214: 0,
    100215: 12,
    100216: 10,
    100217: 11,
    100218: 1,
    100219: 1,
    100220: 0,
    100221: 0,
    100222: 1,
    100223: 2,
    100224: 0,
    100226: 0,
    100230: 1,
    100232: 0,
    100238: 0,
    100239: 2,
    100240: 28,
    100241: 30,
    100242: 25,
    100243: 26,
    100244: 27,
    100245: 20,
    100246: 21,
    100259: 3,
    100260: 0,
    100261: 0,
    100262: 0,
    100263: 1,
    100264: 0,
    100265: 0,
    100266: 1,
    100267: 0,
    100268: 1,
    100269: 2,
    100270: 10,
    100271: 11,
    100272: 1,
    100273: 0,
    100275: 1,
    100276: 0,
    100277: 2,
    100278: 1,
    100279: 0,
    100283: 0,
    100284: 0,
    100287: 0,
    100289: 2,
    100291: 0,
    100292: 0,
    100293: 0,
    100294: 0,
    100295: 1,
    100296: 0,
    100297: 0,
    100298: 0,
    100303: 2,
    100304: 1,
    100305: 0,
    100307: 3,
    100309: 0,
    100310: 23,
    100311: 24,
    100312: 3,
    100320: 0,
    100321: 0,
    100322: 0,
    100323: 0,
    100324: 0,
    100325: 0,
    100326: 0,
    100327: 0,
    100328: 0,
    100329: 0,
    100330: 0,
    100331: 0,
    100332: 9,
    100333: 10,
    100334: 11,
    100335: 0,
    100336: 0,
    100337: 0,
    100341: 0,
    100347: 12,
    100348: 0,
    100349: 9,
    100350: 9,
    100351: 9,
    100352: 9,
    100353: 9,
    100354: 9,
    100355: 9,
    100356: 9,
    100357: 9,
    100358: 9,
    100365: 0,
    100366: 0,
    100369: 2,
    100370: 1,
    100371: 0,
    100372: 2,
    100373: 1,
    100377: 0,
    100380: 0,
    100381: 0,
    100382: 11,
    100384: 10,
    100387: 0,
    100389: 0,
    100390: 2,
    100392: 0,
    100399: 9,
    100400: 9,
    100401: 9,
    100408: 9,
    100410: 9,
    100425: 2,
    100428: 2,
    100432: 1,
    100437: 0,
    100450: 2,
    100451: 1,
    100452: 0,
    100455: 2,
    100457: 0,
    100458: 10,
    100459: 3,
    100460: 0,
    100470: 11,
    100472: 0,
    100473: 3,
    100478: 0,
    100479: 0,
    100480: 0,
    100481: 0,
    100482: 0,
    100483: 1,
    100484: 2,
    100490: 0,
    100496: 0,
    100497: 0,
    100498: 0,
    100499: 0,
    100500: -1,
    100502: 0,
    100503: 0,
    100504: 0,
    100505: 0,
    100506: 0,
    100507: 0,
    100508: 0,
    100509: 0,
    100510: 0,
    100511: 0,
    100512: 1,
    100513: 0,
    100517: -1,
    100521: 0,
    100522: 0,
    100523: 0,
    100524: 0,
    100525: 0,
    100527: 2,
    100528: 0,
    100529: 1,
    100530: 2,
    100531: 31,
    100532: 32,
    100533: 33,
    100534: 0,
    100536: 0,
    100537: 34,
    100547: 0,
    100549: 0,
    100550: 1,
    100551: 2,
    100561: 11,
    100562: 0,
    100563: 0,
    100564: 0,
    100565: 0,
    100566: -1,
    100567: -1,
    100568: 35,
    100569: 1,
    100573: 9,
    100574: 9,
    100575: -1,
    100576: -1,
    100578: -1,
    100580: -1,
    100581: 0,
    100587: -1,
    100588: 0,
    100589: 1,
    100590: 2,
    100591: 36,
    100592: 37,
    100593: 0,
    100594: 0,
    100595: 2,
    100599: 11,
    100600: 10,
    100601: 0,
    100602: 0,
    100603: 0,
    100604: 0,
    100605: 1,
    100606: 0,
    100607: 1,
    100608: 2,
    100609: 0,
    100610: 1,
    100611: 2,
    100614: -1,
    100616: -1,
    100617: 0,
    100618: 0,
    100620: 0,
    100621: 0,
    100623: 10,
    100624: 0,
    100626: 11,
    100627: 1,
    100629: 39,
    100638: 0,
    100639: 0,
    100640: 0,
    100642: 1,
    100643: 2,
    100645: 0,
    100646: 0,
    100647: 2,
    100648: 0,
    100649: 1,
    100928: 12,
    110001: 0,
    110002: 0,
    110004: 0,
    110005: 2,
    200001: 12,
    200002: 12,
    200003: 12,
    200004: 12,
    200005: 12,
    200006: 12,
    200007: 12,
    200008: 12,
    200009: 12,
    200010: 12,
    210001: 12,
    210002: 12,
    210003: 12,
    210004: 12,
    210005: 12,
    210006: 12,
    210007: 12,
    210008: 12,
    210009: 12,
    210010: 12,
    210011: 12,
    210012: 12,
    210013: 12,
    210014: 12,
    210015: 12,
    210016: 12,
    210017: 12,
    210018: 12,
    210019: 12,
    210020: 12,
    220001: 12,
    220002: 12,
    220003: 12,
    220004: 12,
    220005: 12,
    220006: 12,
    220007: 12,
    220008: 12,
    220009: 12,
    220010: 12,
    300002: -1,
    300003: -1,
    300012: -1,
    300013: -1,
    300017: -1,
    300018: -1,
    300022: -1,
    300023: -1,
    300027: -1,
    300028: -1,
    300032: -1,
    300033: -1,
    300037: -1,
    300038: -1,
    300042: -1,
    300043: -1,
    300047: -1,
    300048: -1,
    300052: -1,
    300053: -1,
    300057: -1,
    300058: -1,
    300062: -1,
    300063: -1,
    300067: -1,
    300068: -1,
    300072: -1,
    300073: -1,
    300077: -1,
    300078: -1,
    300082: -1,
    300083: -1,
    300087: -1,
    300088: -1,
    300092: -1,
    300093: -1,
    300102: -1,
    300103: -1,
    300107: -1,
    300108: -1,
    300112: -1,
    300113: -1,
    300117: -1,
    300118: -1,
    300119: -1,
    300120: -1,
    300121: -1,
    300122: -1,
    300123: -1,
    300124: -1,
    300125: -1,
    300126: -1,
}


def _v80_apply_prop_operation(inventory, op, current_role_gid=LOCAL_ROLE_GID):
    """Apply A008 while preserving Assault Fire's backpack/loadout semantics.

    v84 fixes two live-observed cases:
      * Location=Bag (0x0C) is NON-EXCLUSIVE.  Multiple props can belong to
        the same backpack/inventory.  v82/v83 wrongly displaced the previous
        prop at owner/location 0x0C, creating the Bag1/Bag2 ping-pong loop.
      * Manual Equip can arrive as target=<BagGID>, location=0x0C.  For a
        normal equippable item, resolve that generic Bag location to the
        item's canonical equipment slot from DefaultItemLibrary data.  This
        is why an item could say '[Bag 1]' + 'Unequip' yet leave the left
        primary slot blank: OwnerGID was correct but Location stayed 0x0C.
    """
    eff = dict(op)
    gid = int(op["subject_gid"])

    if op["operation"] == PROP_OP_DROP:
        if gid in (LOCAL_ROLE_GID, LOCAL_BAG1_GID, LOCAL_BAG2_GID):
            return "drop ignored: structural starter prop", eff
        before = len(inventory)
        inventory[:] = [p for p in inventory if int(p.get("gid", 0)) != gid]
        return f"drop removed={before-len(inventory)}", eff

    subject = next((p for p in inventory if p["gid"] == gid), None)
    if subject is None:
        return "subject GID not in local inventory (response still ACKed)", eff

    if op["operation"] == PROP_OP_EQUIP:
        requested_owner = int(op["target_gid"])
        requested_location = int(op["location"])
        subject_item_id = int(subject.get("item_id", 0))
        subject_is_bag_entitlement = subject_item_id in (
            LOCAL_BAG1_ITEM_ID, LOCAL_BAG2_ITEM_ID
        )

        bag_owner_gids = {
            int(p["gid"])
            for p in inventory
            if int(p.get("item_id", 0)) in (LOCAL_BAG1_ITEM_ID, LOCAL_BAG2_ITEM_ID)
        }

        # Backpack entitlement props themselves are attached by the client to
        # target=1, loc=Bag.  Preserve that target.  They are NOT mutually
        # exclusive; Bag1 and Bag2 must coexist.
        if subject_is_bag_entitlement:
            owner_gid = requested_owner
            owner_source = "bag-entitlement"
        elif requested_owner in bag_owner_gids:
            owner_gid = requested_owner
            owner_source = "client-bag"
        elif requested_owner in (0, int(current_role_gid)) and LOCAL_BAG1_GID in bag_owner_gids:
            owner_gid = int(LOCAL_BAG1_GID)
            owner_source = "fallback-bag1"
        else:
            owner_gid = requested_owner or int(LOCAL_BAG1_GID)
            owner_source = "client/last-resort"

        location = requested_location
        slot_source = "client"

        # A manual Equip button can supply generic Location=Bag even though
        # TargetGID already identifies the backpack.  Resolve the actual slot
        # from the client resource table (Primary=0, Secondary=1, Melee=2,...).
        if (not subject_is_bag_entitlement and
                owner_gid in bag_owner_gids and
                requested_location == PROP_LOC_BAG):
            canonical = REAL_ITEM_DEFAULT_LOCATIONS.get(subject_item_id)
            if canonical is not None and 0 <= int(canonical) < PROP_LOC_BAG:
                location = int(canonical)
                eff["location"] = location
                slot_source = f"item-default:{location}"

        eff["target_gid"] = owner_gid

        displaced = []
        # Equipment sockets are exclusive. The generic Bag inventory is not.
        if location != PROP_LOC_BAG:
            for p in inventory:
                if p is subject:
                    continue
                if (int(p.get("owner_gid", 0)) == owner_gid and
                        int(p.get("location", PROP_LOC_BAG)) == location):
                    p["owner_gid"] = 0
                    p["location"] = PROP_LOC_BAG
                    displaced.append(int(p["gid"]))

        subject["owner_gid"] = owner_gid
        subject["location"] = location
        extra = "" if not displaced else " displaced=" + ",".join(
            f"0x{x:016x}" for x in displaced
        )
        return (
            f"equip owner=0x{owner_gid:016x} ({owner_source}) "
            f"req_loc=0x{requested_location:02x} stored_loc=0x{location:02x} "
            f"slot={slot_source}{extra}"
        ), eff

    if op["operation"] == PROP_OP_TAKEOFF:
        subject["owner_gid"] = 0
        subject["location"] = PROP_LOC_BAG
        return "takeoff -> bag", eff

    return f"unknown operation={op['operation']}", eff


# ---------------------------------------------------------------------------
# v87 persistent single-player shop/profile state
# ---------------------------------------------------------------------------
PLAYER_STATE_PATH = Path(__file__).with_name("assaultfire_player_state.json")
_PLAYER_STATE_LOCK = threading.RLock()
_PLAYER_STATE_VERSION = 2
_PLAYER_STATE_SESSION_COUNTER = 0
_PLAYER_STATE_ACTIVE_SESSION = 0
_PLAYER_STATE_THREAD = threading.local()


def _v87_default_inventory():
    role_prop = _v75_make_prop(
        LOCAL_ROLE_GID, LOCAL_ROLE_ITEM_ID, owner_gid=0,
        location=PROP_LOC_ROLE1, avail_hours=LOCAL_ROLE_AVAIL_HOURS,
        gain_type=0,
    )
    bag1_prop = _v75_make_prop(
        LOCAL_BAG1_GID, LOCAL_BAG1_ITEM_ID, owner_gid=0,
        location=PROP_LOC_BAG, avail_hours=LOCAL_BAG_AVAIL_HOURS,
        durability=0, durability_max=0, gain_type=0,
    )
    bag2_prop = _v75_make_prop(
        LOCAL_BAG2_GID, LOCAL_BAG2_ITEM_ID, owner_gid=0,
        location=PROP_LOC_BAG, avail_hours=LOCAL_BAG_AVAIL_HOURS,
        durability=0, durability_max=0, gain_type=0,
    )
    return [role_prop, bag1_prop, bag2_prop]


def _v87_default_state():
    return {
        "version": _PLAYER_STATE_VERSION,
        "uin": LOCAL_UIN,
        "nickname": "LocalPlayer",
        "wallet": {
            "ap": LOCAL_TP_BALANCE,
            "gp": LOCAL_GP_BALANCE,
            "mp": LOCAL_MP_BALANCE,
        },
        "current_role_gid": LOCAL_ROLE_GID,
        "next_prop_gid": ((LOCAL_UIN & 0xffffffff) << 32) | 4,
        "inventory": _v87_default_inventory(),
    }


def _v89_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return int(default)


def _v89_u64(value, default=0):
    return _v89_int(value, default) & 0xffffffffffffffff

def _v89_u32(value, default=0):
    return _v89_int(value, default) & 0xffffffff

def _v89_u8(value, default=0):
    return _v89_int(value, default) & 0xff

def _v89_wallet(value, default=0):
    # A00B wallet fields serialize as signed i32.  Keep JSON edits from making
    # login fail inside struct.pack and do not allow negative balances.
    return max(0, min(0x7fffffff, _v89_int(value, default)))


def _v87_normalize_prop(p):
    defaults = _v75_make_prop(0, 0)
    p = p if isinstance(p, dict) else {}
    return {
        "uin": _v89_u64(p.get("uin"), defaults["uin"]),
        "gid": _v89_u64(p.get("gid"), defaults["gid"]),
        "item_id": _v89_u32(p.get("item_id"), defaults["item_id"]),
        "res_flag": _v89_u64(p.get("res_flag"), defaults["res_flag"]),
        "stack_num": _v89_u32(p.get("stack_num"), defaults["stack_num"]),
        "obtain_time": _v89_u64(p.get("obtain_time"), defaults["obtain_time"]),
        "validity": _v89_u32(p.get("validity"), defaults["validity"]),
        "durability": _v89_u32(p.get("durability"), defaults["durability"]),
        "durability_max": _v89_u32(p.get("durability_max"), defaults["durability_max"]),
        "owner_gid": _v89_u64(p.get("owner_gid"), defaults["owner_gid"]),
        "location": _v89_u8(p.get("location"), defaults["location"]),
        "avail_hours": _v89_u32(p.get("avail_hours"), defaults["avail_hours"]),
        "use_hour": _v89_u32(p.get("use_hour"), defaults["use_hour"]),
        "gain_type": _v89_u8(p.get("gain_type"), defaults["gain_type"]),
    }


def _v89_begin_state_session():
    global _PLAYER_STATE_SESSION_COUNTER, _PLAYER_STATE_ACTIVE_SESSION
    with _PLAYER_STATE_LOCK:
        _PLAYER_STATE_SESSION_COUNTER += 1
        _PLAYER_STATE_ACTIVE_SESSION = _PLAYER_STATE_SESSION_COUNTER
        sid = _PLAYER_STATE_ACTIVE_SESSION
    _PLAYER_STATE_THREAD.session_id = sid
    log("STATE", f"begin ZONE state session={sid}")
    return sid


def _v89_bind_state_session(session_id):
    _PLAYER_STATE_THREAD.session_id = session_id


def _v87_pick_current_role_gid(inventory, preferred=0):
    by_gid = {int(p.get("gid", 0)): p for p in inventory}
    preferred = int(preferred or 0)
    if preferred in by_gid:
        p = by_gid[preferred]
        item_id = int(p.get("item_id", 0))
        if int(p.get("location", PROP_LOC_BAG)) in (PROP_LOC_ROLE1, PROP_LOC_ROLE2) or                 REAL_ITEM_DEFAULT_LOCATIONS.get(item_id) in (PROP_LOC_ROLE1, PROP_LOC_ROLE2):
            return preferred
    candidates = []
    for p in inventory:
        item_id = int(p.get("item_id", 0))
        loc = int(p.get("location", PROP_LOC_BAG))
        canonical = REAL_ITEM_DEFAULT_LOCATIONS.get(item_id)
        if loc in (PROP_LOC_ROLE1, PROP_LOC_ROLE2) or canonical in (PROP_LOC_ROLE1, PROP_LOC_ROLE2):
            candidates.append(p)
    candidates.sort(key=lambda p: (
        0 if int(p.get("location", PROP_LOC_BAG)) == PROP_LOC_ROLE1 else 1,
        int(p.get("gid", 0)),
    ))
    if candidates:
        return int(candidates[0].get("gid", LOCAL_ROLE_GID))
    return LOCAL_ROLE_GID


def _v87_normalize_state(raw):
    base = _v87_default_state()
    if not isinstance(raw, dict):
        return base
    wallet = raw.get("wallet") if isinstance(raw.get("wallet"), dict) else {}
    inv_raw = raw.get("inventory") if isinstance(raw.get("inventory"), list) else []

    # De-duplicate by GID and discard zero-GID rows.  A duplicate GID makes
    # equip/takeoff ambiguous and used to survive forever in the JSON save.
    by_gid = {}
    order = []
    for row in inv_raw:
        if not isinstance(row, dict):
            continue
        p = _v87_normalize_prop(row)
        gid = int(p.get("gid", 0))
        if gid == 0:
            continue
        if gid not in by_gid:
            order.append(gid)
        by_gid[gid] = p

    # Reserved starter GIDs are structural.  If a hand-edited/corrupt save
    # reused one for another item, restore the authoritative starter row.
    for starter in _v87_default_inventory():
        starter = _v87_normalize_prop(starter)
        gid = int(starter["gid"])
        if gid not in by_gid:
            order.append(gid)
        if gid not in by_gid or int(by_gid[gid].get("item_id", 0)) != int(starter["item_id"]):
            by_gid[gid] = starter

    inventory = [by_gid[gid] for gid in order if gid in by_gid]
    used = {int(p["gid"]) for p in inventory}
    max_gid = max(used, default=LOCAL_BAG2_GID)
    next_gid = _v89_u64(raw.get("next_prop_gid", max_gid + 1), max_gid + 1)
    if next_gid == 0 or next_gid in used or next_gid <= max_gid:
        next_gid = (max_gid + 1) & 0xffffffffffffffff
    next_gid = _v89_next_free_gid(next_gid, used)

    current_role = _v87_pick_current_role_gid(
        inventory, _v89_u64(raw.get("current_role_gid", LOCAL_ROLE_GID), LOCAL_ROLE_GID)
    )
    return {
        "version": _PLAYER_STATE_VERSION,
        "uin": LOCAL_UIN,
        "nickname": str(raw.get("nickname") or "LocalPlayer")[:31],
        "wallet": {
            "ap": _v89_wallet(wallet.get("ap", LOCAL_TP_BALANCE), LOCAL_TP_BALANCE),
            "gp": _v89_wallet(wallet.get("gp", LOCAL_GP_BALANCE), LOCAL_GP_BALANCE),
            "mp": _v89_wallet(wallet.get("mp", LOCAL_MP_BALANCE), LOCAL_MP_BALANCE),
        },
        "current_role_gid": current_role,
        "next_prop_gid": next_gid,
        "inventory": inventory,
    }


def _v87_load_state():
    with _PLAYER_STATE_LOCK:
        if not PLAYER_STATE_PATH.exists():
            return _v87_default_state(), "new-default"
        try:
            raw = json.loads(PLAYER_STATE_PATH.read_text(encoding="utf-8"))
            return _v87_normalize_state(raw), "disk"
        except Exception as e:
            bad = PLAYER_STATE_PATH.with_suffix(
                PLAYER_STATE_PATH.suffix + f".corrupt-{int(time.time())}"
            )
            try:
                os.replace(str(PLAYER_STATE_PATH), str(bad))
            except Exception:
                pass
            return _v87_default_state(), f"corrupt-reset:{type(e).__name__}:{e}"


def _v87_build_state(nickname, ap_balance, gp_balance, mp_balance,
                     current_role_gid, next_prop_gid, inventory):
    return _v87_normalize_state({
        "version": _PLAYER_STATE_VERSION,
        "uin": LOCAL_UIN,
        "nickname": nickname,
        "wallet": {
            "ap": int(ap_balance), "gp": int(gp_balance), "mp": int(mp_balance),
        },
        "current_role_gid": int(current_role_gid),
        "next_prop_gid": int(next_prop_gid),
        "inventory": [dict(p) for p in inventory],
    })


def _v87_save_state(state, reason="update", session_id=None):
    state = _v87_normalize_state(state)
    if session_id is None:
        session_id = getattr(_PLAYER_STATE_THREAD, "session_id", None)
    tmp = PLAYER_STATE_PATH.with_suffix(PLAYER_STATE_PATH.suffix + ".tmp")
    data = json.dumps(state, indent=2, sort_keys=True) + "\n"
    with _PLAYER_STATE_LOCK:
        if (session_id is not None and
                int(session_id) != int(_PLAYER_STATE_ACTIVE_SESSION)):
            log(
                "STATE",
                f"skip stale save session={session_id} active={_PLAYER_STATE_ACTIVE_SESSION} "
                f"reason={reason}",
            )
            return state
        tmp.write_text(data, encoding="utf-8")
        os.replace(str(tmp), str(PLAYER_STATE_PATH))
    w = state["wallet"]
    log(
        "STATE",
        f"saved reason={reason} session={session_id} "
        f"AP={w['ap']} GP={w['gp']} MP={w['mp']} "
        f"inventory={len(state['inventory'])} role=0x{state['current_role_gid']:016x} "
        f"next_gid=0x{state['next_prop_gid']:016x}"
    )
    return state


def _v48_build_zonehints(seq):
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_ZONE_HINTS, _v48_u16(0)
    )


def _v48_build_heartbeat_response(seq):
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_HEARTBEAT, _v48_u8(0)
    )


def _v48_build_createaccount_response(seq):
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_CREATEACCOUNT,
        _v48_u16(ZONE_ERR_SUCC)
    )


def _v73_parse_main_channel_list_request(body):
    """C2ZN_ReqMainChnlList (0xA355): one big-endian u32 Padding."""
    if len(body) != 4:
        raise ValueError(
            f"MainChnlList request must be exactly 4B, got {len(body)}B"
        )
    return struct.unpack(">I", body)[0]


def _v74_build_main_channel_list_response():
    """Build one-row ZN2C_ResMainChnlList (0xA356).

    v74 corrects two wire details using the already runtime-verified v70+
    TGame behavior:

      * TDR strings on this live decoder path are encoded as
          u32_be(strlen+1) || NUL-terminated bytes
        (same form that made A005 NickName decode correctly).

      * TDR IP values that TGame later copies directly into sockaddr memory
        must be serialized numerically as 0x0100007F so the decoded little-
        endian host dword contains bytes 7F 00 00 01 == 127.0.0.1.

    Schema from proto_c2zn.tdr:
      u16 Result
      i16 MainChnlCount
      MainChnlInfo MainChnlArray[MainChnlCount]

    MainChnlInfo:
      u16 MainChnlId
      u16 MainChnlType
      string MainChnlName[32]
      u32 PlayerCapacity
      u32 PlayerNum
      ip DsaIPs[3]
    """
    main_info = (
        _v48_u16(1)
        + _v48_u16(1)  # MainChnl_Rookie; matches our level-1 local profile
        + _v50_geo_tdr_string("Local Channel", 32)
        + _v48_u32(100)
        + _v48_u32(1)
        + _v48_u32(0x0100007F)
        + _v48_u32(0x0100007F)
        + _v48_u32(0x0100007F)
    )

    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_i16(1)
        + main_info
    )

    # 2 Result + 2 count + 2 id + 2 type +
    # 4-byte string length + 14-byte "Local Channel\0" +
    # 4 capacity + 4 online + 12 bytes DsaIPs = 46 bytes.
    if len(body) != 46:
        raise AssertionError(
            f"unexpected ZN2C_ResMainChnlList body len={len(body)}"
        )

    return _v62_build_server_app(
        TGAME_ZN_MAGIC,
        TGAME_ZN_RES_MAINCHNLLIST,
        body,
    )


def _v91_parse_zone_channel_list_request(body):
    """C2ZN_ReqZoneChannelList (0xA132): u32 MainChannelId."""
    if len(body) != 4:
        raise ValueError(
            f"ZoneChannelList request must be exactly 4B, got {len(body)}B"
        )
    return struct.unpack(">I", body)[0]


def _v91_build_zone_channel_list_response(main_channel_id=1):
    """One local subchannel so TGame can advance from Channels to lobby list.

    Wire schema recovered from proto_c2zn.tdr and runtime-verified in the
    earlier channel branch:
      ZoneChannelListInfo: u8 IsLastPkg, i16 ZoneCount, ZoneChannelInfo[]
      ZoneChannelInfo: u32 MainChannelId, ip Ipv4, string Domain, u16 Port,
                       i32 ChannelCount, ChannelInfo[], i32 FalseChnlCount
      ChannelInfo: u32 Id, string Name, u32 Capacity, u32 PlayerNum,
                   u32 PM, u32 CM, u32 NM, u32 RA
    """
    channel = (
        _v48_u32(1)
        + _v50_geo_tdr_string("Local Subchannel", 32)
        + _v48_u32(100)
        + _v48_u32(1)
        + _v48_u32(0)
        + _v48_u32(0)
        + _v48_u32(1)
        + _v48_u32(0)
    )
    zone = (
        _v48_u32(main_channel_id)
        + _v48_u32(0x0100007F)  # decoded host dword -> 127.0.0.1 bytes
        + _v50_geo_tdr_string("127.0.0.1", 128)
        + _v48_u16(TGAME_ZONE_PORT)
        + _v48_i32(1)
        + channel
        + _v48_i32(0)
    )
    body = _v48_u8(1) + _v48_i16(1) + zone
    if len(body) != 84:
        raise AssertionError(f"unexpected A133 body len={len(body)}")
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_ZONECHANNEL_LIST, body
    )


# ---------------------------------------------------------------------------
# v92-social: friends + direct friend chat
# ---------------------------------------------------------------------------

def _v92_parse_friend_status_request(body):
    """C2ZN_ReqFriendsStatus (A303).

    Native PH TGame builds this as:
      u16 Count | u16 Type | u64 FriendUinLst[Count]
    The live empty-list request seen in this project is exactly 00 00 00 01.
    """
    if len(body) < 4:
        raise ValueError(f"FriendsStatus request too short: {len(body)}B")
    count, query_type = struct.unpack_from(">HH", body, 0)
    expected = 4 + count * 8
    if count > 256 or len(body) != expected:
        raise ValueError(
            f"FriendsStatus malformed count={count} expected={expected} got={len(body)}"
        )
    uins = [struct.unpack_from(">Q", body, 4 + i * 8)[0] for i in range(count)]
    return {"count": count, "type": query_type, "uins": uins}


def _v92_pack_player_address(main_channel_id=1, zone_id=1,
                             sub_channel_id=1, room_id=0,
                             display_id=0, mode_id=0, map_id=0):
    """PlayerAddress used inside FriendStatus.

    Field order comes from proto_c2zn.tdr:
      MainChannelId, Zone.Id, SubChannelId, RoomId, DisplayId, ModeId, MapId.
    Widths follow the same PH wire types already proven by login/channel/room
    traffic: channel identifiers are u32, RoomId is u64, DisplayId is u16,
    ModeId u32 and MapId u16.
    """
    return (
        _v48_u32(main_channel_id)
        + _v48_u32(zone_id)
        + _v48_u32(sub_channel_id)
        + _v48_u64(room_id)
        + _v48_u16(display_id)
        + _v48_u32(mode_id)
        + _v48_u16(map_id)
    )


def _v92_pack_friend_status(uin=LOCAL_FRIEND_UIN, online=True):
    # FriendStatus fields in proto_c2zn.tdr: FriendUin | Address | Status.
    # FriendStatusTypeEnum is ordered EFST_Login, EFST_Logout, so online=0.
    return (
        _v48_u64(uin)
        + _v92_pack_player_address()
        + _v48_u16(0 if online else 1)
    )


def _v92_build_friend_status_response(query_type, requested_uins, friend_enabled):
    """ZN2C_ResFriendStatus (A304)."""
    requested_uins = list(requested_uins or [])
    include = bool(friend_enabled) and (
        not requested_uins or LOCAL_FRIEND_UIN in requested_uins
    )
    rows = [_v92_pack_friend_status()] if include else []
    body = _v48_u16(len(rows)) + _v48_u16(query_type) + b"".join(rows)
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_FRIEND_STATUS, body
    )


def _v92_build_friend_invite(request_id=1, msg_id=1):
    """Build ZN2C_ReqAddFriend (A306) from the compiled TDR field order.

    A306 fields:
      u32 RequestId | u64 ProposerUin | string ProposerNickname |
      string Remark | datetime Time | u64 MsgId

    Sending it after FF05 gives the local client a real native friend-request
    path instead of fabricating UI state in memory.
    """
    body = (
        _v48_u32(request_id)
        + _v48_u64(LOCAL_FRIEND_UIN)
        + _v50_geo_tdr_string(LOCAL_FRIEND_NICKNAME, 32)
        + _v50_geo_tdr_string(LOCAL_FRIEND_REMARK, 256)
        + _v48_dt_zero()
        + _v48_u64(msg_id)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_ADD_FRIEND_REQUEST, body
    )


def _v92_parse_add_friend_request(body):
    """C2ZN_ReqAddFriend (A305).

    TDR field order is RespondentUin | RespondentNickname | Remark.
    """
    if len(body) < 8:
        raise ValueError(f"A305 too short: {len(body)}B")
    respondent_uin = struct.unpack_from(">Q", body, 0)[0]
    off = 8
    respondent_name, _name_raw, off = _v91_read_lp_string(body, off, 32)
    remark, _remark_raw, off = _v91_read_lp_string(body, off, 256)
    return {
        "respondent_uin": respondent_uin,
        "respondent_name": respondent_name,
        "remark": remark,
        "tail": body[off:],
    }


def _v92_parse_del_friend_request(body):
    """C2ZN_ReqDelFriend (A309): one u64 FriendUin."""
    if len(body) != 8:
        raise ValueError(f"A309 must be exactly 8B, got {len(body)}B")
    return struct.unpack(">Q", body)[0]


def _v92_build_del_friend_response(friend_uin, result=SNS_ERR_SUCC):
    """ZN2C_ResDelFriend (A30A): DelFriendUin | Result."""
    body = _v48_u64(friend_uin) + _v48_u16(result)
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_DEL_FRIEND, body
    )


def _v92_parse_add_friend_client_response(body):
    """Best-effort decoder for C2ZN_ResAddFriend (A307).

    PH native construction proves RequestId is u32 and Result is u16 before
    the proposer identity.  The nickname uses normal ZN length-prefixed TDR
    string encoding.
    """
    if len(body) < 14:
        raise ValueError(f"A307 too short: {len(body)}B")
    request_id = struct.unpack_from(">I", body, 0)[0]
    result = struct.unpack_from(">H", body, 4)[0]
    proposer_uin = struct.unpack_from(">Q", body, 6)[0]
    off = 14
    proposer_name = ""
    if off < len(body):
        try:
            proposer_name, _proposer_raw, off = _v91_read_lp_string(body, off, 32)
        except Exception:
            proposer_name = ""
    return {
        "request_id": request_id,
        "result": result,
        "proposer_uin": proposer_uin,
        "proposer_name": proposer_name,
        "tail": body[off:],
    }


def _v92_build_add_friend_server_response(result=SNS_ERR_SUCC, msg_id=1,
                                           friend_uin=LOCAL_FRIEND_UIN,
                                           friend_name=LOCAL_FRIEND_NICKNAME):
    """ZN2C_ResAddFriend (A308), acknowledging the accepted friend."""
    body = (
        _v48_u16(result)
        + _v48_u64(friend_uin)
        + _v50_geo_tdr_string(friend_name, 32)
        + _v48_dt_zero()
        + _v48_u64(msg_id)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_ADD_FRIEND_S2C, body
    )


def _v92_parse_chat_p2p_request(body):
    """Decode the plain-text part of C2ZN_ReqChatP2P (A405).

    The PH native builder at 0x014C6D60 proves the leading wire fields are
    ChatType, RecipientUin, RecipientNickname and ChatMsgBuf, followed by the
    one-byte ChatPkg count.  Rich ChatPkg payloads are retained as an opaque
    tail; the local echo bot only needs the ordinary text fields.
    """
    if len(body) < 10:
        raise ValueError(f"A405 too short: {len(body)}B")
    chat_type = struct.unpack_from(">H", body, 0)[0]
    recipient_uin = struct.unpack_from(">Q", body, 2)[0]
    off = 10
    recipient_name, _recipient_raw, off = _v91_read_lp_string(body, off, 32)
    message, _message_raw, off = _v91_read_lp_string(body, off, 128)
    pkg_count = body[off] if off < len(body) else 0
    if off < len(body):
        off += 1
    return {
        "chat_type": chat_type,
        "recipient_uin": recipient_uin,
        "recipient_name": recipient_name,
        "message": message,
        "pkg_count": pkg_count,
        "tail": body[off:],
    }


def _v92_build_chat_p2p_notify(chat_type, message,
                               sender_uin=LOCAL_FRIEND_UIN,
                               sender_name=LOCAL_FRIEND_NICKNAME):
    """ZN2C_NtfChatP2P (A406), plain-text/no-rich-pkg form.

    TDR fields are:
      ZN2CP2PType | RequisitionerUin | RequisitionerNickname |
      ChatMsgBuf | ChatMsgLen | PkgCount | ChatPkg[] | ReqInMatch.
    """
    msg_bytes = message.encode("ascii", errors="replace")[:126]
    clean = msg_bytes.decode("ascii", errors="replace")
    body = (
        _v48_u16(chat_type)
        + _v48_u64(sender_uin)
        + _v50_geo_tdr_string(sender_name, 32)
        + _v50_geo_tdr_string(clean, 128)
        + _v48_u16(len(msg_bytes))
        + _v48_u8(0)   # PkgCount: ordinary text has no rich ChatPkg records
        + _v48_u8(0)   # ReqInMatch
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_CHAT_P2P, body
    )


def _v92_friend_bot_reply(text):
    text = (text or "").strip()
    if not text:
        return "Hello from LocalFriend."
    if len(text) > 90:
        text = text[:90]
    return "LocalFriend: " + text


# ---------------------------------------------------------------------------
# v94-clan: safe/simple clan request/response core
# ---------------------------------------------------------------------------

def _v94_parse_create_clan_request(body):
    """C2ZN_ReqCreateClan (A601): u64 Uin | ClanName | SafeCode | CertifiedMail."""
    if len(body) < 8:
        raise ValueError(f"A601 too short: {len(body)}B")
    off = 0
    uin = struct.unpack_from(">Q", body, off)[0]; off += 8
    clan_name, _raw_name, off = _v91_read_lp_string(body, off, MAX_CLAN_NAME_LEN)
    safe_code, _raw_safe, off = _v91_read_lp_string(body, off, MAX_CLAN_SAFECODE_LEN)
    certified_mail, _raw_mail, off = _v91_read_lp_string(body, off, 256)
    if off != len(body):
        raise ValueError(
            f"A601 trailing bytes: parsed={off} total={len(body)} tail={body[off:].hex()}"
        )
    return {
        "uin": uin,
        "clan_name": clan_name,
        "safe_code": safe_code,
        "certified_mail": certified_mail,
    }

def _v93_validate_clan_name(name):
    """Conservative local validation without inventing Tencent policy."""
    name = (name or "").strip()
    raw = name.encode("ascii", errors="replace")
    # MAX_CLAN_NAME_LEN includes the terminal NUL on the TDR wire.
    if not raw or len(raw) + 1 > MAX_CLAN_NAME_LEN:
        return False, name
    return True, name


def _v93_build_create_clan_response(clan_name, result=CLAN_ERR_SUCC):
    """ZN2C_ResCreateClan (A602): Result | ClanName."""
    body = (
        _v48_u16(result)
        + _v50_geo_tdr_string(clan_name, MAX_CLAN_NAME_LEN)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_CREATE_CLAN, body
    )


def _v94_parse_verify_clan_name_request(body):
    """C2ZN_ReqVerifyClanName (AB02): u64 Uin | ClanName."""
    if len(body) < 8:
        raise ValueError(f"AB02 too short: {len(body)}B")
    uin = struct.unpack_from(">Q", body, 0)[0]
    name, _raw, off = _v91_read_lp_string(body, 8, MAX_CLAN_NAME_LEN)
    if off != len(body):
        raise ValueError(f"AB02 trailing bytes: parsed={off} total={len(body)}")
    return uin, name

def _v93_build_verify_clan_name_response(clan_name, result=CLAN_ERR_SUCC):
    """ZN2C_ResVerifyClanName (AB03): Result | ClanName."""
    body = (
        _v48_u16(result)
        + _v50_geo_tdr_string(clan_name, MAX_CLAN_NAME_LEN)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_VERIFY_CLAN_NAME, body
    )


def _v94_parse_clan_detail_request(body):
    """C2ZN_ReqClanDetail (AA05): u64 Uin."""
    if len(body) != 8:
        raise ValueError(f"AA05 request must be 8B, got {len(body)}B")
    return struct.unpack(">Q", body)[0]


def _v94_parse_clan_members_request(body):
    """C2ZN_ReqClanMembers (AA07): u64 Uin | IsAll.

    The compiled schema exposes Uin first.  PH normally uses a one-byte bool
    for IsAll; accept 1/2/4-byte scalar variants for trace compatibility.
    """
    if len(body) < 9:
        raise ValueError(f"AA07 too short: {len(body)}B")
    uin = struct.unpack_from(">Q", body, 0)[0]
    tail = body[8:]
    if len(tail) == 1:
        is_all = tail[0]
    elif len(tail) == 2:
        is_all = struct.unpack(">H", tail)[0]
    elif len(tail) == 4:
        is_all = struct.unpack(">I", tail)[0]
    else:
        raise ValueError(f"AA07 IsAll width unexpected: {len(tail)}B")
    return uin, is_all


def _v94_parse_clan_common_request(body):
    """C2ZN_ReqClanCommon (AA09): u64 Uin | u64 ClanID."""
    if len(body) != 16:
        raise ValueError(f"AA09 request must be 16B, got {len(body)}B")
    return struct.unpack(">QQ", body)


def _v94_clan_probe_log(label, cmd, body, role_state):
    clan = role_state.get("v94_clan") or role_state.get("v93_clan") or {}
    log(
        label,
        "v94 CLAN nested packet recognized/deferred: "
        f"cmd=0x{cmd:04x} body_len={len(body)} body={body.hex()} "
        f"local_clan_id=0x{int(clan.get('clan_id', 0)):016x} "
        f"local_clan_name={clan.get('clan_name', '')!r}; "
        "membership/request shape is implemented; nested AA06/AA08/AA0A serializer awaits live PH validation"
    )

def _v91_parse_match_room_list_request(body):
    """Decode C2ZN_ReqMatchRoomList (0xA100), exactly 13 bytes.

      u32 ModeId | u16 MapId | u16 Flags | u8 AtLeastCount |
      u16 StartIndex | u16 RoomCount
    """
    if len(body) != 13:
        raise ValueError(
            f"MatchRoomList request must be exactly 13B, got {len(body)}B"
        )
    return {
        "mode_id": struct.unpack_from(">I", body, 0)[0],
        "map_id": struct.unpack_from(">H", body, 4)[0],
        "flags": struct.unpack_from(">H", body, 6)[0],
        "at_least_count": body[8],
        "start_index": struct.unpack_from(">H", body, 9)[0],
        "room_count": struct.unpack_from(">H", body, 11)[0],
    }


def _v91_build_match_settings_wire(
        mode_id=0x00002001,
        map_id=0x002F,
        map_string="",
        sub_mode_id=0x00001001,
        flags=0x00003008,
        setting_type=0,
        value=0,
        respawn_time=0,
        recode_type=0,
        live_delay_sec=0):
    """Serialize MatchSettings using a known-good live Survival capture.

    The defaults are not guesses: they came from the accepted PH client room
    creation captured on 2026-09-19:
      ModeId=0x2001 MapId=0x002F SubModeId=0x1001 Flags=0x3008.
    MapString was empty in that request.
    """
    return (
        _v48_u32(mode_id)
        + _v48_u16(map_id)
        + _v50_geo_tdr_string(map_string, 32)
        + _v48_u32(sub_mode_id)
        + _v48_u32(flags)
        + _v48_u16(setting_type)
        + _v48_u16(value)
        + _v48_u16(respawn_time)
        + _v48_u16(recode_type)
        + _v48_u16(live_delay_sec)
    )


def _v91_default_match_lobbies():
    """Synthetic room rows for the local/offline lobby browser.

    They intentionally share a runtime-proven Survival MatchSettings payload;
    only identity/count metadata changes.  No fake remote endpoint is exposed.
    """
    settings = _v91_build_match_settings_wire()
    return [
        {
            "room_id": 0x1001,
            "display_id": 1,
            "qqtalk_room_id": 0,
            "name": "Local Survival 1",
            "owner_name": "LocalHost",
            "match_settings_wire": settings,
            "mode_id": 0x00002001,
            "map_id": 0x002F,
            "fighter_capacity": 4,
            "observer_capacity": 0,
            "fighter_count": 1,
            "observer_count": 0,
        },
        {
            "room_id": 0x1002,
            "display_id": 2,
            "qqtalk_room_id": 0,
            "name": "Local Survival 2",
            "owner_name": "LocalHost",
            "match_settings_wire": settings,
            "mode_id": 0x00002001,
            "map_id": 0x002F,
            "fighter_capacity": 4,
            "observer_capacity": 0,
            "fighter_count": 2,
            "observer_count": 0,
        },
        {
            "room_id": 0x1003,
            "display_id": 3,
            "qqtalk_room_id": 0,
            "name": "Local Survival 3",
            "owner_name": "LocalHost",
            "match_settings_wire": settings,
            "mode_id": 0x00002001,
            "map_id": 0x002F,
            "fighter_capacity": 4,
            "observer_capacity": 0,
            "fighter_count": 3,
            "observer_count": 0,
        },
    ]


def _v91_pack_basic_match_room_info(room):
    """BasicMatchRoomInfo used by ZN2C_ResMatchRoomList (0xA102)."""
    return (
        _v48_u64(room["room_id"])
        + _v48_u16(room["display_id"])
        + _v48_u64(room.get("qqtalk_room_id", 0))
        + _v50_geo_tdr_string(room["name"], 64)
        + _v50_geo_tdr_string(room.get("owner_name", "LocalHost"), 32)
        + room["match_settings_wire"]
        + _v48_u8(room.get("fighter_capacity", 4))
        + _v48_u8(room.get("observer_capacity", 0))
        + _v48_u8(room.get("fighter_count", 1))
        + _v48_u8(room.get("observer_count", 0))
    )


def _v91_filter_match_lobbies(req, rooms):
    """Apply the two filters whose semantics are unambiguous, then paginate."""
    filtered = []
    for room in rooms:
        if req["mode_id"] not in (0, room.get("mode_id", 0)):
            continue
        if req["map_id"] not in (0, room.get("map_id", 0)):
            continue
        filtered.append(room)

    total = len(filtered)
    start = min(req["start_index"], total)
    want = req["room_count"] or 20
    want = min(want, 20)
    return total, filtered[start:start + want]


def _v91_build_match_room_list_response(total_room_num, rooms):
    """ZN2C_ResMatchRoomList (0xA102): Result/total/count/rows."""
    rows = list(rooms)
    if total_room_num < 0 or total_room_num > 0xFFFF:
        raise ValueError("TotalRoomNum out of range")
    if len(rows) > 0xFFFF:
        raise ValueError("RoomCount out of range")
    body = (
        _v48_u16(ZONE_ERR_SUCC)
        + _v48_u16(total_room_num)
        + _v48_u16(len(rows))
        + b"".join(_v91_pack_basic_match_room_info(r) for r in rows)
    )
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_MATCHROOMLIST, body
    )


def _v91_read_lp_string(body, off, max_wire_len=None):
    if off + 4 > len(body):
        raise ValueError("truncated length-prefixed string length")
    n = struct.unpack_from(">I", body, off)[0]
    off += 4
    if n < 1 or off + n > len(body):
        raise ValueError(
            f"invalid length-prefixed string n={n} off={off} body={len(body)}"
        )
    if max_wire_len is not None and n > max_wire_len:
        raise ValueError(f"string n={n} exceeds max {max_wire_len}")
    raw = body[off:off + n]
    off += n
    text_raw = raw[:-1] if raw.endswith(b"\x00") else raw
    return text_raw.decode("latin1", "replace"), raw, off


def _v91_parse_create_match_room_request(body):
    """Parse enough of A10A to add a client-created room to the lobby list."""
    off = 0
    name, _name_raw, off = _v91_read_lp_string(body, off, 64)
    ms_start = off
    if off + 6 > len(body):
        raise ValueError("truncated MatchSettings prefix")
    mode_id = struct.unpack_from(">I", body, off)[0]; off += 4
    map_id = struct.unpack_from(">H", body, off)[0]; off += 2
    map_string, _map_raw, off = _v91_read_lp_string(body, off, 32)
    if off + 18 > len(body):
        raise ValueError("truncated MatchSettings tail")
    sub_mode_id = struct.unpack_from(">I", body, off)[0]; off += 4
    flags = struct.unpack_from(">I", body, off)[0]; off += 4
    setting_type = struct.unpack_from(">H", body, off)[0]; off += 2
    value = struct.unpack_from(">H", body, off)[0]; off += 2
    respawn_time = struct.unpack_from(">H", body, off)[0]; off += 2
    recode_type = struct.unpack_from(">H", body, off)[0]; off += 2
    live_delay_sec = struct.unpack_from(">H", body, off)[0]; off += 2
    ms_end = off
    if off + 2 > len(body):
        raise ValueError("truncated room capacities")
    fighter_capacity = body[off]
    observer_capacity = body[off + 1]
    off += 2
    password, _pw_raw, off = _v91_read_lp_string(body, off, 8)
    return {
        "name": name,
        "mode_id": mode_id,
        "map_id": map_id,
        "map_string": map_string,
        "sub_mode_id": sub_mode_id,
        "flags": flags,
        "setting_type": setting_type,
        "value": value,
        "respawn_time": respawn_time,
        "recode_type": recode_type,
        "live_delay_sec": live_delay_sec,
        "match_settings_wire": body[ms_start:ms_end],
        "fighter_capacity": fighter_capacity,
        "observer_capacity": observer_capacity,
        "password": password,
        "game_server_info": body[off:],
    }


def _v91_build_create_match_room_response():
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_CREATEMATCHROOM, _v48_u16(ZONE_ERR_SUCC)
    )


def _v72_parse_start_room_alloc(body):
    """Decode the fixed part of C2ZN_ReqStartRoomAlloc seen on the wire.

    Live body length is 46 bytes for one requested map:
      u64 PlayerUin
      32B MatchSettings
      u8  PlayerHardLevel
      u8  MapCount
      u32 MapIds[MapCount]

    The 32-byte MatchSettings sub-structure is preserved raw for now.  The
    first 4 bytes are ModeId and bytes 4..5 track MapId in our captures.
    """
    if len(body) < 42:
        raise ValueError(f"StartRoomAlloc body too short: {len(body)}B")
    uin = struct.unpack_from(">Q", body, 0)[0]
    match = body[8:40]
    hard_level = body[40]
    map_count = body[41]
    need = 42 + 4 * map_count
    if len(body) < need:
        raise ValueError(
            f"StartRoomAlloc truncated: map_count={map_count} "
            f"need={need} got={len(body)}"
        )
    maps = [struct.unpack_from(">I", body, 42 + 4*i)[0] for i in range(map_count)]
    mode_id = struct.unpack_from(">I", match, 0)[0] if len(match) >= 4 else None
    match_map_id = struct.unpack_from(">H", match, 4)[0] if len(match) >= 6 else None
    return {
        "uin": uin,
        "match": match,
        "mode_id": mode_id,
        "match_map_id": match_map_id,
        "hard_level": hard_level,
        "map_count": map_count,
        "maps": maps,
        "consumed": need,
        "tail": body[need:],
    }


def _v72_build_enter_room_alloc_success():
    # ZN2C_NtfEnterRoomAlloc: diagnostic success Result only.
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_NTF_ENTERROOMALLOC,
        _v48_u16(ZONE_ERR_SUCC)
    )


def _v72_build_start_room_alloc_success():
    # ZN2C_ResStartRoomAlloc: diagnostic success Result only.
    return _v62_build_server_app(
        TGAME_ZN_MAGIC, TGAME_ZN_RES_STARTROOMALLOC,
        _v48_u16(ZONE_ERR_SUCC)
    )


def _v48_parse_createaccount(body):
    end = body.find(b"\x00")
    if end < 0:
        raise ValueError("CreateAccount nickname missing NUL")
    return body[:end].decode("latin1", "replace")


def _v57_next_server_seq(state):
    """Independent downstream frame sequence for one TGame connection."""
    seq = state.get("_v57_server_seq", 1)
    state["_v57_server_seq"] = (seq + 1) & 0xFFFFFFFF
    if state["_v57_server_seq"] == 0:
        state["_v57_server_seq"] = 1
    return seq


def _v48_send_app(conn, key, app_plain, label, desc):
    # app_plain is the exact plaintext carried by TPDU cmd00.
    # v62 downstream GEO/ZN responses begin directly with their TDR package
    # header (0x8202 or 0x3243); no client-style 4-byte app sequence prefix.
    pkt, enc = tgame_build_cmd00_mode3(app_plain, key)
    conn.sendall(pkt)
    log(
        label,
        f"TX {desc} v57-cmd00-server-seq "
        f"plain_len={len(app_plain)} plain={app_plain.hex()} "
        f"enc_len={len(enc)} wire={_short_hex(pkt, 160)}"
    )
    return pkt


def tgame_build_cmd01_chgskey(old_key, mode, new_key=b"LOCAL_GAME_KEY01"):
    """Build the post-SYN key-change packet expected after cmd09.

    ProtocalHandler's cmd01 parser decrypts the encrypted body under the
    current mode and copies exactly 16 plaintext bytes into the new key.
    """
    if len(new_key) != 16:
        raise ValueError("new TGame key must be exactly 16 bytes")
    if mode == 3:
        enc = tgame_mode3_encrypt(new_key, old_key)
    elif mode == 4:
        enc = tgame_mode4_encrypt(new_key, old_key)
    else:
        raise ValueError(f"unsupported key-change mode {mode}")
    if len(enc) > 0xFFFF:
        raise ValueError("encrypted key-change body too large")

    # Compact wire layout: generic 12-byte header, then cmd-specific encrypted
    # length. cmd01 uses a 16-bit encrypted-length field internally.
    total = 16 + len(enc)
    pkt = (
        b"\x55\x0e\x01\x00"
        + struct.pack(">I", total)
        + bytes(4)
        + b"\x00\x00"
        + struct.pack(">H", len(enc))
        + enc
    )
    # For a 16-byte new key under mode 3, ciphertext is 32 bytes and the
    # compact cmd01 frame is exactly 48 bytes:
    #   12-byte TPDUBase + 2 reserved + 2-byte enc_len + ciphertext.
    if len(pkt) != total:
        raise AssertionError(
            f"cmd01 frame length mismatch: total={total} actual={len(pkt)}"
        )
    return pkt, enc, new_key


def tgame_build_cmd08_syn_auto(key, mode, randstr=TGAME_SYN_RAND):
    if len(randstr) != 16:
        raise ValueError("TPDUSynInfo.randstr must be exactly 16 bytes")
    if mode == 3:
        enc = tgame_mode3_encrypt(randstr, key)
    elif mode == 4:
        enc = tgame_mode4_encrypt(randstr, key)
    else:
        raise ValueError(f"TGame encryption mode {mode} is not implemented in v30")
    if len(enc) > 0xFF:
        raise ValueError("encrypted SYN too large")
    total = 13 + len(enc)
    pkt = (
        b"\x55\x0e\x08\x00" +
        struct.pack(">I", total) +
        b"\x00\x00\x00\x00" +
        bytes([len(enc)]) +
        enc
    )
    return pkt, enc


def tgame_read_loginkey_from_shared_memory(pid):
    """Read LoginKey from TCLS_SHAREDMEMEMORY<PID> without modifying it.

    Verified shared-memory layout:
      DWORD at +0x14 -> offset of the LoginKey byte-array field.
      At that field: little-endian DWORD length, followed by the bytes.
    The observed length is 16.
    """
    if os.name != "nt" or pid is None:
        return None, "not-windows/no-pid"

    import ctypes
    from ctypes import wintypes

    FILE_MAP_READ = 0x0004
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    k32.OpenFileMappingW.argtypes = [
        wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR
    ]
    k32.OpenFileMappingW.restype = wintypes.HANDLE
    k32.MapViewOfFile.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_size_t
    ]
    k32.MapViewOfFile.restype = ctypes.c_void_p
    k32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    k32.UnmapViewOfFile.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    name = f"TCLS_SHAREDMEMEMORY{int(pid)}"
    h = k32.OpenFileMappingW(FILE_MAP_READ, False, name)
    if not h:
        return None, f"OpenFileMappingW({name}) failed err={ctypes.get_last_error()}"

    try:
        view = k32.MapViewOfFile(h, FILE_MAP_READ, 0, 0, 0)
        if not view:
            return None, f"MapViewOfFile failed err={ctypes.get_last_error()}"
        try:
            head = ctypes.string_at(view, 0x40)
            field_off = struct.unpack_from("<I", head, 0x14)[0]
            if field_off < 0x20 or field_off > 0x10000:
                return None, f"bad LoginKey field offset 0x{field_off:x}"

            field = ctypes.string_at(view + field_off, 4 + 64)
            n = struct.unpack_from("<I", field, 0)[0]
            if n != 16:
                return None, f"LoginKey length={n}, expected 16"

            key = bytes(field[4:20])
            return key, f"{name}+0x{field_off:x}"
        finally:
            k32.UnmapViewOfFile(view)
    finally:
        k32.CloseHandle(h)


def _aes_ecb_encrypt_block(block, key):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _aes_ecb_decrypt_block(block, key):
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(block) + dec.finalize()


def tgame_mode4_encrypt(plain, key):
    """Reimplementation of ProtocalHandler.dll mode-4 encrypt (0x1008BC40).

    Framing:
      random-high-nibble | padding-count
      padding-count random bytes
      2 random bytes
      payload
      7 zero trailer bytes

    Chaining:
      C[i] = AES(P[i] XOR C[i-1]) XOR P[i-1]
      C[-1] = P[-1] = 16 zero bytes
    """
    if len(key) != 16:
        raise ValueError("mode4 key must be 16 bytes")

    pad = (16 - ((len(plain) + 10) & 0x0F)) & 0x0F
    framed = bytearray()
    framed.append((os.urandom(1)[0] & 0xF0) | pad)
    if pad:
        framed += os.urandom(pad)
    framed += os.urandom(2)
    framed += plain
    framed += b"\x00" * 7

    if len(framed) & 0x0F:
        raise AssertionError("mode4 framed length is not block aligned")

    out = bytearray()
    prev_plain = bytes(16)
    prev_cipher = bytes(16)

    for off in range(0, len(framed), 16):
        p = bytes(framed[off:off + 16])
        x = bytes(a ^ b for a, b in zip(p, prev_cipher))
        y = _aes_ecb_encrypt_block(x, key)
        c = bytes(a ^ b for a, b in zip(y, prev_plain))
        out += c
        prev_plain = p
        prev_cipher = c

    return bytes(out)


def tgame_mode4_decrypt(ciphertext, key):
    """Inverse of ProtocalHandler.dll mode-4 framing; used to verify cmd09."""
    if len(key) != 16 or not ciphertext or (len(ciphertext) & 0x0F):
        return None, "bad mode4 input"

    framed = bytearray()
    prev_plain = bytes(16)
    prev_cipher = bytes(16)

    try:
        for off in range(0, len(ciphertext), 16):
            c = ciphertext[off:off + 16]
            y = bytes(a ^ b for a, b in zip(c, prev_plain))
            x = _aes_ecb_decrypt_block(y, key)
            p = bytes(a ^ b for a, b in zip(x, prev_cipher))
            framed += p
            prev_plain = p
            prev_cipher = c
    except Exception as e:
        return None, f"AES/dechain failed: {type(e).__name__}: {e}"

    pad = framed[0] & 0x0F
    start = 1 + pad + 2
    end = len(framed) - 7
    if start > end:
        return None, f"bad pad/start pad={pad} total={len(framed)}"
    if framed[end:] != b"\x00" * 7:
        return None, f"bad zero trailer framed={bytes(framed).hex()}"

    return bytes(framed[start:end]), "ok"



def _af_dword_to_le_bytes(hex_word):
    """x32dbg {x:[addr]} prints a DWORD value; convert to its 4 memory bytes."""
    value = int(hex_word, 16) & 0xFFFFFFFF
    return struct.pack("<I", value)


def _parse_af_crypto_records(raw):
    """Return [(position, key16, mode, description), ...] from AF11/AF8 logs."""
    out = []

    # AF11 records are preferred because they retain the connection handle and
    # print the key as four DWORDs. Reconstruct the original 16 memory bytes.
    af11_re = re.compile(
        r"\[AF11\]\s+SET\s+"
        r"caller=(?P<caller>[0-9A-Fa-f]+)\s+"
        r"conn=(?P<conn>[0-9A-Fa-f]+)\s+"
        r"keyptr=(?P<keyptr>[0-9A-Fa-f]+)\s+"
        r"k0=(?P<k0>[0-9A-Fa-f]+)\s+"
        r"k1=(?P<k1>[0-9A-Fa-f]+)\s+"
        r"k2=(?P<k2>[0-9A-Fa-f]+)\s+"
        r"k3=(?P<k3>[0-9A-Fa-f]+)\s+"
        r"mode=(?P<mode>\d+)"
    )
    for m in af11_re.finditer(raw):
        key = b"".join(
            _af_dword_to_le_bytes(m.group(name))
            for name in ("k0", "k1", "k2", "k3")
        )
        out.append((
            m.start(),
            key,
            int(m.group("mode")),
            f"AF11 conn={m.group('conn')} caller={m.group('caller')}",
        ))

    # Backward compatibility with the older AF8 logger.
    af8_re = re.compile(
        r"\[AF8\]\s+SetEncryptMethod\b.*?"
        r"conn=(?P<conn>[0-9A-Fa-f]+)\s+"
        r"keyptr=(?P<keyptr>[0-9A-Fa-f]+)\s+"
        r"key16=(?P<key>[0-9A-Fa-f]{32,})\s+"
        r"mode=(?P<mode>\d+)"
    )
    for m in af8_re.finditer(raw):
        out.append((
            m.start(),
            bytes.fromhex(m.group("key")[:32]),
            int(m.group("mode")),
            f"AF8 conn={m.group('conn')}",
        ))

    return out


def _candidate_x32dbg_logs(explicit=None):
    """Find likely x32dbg log files, newest first."""
    if explicit:
        return [Path(explicit)]

    env_path = os.environ.get("AF_X32DBG_LOG")
    if env_path:
        return [Path(env_path)]

    downloads = Path.home() / "Downloads"
    candidates = []
    if downloads.exists():
        seen = set()
        for pat in ("af*log*.txt", "*af*log*.txt"):
            for p in downloads.glob(pat):
                try:
                    rp = p.resolve()
                except Exception:
                    rp = p
                if rp in seen or not p.is_file():
                    continue
                seen.add(rp)
                candidates.append(p)

    # Preserve the old default as a final fallback.
    fallback = Path(os.environ.get("AF_X32DBG_LOG", str(Path.home() / "Downloads" / "af_x32dbg.log")))
    if fallback not in candidates:
        candidates.append(fallback)

    def _mtime(p):
        try:
            return p.stat().st_mtime
        except Exception:
            return -1.0

    candidates.sort(key=_mtime, reverse=True)
    return candidates


def tgame_read_x32dbg_live_crypto(log_path=None, expected_pid=None, wait_s=3.0, poll_s=0.05):
    """Read the freshest live AF11/AF8 SetEncryptMethod record.

    v40 intentionally does not hard-code one historical log filename. x32dbg
    log names can change between runs; using the old fixed path caused v39 to
    reuse a stale key from an earlier process.
    """
    deadline = time.time() + max(0.0, wait_s)
    last_err = "no AF11/AF8 crypto record found"

    while True:
        best = None  # (file_mtime, record_pos, key, mode, source)
        for p in _candidate_x32dbg_logs(log_path):
            try:
                raw = p.read_text(encoding="utf-8", errors="ignore")
                mtime = p.stat().st_mtime
            except Exception:
                continue

            # Bind a debugger log to the exact TGame process that owns this
            # ROLE socket. Reusing a fresh-looking log from another TGame PID
            # is still a wrong-key failure because the session key is per-process.
            log_pid = None
            m_pid = re.search(r"GetCurrentProcessId\s*=\s*(\d+)", raw)
            if m_pid:
                log_pid = int(m_pid.group(1))
            else:
                m_pid = re.search(r"\[P(\d+)\]", raw)
                if m_pid:
                    log_pid = int(m_pid.group(1))

            if expected_pid is not None and log_pid != int(expected_pid):
                continue

            records = _parse_af_crypto_records(raw)
            if not records:
                continue

            pos, key, mode, desc = records[-1]
            pid_desc = f" pid={log_pid}" if log_pid is not None else ""
            item = (mtime, pos, key, mode, f"{p}{pid_desc} {desc}")
            if best is None or item[:2] > best[:2]:
                best = item

        if best is not None:
            _, _, key, mode, source = best
            return key, mode, source

        if time.time() >= deadline:
            if expected_pid is not None:
                return None, None, (
                    f"no AF11/AF8 crypto record for current TGame PID={expected_pid}; "
                    "refusing to reuse another process's session key"
                )
            return None, None, last_err

        time.sleep(poll_s)

def tgame_parse_auth(data):
    """Parse the verified 0x55/0x0E TGame cmd03 AUTH wire shape."""
    if len(data) < 32 or data[0:3] != b"\x55\x0e\x03":
        return None

    total_len = struct.unpack(">I", data[4:8])[0]
    field0 = struct.unpack(">I", data[12:16])[0]
    field1 = struct.unpack(">I", data[16:20])[0]
    auth_type = struct.unpack(">I", data[20:24])[0]
    uin = struct.unpack(">I", data[24:28])[0]
    auth_len = struct.unpack(">I", data[28:32])[0]

    return {
        "total_len": total_len,
        "field0": field0,
        "field1": field1,
        "auth_type": auth_type,
        "uin": uin,
        "auth_len": auth_len,
        "ticket": data[32:32 + auth_len],
    }


def tgame_build_cmd08_syn(login_key, randstr=TGAME_SYN_RAND):
    """Build cmd08 exactly in the form consumed by ProtocalHandler+0x75C60."""
    if len(randstr) != 16:
        raise ValueError("TPDUSynInfo.randstr must be exactly 16 bytes")

    enc = tgame_mode4_encrypt(randstr, login_key)
    if len(enc) > 0xFF:
        raise ValueError("encrypted SYN too large")

    total = 13 + len(enc)
    pkt = bytearray()
    pkt += b"\x55\x0e\x08\x00"
    pkt += struct.pack(">I", total)
    pkt += b"\x00\x00\x00\x00"
    pkt += bytes([len(enc)])
    pkt += enc
    return bytes(pkt), enc


def tgame_decode_cmd09(data, login_key):
    lines = []
    if len(data) < 13:
        return [f"TGame follow-up too short: {len(data)}B"]

    total = struct.unpack(">I", data[4:8])[0]
    lines.append(
        f"TGame follow-up: magic={data[0]:02x} ver={data[1]:02x} "
        f"cmd={data[2]:02x} total={total} raw_len={len(data)}"
    )

    if data[0:2] != b"\x55\x0e" or data[2] != 0x09:
        return lines

    n = data[12]
    enc = data[13:13 + n]
    plain, status = tgame_mode4_decrypt(enc, login_key)
    lines.append(
        f"TGame SYNACK mode4={status} enc_len={n} "
        f"plain={plain.hex() if plain is not None else None} "
        f"matches={plain == TGAME_SYN_RAND if plain is not None else False}"
    )
    return lines

def handle_placeholder(conn, addr, label):
    """
    Temporary 65005 capture handler.

    It identifies the connecting process first, captures the first complete
    TCP burst, and keeps the socket alive long enough to observe follow-ups.
    """
    # Per-connection downstream sequence state. Reset for each accepted socket.
    state = {"_v57_server_seq": 1}
    try:
        server_port = conn.getsockname()[1]
        pid, process_name = identify_peer_process(addr, server_port)

        if pid is not None:
            log(
                label,
                f"Connected from {addr} OWNER="
                f"{process_name or '?'} PID={pid}"
            )
        else:
            log(
                label,
                f"Connected from {addr} OWNER=<unresolved>"
            )

        conn.settimeout(15.0)

        try:
            first = conn.recv(4096)
        except socket.timeout:
            first = b""

        if not first:
            log(label, "No data received")
            return

        packet = bytearray(first)

        # Collect fragments from the same initial burst.
        conn.settimeout(0.25)

        while len(packet) < 65536:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break

            if not chunk:
                break

            packet.extend(chunk)

        data = bytes(packet)

        owner = (
            f"{process_name or '?'} PID={pid}"
            if pid is not None
            else "unresolved"
        )

        log(
            label,
            f"FIRST RX COMPLETE ({len(data)}B) "
            f"OWNER={owner}: {_short_hex(data, 96)}"
        )

        if label.upper() in ("ROLE", "ZONE"):
            for line in decode_role_packet_for_log(data):
                log(label, line)

        if not QUIET_ROLE_HEX:
            print(
                f"\n[{label}] OWNER: {owner}\n"
                f"[{label}] COPY THIS HEX:\n"
                f"{data.hex(' ')}\n",
                flush=True,
            )

        if len(data) >= 4:
            log(
                label,
                f"First bytes: {data[:16].hex(' ')}"
            )

            # ProtocalHandler's final send path forces byte[3] = 0x04.
            if data[2] == 0x03 and data[3] == 0x04:
                log(
                    label,
                    "SIGNATURE: compatible with ProtocalHandler AUTH "
                    "(cmd=03, wire byte[3]=04)"
                )

            elif data[2] == 0x03:
                log(
                    label,
                    f"NOTE: cmd-like byte is 03 but byte[3]={data[3]:02X}; "
                    "this does NOT match ProtocalHandler's final AUTH send buffer"
                )

        role_state = {}
        tgame_mode4_key = None
        if label.upper() in ("ROLE", "ZONE"):
            tgame_auth = tgame_parse_auth(data) if (process_name or "").lower() == "tgame.exe" else None

            if tgame_auth is not None:
                ticket_disp = tgame_auth.get("ticket", b"").decode("ascii", "replace")
                log(
                    label,
                    "TGame AUTH decoded: "
                    f"total={tgame_auth.get('total_len')} "
                    f"field0={tgame_auth.get('field0')} "
                    f"field1={tgame_auth.get('field1')} "
                    f"auth_type={tgame_auth.get('auth_type')} "
                    f"uin={tgame_auth.get('uin')} "
                    f"auth_len={tgame_auth.get('auth_len')} "
                    f"ticket={ticket_disp!r}"
                )

                # v42: AuthType-4 does not carry the mode-3 session key on the
                # wire. The live ProtocalHandler object contains both our exact
                # AP ticket and the copied 16-byte key, at fixed offsets. Anchor
                # on the ticket from THIS cmd03 and recover the matching key/mode
                # directly from THIS TGame PID. No debugger log is required.
                with _TGAME_USED_AUTH_ANCHORS_LOCK:
                    _used_auth_anchors = set(
                        _TGAME_USED_AUTH_ANCHORS.get(int(pid), set())
                    )

                # The ZONE connection is a second live AuthAP object carrying
                # the same ticket. Give TGame a brief moment to finish linking
                # the new handler/connection object, then require a fresh
                # ticket anchor instead of reusing the GEO object's key.
                tgame_mode4_key = None
                tgame_crypto_mode = None
                crypto_src = None
                for _recover_try in range(10):
                    tgame_mode4_key, tgame_crypto_mode, crypto_src = (
                        tgame_recover_key_by_ticket(
                            pid=pid,
                            ticket=tgame_auth.get("ticket", b""),
                            exclude_anchors=_used_auth_anchors,
                        )
                    )
                    if tgame_mode4_key is not None:
                        break
                    time.sleep(0.05)

                if (
                    tgame_mode4_key is not None
                    and isinstance(crypto_src, dict)
                    and crypto_src.get("anchor")
                ):
                    try:
                        _chosen_anchor = int(str(crypto_src["anchor"]), 16)
                        with _TGAME_USED_AUTH_ANCHORS_LOCK:
                            _TGAME_USED_AUTH_ANCHORS.setdefault(
                                int(pid), set()
                            ).add(_chosen_anchor)
                    except Exception:
                        pass
                if tgame_mode4_key is None:
                    log(label, f"TGame ticket-anchor key recovery FAILED: {crypto_src}")
                    log(label, "v42 sends no guessed cmd08.")
                elif tgame_crypto_mode not in (3, 4):
                    log(
                        label,
                        f"TGame ticket-anchor state mode={tgame_crypto_mode} "
                        f"key={tgame_mode4_key.hex()} source={crypto_src}; "
                        "unsupported for this SYN"
                    )
                else:
                    if isinstance(crypto_src, dict):
                        log(
                            label,
                            "TGame ticket-anchor crypto-state: "
                            f"mode={tgame_crypto_mode} "
                            f"key={tgame_mode4_key.hex()} "
                            f"verified={crypto_src.get('verified')} "
                            f"uin={crypto_src.get('uin')} "
                            f"service_id={crypto_src.get('service_id')} "
                            f"conn={crypto_src.get('conn')} "
                            f"anchor={crypto_src.get('anchor')} "
                            f"fresh={crypto_src.get('fresh_for_connection')} "
                            f"candidates={crypto_src.get('candidate_count')}"
                        )
                    else:
                        log(
                            label,
                            f"TGame ticket-anchor crypto-state: "
                            f"mode={tgame_crypto_mode} "
                            f"key={tgame_mode4_key.hex()} source={crypto_src}"
                        )

                    syn, syn_cipher = tgame_build_cmd08_syn_auto(
                        tgame_mode4_key, tgame_crypto_mode
                    )
                    conn.sendall(syn)
                    log(label, f"TX TGAME cmd08 SYN v42 ({len(syn)}B): {syn.hex()}")
                    log(
                        label,
                        f"TX TGAME SYN challenge={TGAME_SYN_RAND!r} "
                        f"mode={tgame_crypto_mode} cipher_len={len(syn_cipher)}; "
                        "waiting for cmd09 SYNACK"
                    )

                role_state = {"tgame": True}
            else:
                role_state = role_extract_auth_state(data)
            if not role_state.get("tgame"):
                log(label, f"live auth state: mode={role_state.get('mode')} uin={role_state.get('uin')} seq={role_state.get('seq')} key={role_state.get('session_key')!r} body_status={role_state.get('body_status')}")
            app_plain = role_state.get("app_plain") or b""
            if len(app_plain) >= 14:
                try:
                    app_len = int.from_bytes(app_plain[0:4], "big")
                    magic = int.from_bytes(app_plain[4:6], "big")
                    ver = int.from_bytes(app_plain[6:8], "big")
                    cmdid = int.from_bytes(app_plain[8:10], "big")
                    app_seq = int.from_bytes(app_plain[10:14], "big")
                    app_uin = int.from_bytes(app_plain[14:18], "big") if len(app_plain) >= 18 else None
                    log(label, f"TACC request decoded: len={app_len} magic=0x{magic:04x} ver={ver} cmdid={cmdid} app_seq={app_seq} app_uin={app_uin} raw={app_plain.hex()}")
                except Exception as e:
                    log(label, f"TACC request parse error: {e}")
            if label.upper() == "ROLE" and (not role_state.get("tgame")) and role_state.get("mode") == 3 and role_state.get("session_key") and role_state.get("seq") is not None:
                # v5: this ROLE connection is client.exe / CPlayerInfoQuerier.
                # It already sent an authenticated TPDU cmd03 with a TACC request body.
                # The correct next server message is a TPDU cmd05 carrying TACC_CMD_RSP,
                # not a cmd08 SYN challenge.
                app, priv_payload = role_build_tacc_one_private_entry_app(
                    uin=role_state.get("uin") or 10001,
                    server_id=0x01010101,
                    host="127.0.0.1",
                    port=65005,
                    cmdid=2,
                    update_time=int(time.time()),
                )
                # Echo the client's TPDU sequence. v6 used echo; v7 used +1.
                # The payload content, not the TPDU seq, is the new variable here.
                rsp, body_plain, body_cipher = role_build_plain_tpdu_body_response(
                    role_state["session_key"],
                    role_state["seq"] & 0xffffffff,
                    app,
                )
                conn.sendall(rsp)
                log(label, f"TX TACC-RSP v26 tgame-mode4-syn-probe ({len(rsp)}B) app_len={len(app)} body_cipher_len={len(body_cipher)} client_seq={role_state['seq']} uin={role_state.get('uin')}")
                log(label, f"TX TACC-RSP v26 server_id=0x01010101 private_data={priv_payload.hex()} ; waiting for TGame/next connection")
            elif not role_state.get("tgame"):
                log(label, "Not sending TACC-RSP: live mode3/session key/sequence was not recovered")

        log(
            label,
            "Keeping connection open for follow-up handshake traffic"
        )

        followup_seconds = 3600.0 if label.upper() == "ZONE" else 120.0
        deadline = time.time() + followup_seconds
        log(label, f"Follow-up receive lifetime={followup_seconds:.0f}s")
        conn.settimeout(1.0)

        # Transport crypto state changes immediately after a successful cmd01.
        active_tgame_key = tgame_mode4_key
        active_tgame_mode = locals().get("tgame_crypto_mode")

        # v71: TCP is a byte stream, not a packet API.  Once CHGSKEY has
        # completed, preserve partial tails and split coalesced generic TPDUs.
        post_chgskey_stream_mode = False
        post_chgskey_tail = b""
        post_chgskey_frame_queue = []

        # v69 diagnostic:
        # The client consistently sends FF05 only *after* accepting A001.
        # Do not push A005/A006/FF13 before that client-side milestone.
        pending_zone_profile = None

        # v87 persistent shop/profile state. ZONE owns the authoritative local
        # player save; ROLE/GEO sockets use defaults and never overwrite it.
        if label.upper() == "ZONE":
            shop_session_id = _v89_begin_state_session()
            persisted, state_source = _v87_load_state()
            shop_state_active = True
        else:
            shop_session_id = None
            _v89_bind_state_session(None)
            persisted, state_source = _v87_default_state(), "non-zone-default"
            shop_state_active = False
        local_inventory = [dict(p) for p in persisted["inventory"]]
        next_local_prop_gid = int(persisted["next_prop_gid"])
        local_tp_balance = int(persisted["wallet"]["ap"])  # protocol TP == client AP
        local_gp_balance = int(persisted["wallet"]["gp"])
        local_mp_balance = int(persisted["wallet"]["mp"])
        local_nickname = str(persisted.get("nickname") or "LocalPlayer")
        current_role_gid = _v87_pick_current_role_gid(
            local_inventory, persisted.get("current_role_gid", LOCAL_ROLE_GID)
        )
        if label.upper() == "ZONE":
            local_clan, clan_state_source = _v94_load_clan_state()
        else:
            local_clan, clan_state_source = _v94_default_clan_state(), "non-zone-default"
        role_state["v94_clan"] = local_clan
        local_moneyflow = []
        # A505 retransmissions can occur after transport retries.  Key by the
        # client app sequence and replay the original A506 instead of charging
        # or granting twice.
        processed_buy_requests = {}
        processed_buy_order = []
        if shop_state_active:
            log(
                "STATE",
                f"loaded source={state_source} AP={local_tp_balance} "
                f"GP={local_gp_balance} MP={local_mp_balance} "
                f"inventory={len(local_inventory)} role=0x{current_role_gid:016x} "
                f"path={PLAYER_STATE_PATH}"
            )
            log(
                "CLAN",
                f"loaded source={clan_state_source} "
                f"clan_id=0x{int(local_clan.get('clan_id', 0)):016x} "
                f"name={local_clan.get('clan_name', '')!r} "
                f"captain={local_clan.get('captain_name', '')!r} "
                f"path={CLAN_STATE_PATH}",
            )
            if state_source != "disk":
                _v87_save_state(
                    _v87_build_state(
                        local_nickname, local_tp_balance, local_gp_balance,
                        local_mp_balance, current_role_gid, next_local_prop_gid,
                        local_inventory,
                    ),
                    reason="initialize",
                )

        while time.time() < deadline:
            # v71: after CHGSKEY, consume one complete generic TPDU at a time.
            # Extra TPDUs from the same recv() remain queued for the next loop.
            if post_chgskey_stream_mode and post_chgskey_frame_queue:
                extra = post_chgskey_frame_queue.pop(0)
                log(
                    label,
                    f"FOLLOW-UP FRAME ({len(extra)}B) from queued TCP data "
                    f"OWNER={owner}: {_short_hex(extra, 96)}"
                )
            else:
                try:
                    rx_chunk = conn.recv(4096)
                except socket.timeout:
                    continue

                if not rx_chunk:
                    log(label, "Client closed connection; if this was client.exe after TACC-RSP, that can be normal. Watch for next VERSION/ROLE owner=TGame.exe.")
                    break

                if post_chgskey_stream_mode:
                    combined = post_chgskey_tail + rx_chunk
                    try:
                        frames, post_chgskey_tail = tgame_split_generic_stream(
                            combined
                        )
                    except Exception as e:
                        log(
                            label,
                            f"v71 TCP stream split ERROR: {type(e).__name__}: {e}; "
                            f"combined={_short_hex(combined, 160)}"
                        )
                        # Preserve old behavior as a diagnostic fallback.
                        extra = combined
                        post_chgskey_tail = b""
                    else:
                        log(
                            label,
                            f"FOLLOW-UP RX CHUNK ({len(rx_chunk)}B) "
                            f"OWNER={owner}: complete_frames={len(frames)} "
                            f"tail={len(post_chgskey_tail)}B "
                            f"{_short_hex(rx_chunk, 96)}"
                        )
                        if not frames:
                            continue
                        extra = frames.pop(0)
                        post_chgskey_frame_queue.extend(frames)
                        log(
                            label,
                            f"FOLLOW-UP FRAME ({len(extra)}B) "
                            f"OWNER={owner}: {_short_hex(extra, 96)}"
                        )
                else:
                    extra = rx_chunk
                    log(
                        label,
                        f"FOLLOW-UP RX ({len(extra)}B) "
                        f"OWNER={owner}: {_short_hex(extra, 96)}"
                    )
            if label.upper() in ("ROLE", "ZONE"):
                if tgame_mode4_key is not None:
                    mode_now = locals().get("tgame_crypto_mode")
                    if mode_now == 3:
                        try:
                            if len(extra) >= 3 and extra[2] == 0x09:
                                # SYNACK uses the cmd-specific head extension.
                                cmd_now, total_now, enc_now = tgame_parse_wire_encrypted_body(extra)
                                plain_now = tgame_mode3_decrypt(enc_now, active_tgame_key)
                                log(
                                    label,
                                    f"TGame mode3 follow-up cmd=0x{cmd_now:02x} "
                                    f"total={total_now} plain={plain_now.hex()}"
                                )
                                if plain_now == TGAME_SYN_RAND:
                                    log(label, "TGame SYNACK verified: challenge echo matches")
                                    chg, chg_enc, new_key = tgame_build_cmd01_chgskey(
                                        active_tgame_key, mode_now
                                    )
                                    conn.sendall(chg)
                                    active_tgame_key = new_key
                                    active_tgame_mode = mode_now
                                    post_chgskey_stream_mode = True
                                    post_chgskey_tail = b""
                                    post_chgskey_frame_queue.clear()
                                    log(
                                        label,
                                        f"TX TGAME cmd01 CHGSKEY v44 ({len(chg)}B) "
                                        f"new_key={new_key!r} enc_len={len(chg_enc)}: {chg.hex()}"
                                    )
                                    log(
                                        label,
                                        "TGame transport key switched locally; subsequent "
                                        "cmd00 body traffic will be decrypted with the new key"
                                    )
                                else:
                                    log(
                                        label,
                                        f"TGame SYNACK plaintext mismatch expected={TGAME_SYN_RAND.hex()}"
                                    )
                            else:
                                # Normal post-handshake traffic uses the generic
                                # 12-byte TPDUBase and encrypted BodyLen bytes.
                                cmd_now, head_now, body_len_now, enc_now = (
                                    tgame_parse_generic_body(extra)
                                )
                                plain_now = tgame_mode3_decrypt(
                                    enc_now, active_tgame_key
                                )
                                log(
                                    label,
                                    f"TGame post-CHGSKEY cmd=0x{cmd_now:02x} "
                                    f"head_len={head_now} body_len={body_len_now} "
                                    f"plain_len={len(plain_now)} plain={plain_now.hex()}"
                                )

                                if cmd_now == 0x0D:
                                    close_seq = (
                                        struct.unpack(">I", plain_now[:4])[0]
                                        if len(plain_now) >= 4 else None
                                    )
                                    log(
                                        label,
                                        "TGame TPDU CLOSE "
                                        + (
                                            f"seq=0x{close_seq:08x}"
                                            if close_seq is not None
                                            else f"plain={plain_now.hex()}"
                                        )
                                    )
                                    continue

                                # v48 application dispatcher.  The ROLE socket
                                # carries C2GEO (0x8202).  After ZoneList the
                                # client opens a NEW connection to port 65006,
                                # repeats the same TPDU handshake, then carries
                                # C2ZN (0x3243) inside cmd00.
                                try:
                                    app = _v48_parse_app(plain_now)
                                    log(
                                        label,
                                        "TGame APP: "
                                        f"seq=0x{app['seq']:08x} "
                                        f"magic=0x{app['magic']:04x} "
                                        f"cmd=0x{app['cmd']:04x} "
                                        f"head_len={app['head_len']} "
                                        f"body_len={app['body_len']} "
                                        f"body={_short_hex(app['body'], 128)}"
                                    )

                                    if app["magic"] == TGAME_GEO_MAGIC:
                                        if app["cmd"] == TGAME_GEO_REQ_PINGLIST:
                                            # Runtime v60: x32dbg proved two wire-format fixes.
                                            # 1) Response cmd00 plaintext begins at GEO magic 0x8202;
                                            #    do NOT prepend/echo the client's 4-byte app sequence.
                                            # 2) PingInfo.Domain is u32_be(strlen+1) + NUL string,
                                            #    making BodyLen=0x22 and app plaintext length 0x2A.
                                            client_seq = app["seq"] & 0xffffffff
                                            log(
                                                label,
                                                f"GEO PingList runtime-verified response: "
                                                f"client_rx_seq=0x{client_seq:08x} "
                                                "response_seq_prefix=NONE "
                                                "domain_len_prefix=u32be"
                                            )
                                            rsp_plain = tgame_build_geo_pinglist_response(
                                                client_seq, max_delay_ms=1000
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp_plain,
                                                label,
                                                "TGAME GEO2C_RES_PINGLIST v61-ping-verified "
                                                "seq_prefix=NONE body_len=0x22 "
                                                "result=0x8B00 servers=1 "
                                                "target=127.0.0.1 max_delay_ms=1000"
                                            )

                                        elif app["cmd"] == TGAME_GEO_REQ_ZONELIST:
                                            zreq = _v48_parse_geo_req_zonelist(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                "C2GEO_REQ_ZONELIST ACCEPTANCE SIGNAL: "
                                                f"count={zreq['count']} "
                                                f"servers={zreq['servers']} "
                                                f"max_delay_ms={zreq['max_delay_ms']} "
                                                f"consumed={zreq['consumed']}/{zreq['body_len']}"
                                            )
                                            client_seq = app["seq"] & 0xffffffff
                                            log(
                                                label,
                                                "GEO ZoneList response derived from accepted PingList framing: "
                                                f"client_rx_seq=0x{client_seq:08x} "
                                                "response_seq_prefix=NONE "
                                                "domain_len_prefix=u32be"
                                            )
                                            zrsp = _v48_build_geo_zonelist(
                                                client_seq, port=TGAME_ZONE_PORT
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, zrsp,
                                                label,
                                                "TGAME GEO2C_RES_ZONELIST v61-no-seq-u32-domain "
                                                "seq_prefix=NONE body_len=0x3E "
                                                "result=0x8B00 zones=1 "
                                                f"target=127.0.0.1:{TGAME_ZONE_PORT} "
                                                "decision=Sequential"
                                            )
                                            log(
                                                label,
                                                f"Waiting for NEW TGame TCP connection "
                                                f"to ZONE port {TGAME_ZONE_PORT}"
                                            )

                                        else:
                                            log(
                                                label,
                                                f"Unhandled GEO cmd=0x{app['cmd']:04x}"
                                            )

                                    elif app["magic"] == TGAME_ZN_MAGIC:
                                        if app["cmd"] == TGAME_ZN_REQ_LOGIN:
                                            req = _v48_parse_zn_login(app["body"])
                                            log(
                                                label,
                                                "C2ZN_REQ_LOGIN: "
                                                f"sub=0x{req['sub_channel_id']:08x} "
                                                f"pref_crc=0x{req['preference_crc']:08x} "
                                                f"system_crc=0x{req['system_crc']:08x}"
                                            )

                                            base_seq = app["seq"]
                                            seq_login = (base_seq + 1) & 0xffffffff
                                            seq_pinfo = (base_seq + 2) & 0xffffffff
                                            seq_props = (base_seq + 3) & 0xffffffff
                                            seq_hints = (base_seq + 4) & 0xffffffff
                                            log(
                                                label,
                                                "TPDUFrame SEQ candidate ZONE: "
                                                f"client=0x{base_seq:08x} "
                                                f"login=0x{seq_login:08x} "
                                                f"pinfo=0x{seq_pinfo:08x} "
                                                f"props=0x{seq_props:08x} "
                                                f"hints=0x{seq_hints:08x}"
                                            )
                                            login_rsp = _v48_build_zn_login_response(
                                                seq_login,
                                                tgame_point=local_tp_balance,
                                                gold_point=local_gp_balance,
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, login_rsp,
                                                label,
                                                "ZN2C_RES_LOGIN v72-roomalloc-accept-probe "
                                                "result=0x8100 main=1 sub=1 freeprops=0"
                                            )

                                            # IMPORTANT v69 change:
                                            # Do NOT send PlayerInfo/PlayerProps/ZoneHints
                                            # immediately after A001.  The A001-only v63
                                            # capture proved the client naturally sends
                                            # FF05 after it accepts login.  Treat FF05 as
                                            # the client-side readiness milestone and only
                                            # then publish the profile.
                                            pending_zone_profile = {
                                                "seq_pinfo": seq_pinfo,
                                                "seq_props": seq_props,
                                                "seq_hints": seq_hints,
                                            }
                                            log(
                                                label,
                                                "v71: profile notifications DEFERRED until "
                                                "client FF05 readiness packet"
                                            )

                                        elif app["cmd"] == 0xFF05:
                                            ff05_value = (
                                                struct.unpack(">I", app["body"][:4])[0]
                                                if len(app["body"]) >= 4 else None
                                            )
                                            log(
                                                label,
                                                "C2ZN FF05 observed: "
                                                + (f"value=0x{ff05_value:08x} ({ff05_value}) " if ff05_value is not None else "")
                                                + "=> client login-ready milestone"
                                            )

                                            if pending_zone_profile is not None:
                                                pinfo = _v48_build_playerinfo(
                                                    pending_zone_profile["seq_pinfo"],
                                                    uin=LOCAL_UIN,
                                                    tgame_point=local_tp_balance,
                                                    gold_point=local_gp_balance,
                                                    month_point=local_mp_balance,
                                                    cur_role_gid=current_role_gid,
                                                    nickname=local_nickname,
                                                    clan_id=int(local_clan.get("clan_id", 0)),
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key, pinfo,
                                                    label,
                                                    "ZN2C_NTF_PLAYERINFO v81-after-ff05 "
                                                    f"nick={local_nickname} level=1 "
                                                    f"role=0x{current_role_gid:016x} "
                                                    f"AP={local_tp_balance} GP={local_gp_balance} MP={local_mp_balance}"
                                                )

                                                # GP/MP already populate from PlayerInfo at login.
                                                # AP/TP does not, so answer only that premium-wallet
                                                # path here; do not label GP/MP updates as TPBALANCE.
                                                login_tp_update = _v88_build_update_player_property(
                                                    UPDATE_FLAG_TP,
                                                    UPDATE_REASON_TP_BALANCE,
                                                    local_tp_balance,
                                                    local_gp_balance,
                                                    local_mp_balance,
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key, login_tp_update, label,
                                                    "ZN2C_NTF_UPDATEPLAYERPROPERTY v89 login-AP "
                                                    f"AP={local_tp_balance} GP={local_gp_balance} "
                                                    f"MP={local_mp_balance} reason=0x{UPDATE_REASON_TP_BALANCE:02x}",
                                                )

                                                for idx, props in enumerate(
                                                    _v75_build_playerprops_packets(local_inventory)
                                                ):
                                                    _v48_send_app(
                                                        conn, active_tgame_key, props, label,
                                                        f"ZN2C_NTF_PLAYERPROPS v81-after-ff05 "
                                                        f"packet={idx+1} inventory={len(local_inventory)} "
                                                        f"role_gid=0x{current_role_gid:016x} bags=1,2"
                                                    )

                                                hints = _v48_build_zonehints(
                                                    pending_zone_profile["seq_hints"]
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key, hints,
                                                    label,
                                                    "ZN2C_NTF_ZONE_HINTS v71-after-ff05 "
                                                    "hint=0"
                                                )

                                                pending_zone_profile = None
                                                log(
                                                    label,
                                                    "v71: deferred profile sequence sent "
                                                    "after FF05"
                                                )

                                            else:
                                                log(
                                                    label,
                                                    "v71: FF05 received with no pending "
                                                    "profile sequence"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_HEARTBEAT:
                                            hb_seq = (app["seq"] + 1) & 0xffffffff
                                            hb = _v48_build_heartbeat_response(
                                                hb_seq
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, hb,
                                                label,
                                                "ZN2C_RES_HEARTBEAT v72-roomalloc-accept-probe"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CREATEACCOUNT:
                                            nick = _v48_parse_createaccount(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                f"C2ZN_REQ_CREATEACCOUNT nickname={nick!r}"
                                            )
                                            rsp_seq = (app["seq"] + 1) & 0xffffffff
                                            rsp = _v48_build_createaccount_response(
                                                rsp_seq
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_CREATEACCOUNT v72-roomalloc-accept "
                                                "result=0x8100"
                                            )
                                            local_nickname = (nick or "LocalPlayer")[:31]
                                            if shop_state_active:
                                                _v87_save_state(
                                                    _v87_build_state(
                                                        local_nickname, local_tp_balance,
                                                        local_gp_balance, local_mp_balance,
                                                        current_role_gid, next_local_prop_gid,
                                                        local_inventory,
                                                    ),
                                                    reason="nickname",
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_SHOPCONFHASH:
                                            client_hash = _v75_parse_shop_conf_hash(app["body"])
                                            log(label, f"C2ZN_REQ_SHOPCONFHASH v75 client_hash=0x{client_hash:08x}")
                                            rsp = _v75_build_shop_conf_hash_response(client_hash)
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp, label,
                                                "ZN2C_RES_SHOPCONFHASH v75 result=0x8200 hash=echo url=''"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_TP_BALANCE:
                                            tp_uin = _v89_parse_tp_balance_request(app["body"])
                                            log(
                                                label,
                                                f"C2ZN_REQ_TPBALANCE v89 cmd=0xA50E uin={tp_uin} "
                                                f"AP={local_tp_balance}",
                                            )
                                            tp_update = _v88_build_update_player_property(
                                                UPDATE_FLAG_TP,
                                                UPDATE_REASON_TP_BALANCE,
                                                local_tp_balance,
                                                local_gp_balance,
                                                local_mp_balance,
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, tp_update, label,
                                                "ZN2C_NTF_UPDATEPLAYERPROPERTY v89 TPBalance "
                                                f"flag=AP AP={local_tp_balance} GP={local_gp_balance} "
                                                f"MP={local_mp_balance} reason=0x{UPDATE_REASON_TP_BALANCE:02x}",
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_BUYCOMMODITY:
                                            raw_buy_body = bytes(app["body"])
                                            buy_seq = int(app["seq"]) & 0xffffffff
                                            cached = processed_buy_requests.get(buy_seq)
                                            if cached is not None:
                                                if cached["body"] == raw_buy_body:
                                                    log(
                                                        label,
                                                        f"v89 BUY replay: seq=0x{buy_seq:08x} "
                                                        "duplicate request; no charge/no new GID",
                                                    )
                                                    _v48_send_app(
                                                        conn, active_tgame_key, cached["response"], label,
                                                        f"ZN2C_RES_BUYCOMMODITY v89 replay seq=0x{buy_seq:08x}",
                                                    )
                                                    _v88_send_wallet_sync(
                                                        conn, active_tgame_key, label,
                                                        local_tp_balance, local_gp_balance, local_mp_balance,
                                                        reason=UPDATE_REASON_BUY,
                                                        prefix="v89 replay-wallet",
                                                    )
                                                    for idx, props_pkt in enumerate(
                                                        _v75_build_playerprops_packets(local_inventory)
                                                    ):
                                                        _v48_send_app(
                                                            conn, active_tgame_key, props_pkt, label,
                                                            f"ZN2C_NTF_PLAYERPROPS v89 replay packet={idx+1} "
                                                            f"inventory={len(local_inventory)}",
                                                        )
                                                    continue
                                                log(
                                                    label,
                                                    f"v89 BUY sequence collision: seq=0x{buy_seq:08x} "
                                                    "body changed; rejecting without mutation",
                                                )

                                            req = _v75_parse_buy_commodity(raw_buy_body)
                                            log(
                                                label,
                                                "C2ZN_REQ_BUYCOMMODITY v89: "
                                                f"seq=0x{buy_seq:08x} buy_type={req['buy_type']} "
                                                f"pay_type={req['pay_type']} consignne={req['consignne']} "
                                                f"nick={req['nickname']!r} count={req['count']} "
                                                f"convert_mp={req['convert_mp']} remark={req['remark']!r}"
                                            )

                                            reject = None
                                            if cached is not None and cached["body"] != raw_buy_body:
                                                reject = _v89_ShopReject(
                                                    SHOP_ERR_FAIL,
                                                    "same application sequence reused with different buy body",
                                                )

                                            plan = None
                                            if reject is None:
                                                try:
                                                    plan = _v89_plan_buy(
                                                        req, local_inventory, next_local_prop_gid,
                                                        local_tp_balance, local_gp_balance, local_mp_balance,
                                                    )
                                                except _v89_ShopReject as shop_e:
                                                    reject = shop_e

                                            if reject is not None:
                                                log(
                                                    label,
                                                    f"v89 BUY rejected result=0x{reject.result:04x}: "
                                                    f"{reject.message}; state unchanged",
                                                )
                                                rsp = _v75_build_buy_commodity_response(
                                                    req, [],
                                                    consume_tp=0,
                                                    tp_balance=local_tp_balance,
                                                    consume_gp=0,
                                                    consume_mp=0,
                                                    result=reject.result,
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key, rsp, label,
                                                    f"ZN2C_RES_BUYCOMMODITY v89 REJECT result=0x{reject.result:04x}",
                                                )
                                                # Cache a first-seen request.  If this was a
                                                # sequence collision, preserve the original cached
                                                # response instead of replacing it with the reject.
                                                if cached is None:
                                                    processed_buy_requests[buy_seq] = {
                                                        "body": raw_buy_body,
                                                        "response": rsp,
                                                    }
                                                    processed_buy_order.append(buy_seq)
                                                    if len(processed_buy_order) > 64:
                                                        old_seq = processed_buy_order.pop(0)
                                                        if old_seq != buy_seq:
                                                            processed_buy_requests.pop(old_seq, None)
                                                continue

                                            # COMMIT begins here.  Nothing above mutates wallet,
                                            # inventory, or GID allocation.
                                            bought = plan["bought"]
                                            consume_tp = int(plan["consume_tp"])
                                            consume_gp = int(plan["consume_gp"])
                                            consume_mp = int(plan["consume_mp"])
                                            local_inventory.extend(row["prop"] for row in bought)
                                            next_local_prop_gid = int(plan["next_gid"])
                                            local_tp_balance -= consume_tp
                                            local_gp_balance -= consume_gp
                                            local_mp_balance -= consume_mp

                                            for row in bought:
                                                prop = row["prop"]
                                                log(
                                                    label,
                                                    "v89 BUY grant: "
                                                    f"commodity={row['commodity_id']} "
                                                    f"price_index={row['price_index']} "
                                                    f"client_price={row['client_price']} "
                                                    f"server_price={row['server_price']} "
                                                    f"currency={row['currency']} "
                                                    f"price_source={row['price_source']} "
                                                    f"voucher={row['voucher_id']} -> gid=0x{int(prop['gid']):016x} "
                                                    f"item_id={int(prop['item_id'])} source={row['map_source']}",
                                                )
                                            log(
                                                label,
                                                "v89 SHOP CHARGE atomic: "
                                                f"consume_AP={consume_tp} AP_balance={local_tp_balance} "
                                                f"consume_GP={consume_gp} GP_balance={local_gp_balance} "
                                                f"consume_MP={consume_mp} MP_balance={local_mp_balance}"
                                            )

                                            if shop_state_active:
                                                _v87_save_state(
                                                    _v87_build_state(
                                                        local_nickname, local_tp_balance,
                                                        local_gp_balance, local_mp_balance,
                                                        current_role_gid, next_local_prop_gid,
                                                        local_inventory,
                                                    ),
                                                    reason="buy",
                                                )

                                            new_moneyflow = []
                                            if consume_tp:
                                                new_moneyflow.append(_v81_pack_moneyflow_record(
                                                    MONEYTYPE_TP, -consume_tp, local_tp_balance
                                                ))
                                            if consume_gp:
                                                new_moneyflow.append(_v81_pack_moneyflow_record(
                                                    MONEYTYPE_GP, -consume_gp, local_gp_balance
                                                ))
                                            if consume_mp:
                                                new_moneyflow.append(_v81_pack_moneyflow_record(
                                                    MONEYTYPE_MP, -consume_mp, local_mp_balance
                                                ))
                                            local_moneyflow.extend(new_moneyflow)

                                            rsp = _v75_build_buy_commodity_response(
                                                req, bought,
                                                consume_tp=consume_tp,
                                                tp_balance=local_tp_balance,
                                                consume_gp=consume_gp,
                                                consume_mp=consume_mp,
                                                result=SHOP_ERR_SUCC,
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp, label,
                                                f"ZN2C_RES_BUYCOMMODITY v89 result=0x8200 "
                                                f"props={len(bought)} consumeGP={consume_gp} "
                                                f"consumeTP={consume_tp} consumeMP={consume_mp}"
                                            )

                                            processed_buy_requests[buy_seq] = {
                                                "body": raw_buy_body,
                                                "response": rsp,
                                            }
                                            processed_buy_order.append(buy_seq)
                                            if len(processed_buy_order) > 64:
                                                old_seq = processed_buy_order.pop(0)
                                                if old_seq != buy_seq:
                                                    processed_buy_requests.pop(old_seq, None)

                                            _v88_send_wallet_sync(
                                                conn, active_tgame_key, label,
                                                local_tp_balance,
                                                local_gp_balance,
                                                local_mp_balance,
                                                reason=UPDATE_REASON_BUY,
                                                prefix="v89 post-buy",
                                            )

                                            wallet_pinfo = _v48_build_playerinfo(
                                                (app["seq"] + 1) & 0xffffffff,
                                                uin=LOCAL_UIN,
                                                tgame_point=local_tp_balance,
                                                gold_point=local_gp_balance,
                                                month_point=local_mp_balance,
                                                cur_role_gid=current_role_gid,
                                                nickname=local_nickname,
                                                clan_id=int(local_clan.get("clan_id", 0)),
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, wallet_pinfo, label,
                                                "ZN2C_NTF_PLAYERINFO v89 wallet-refresh "
                                                f"AP={local_tp_balance} GP={local_gp_balance} "
                                                f"MP={local_mp_balance} role=0x{current_role_gid:016x}"
                                            )

                                            if ENABLE_MONEYFLOW_NOTIFICATIONS and new_moneyflow:
                                                moneyflow_pkt = _v81_build_moneyflow_notification(new_moneyflow)
                                                _v48_send_app(
                                                    conn, active_tgame_key, moneyflow_pkt, label,
                                                    f"ZN2C_NTF_MONEYFLOW v90-shopfix cmd=0x{TGAME_ZN_NTF_MONEYFLOW:04X} "
                                                    f"count={len(new_moneyflow)}"
                                                )

                                            for idx, props_pkt in enumerate(
                                                _v75_build_playerprops_packets(local_inventory)
                                            ):
                                                _v48_send_app(
                                                    conn, active_tgame_key, props_pkt, label,
                                                    f"ZN2C_NTF_PLAYERPROPS v89 post-buy packet={idx+1} "
                                                    f"inventory={len(local_inventory)}"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_PROP_OPERATION:
                                            # This is the actual equip/take-off request emitted
                                            # after the shop's "select backpack equipment" OK.
                                            # Wire body observed live:
                                            #   u16 OpType | u64 PropGID | u64 OwnerGID | u8 Location
                                            op = _v75_parse_prop_operation(app["body"])
                                            action, effective_op = _v80_apply_prop_operation(
                                                local_inventory, op, current_role_gid
                                            )
                                            effective_body = _v80_pack_prop_operation(effective_op)
                                            if op["operation"] == PROP_OP_EQUIP:
                                                subject = next((p for p in local_inventory if int(p.get("gid", 0)) == int(op["subject_gid"])), None)
                                                if subject is not None:
                                                    item_id = int(subject.get("item_id", 0))
                                                    if int(subject.get("location", PROP_LOC_BAG)) in (PROP_LOC_ROLE1, PROP_LOC_ROLE2) or                                                             REAL_ITEM_DEFAULT_LOCATIONS.get(item_id) in (PROP_LOC_ROLE1, PROP_LOC_ROLE2):
                                                        current_role_gid = int(subject["gid"])
                                            current_role_gid = _v87_pick_current_role_gid(local_inventory, current_role_gid)
                                            if shop_state_active:
                                                _v87_save_state(
                                                    _v87_build_state(
                                                        local_nickname, local_tp_balance,
                                                        local_gp_balance, local_mp_balance,
                                                        current_role_gid, next_local_prop_gid,
                                                        local_inventory,
                                                    ),
                                                    reason="prop-operation",
                                                )
                                            log(
                                                label,
                                                "C2ZN_REQ_PROPOPERATION v82 LIVE: "
                                                f"op={op['operation']} subject=0x{op['subject_gid']:016x} "
                                                f"client_target=0x{op['target_gid']:016x} "
                                                f"effective_target=0x{effective_op['target_gid']:016x} "
                                                f"loc=0x{op['location']:02x} => {action}"
                                            )

                                            # A009 returns the authoritative operation.  If the
                                            # request had OwnerPropId=0 this now supplies CurRoleGID.
                                            rsp = _v79_build_live_prop_operation_response(effective_body)
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp, label,
                                                "ZN2C_RES_PROPOPERATION v82 cmd=0xA009 "
                                                "result=0x8100 + authoritative operation"
                                            )

                                            # A00A is the server notification form of the same
                                            # operation.  Send it as well so the local inventory/
                                            # loadout UI receives the authoritative state change.
                                            ntf = _v79_build_live_prop_operation_notification(effective_body)
                                            _v48_send_app(
                                                conn, active_tgame_key, ntf, label,
                                                "ZN2C_NTF_PROPOPERATION v88 cmd=0xA00A "
                                                "authoritative operation"
                                            )

                                            # Re-publish authoritative inventory after mutation.
                                            for idx, props_pkt in enumerate(
                                                _v75_build_playerprops_packets(local_inventory)
                                            ):
                                                _v48_send_app(
                                                    conn, active_tgame_key, props_pkt, label,
                                                    f"ZN2C_NTF_PLAYERPROPS v82 post-A008 "
                                                    f"packet={idx+1} inventory={len(local_inventory)}"
                                                )
                                            role_refresh = _v48_build_playerinfo(
                                                (app["seq"] + 1) & 0xffffffff,
                                                uin=LOCAL_UIN,
                                                tgame_point=local_tp_balance,
                                                gold_point=local_gp_balance,
                                                month_point=local_mp_balance,
                                                cur_role_gid=current_role_gid,
                                                nickname=local_nickname,
                                                clan_id=int(local_clan.get("clan_id", 0)),
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, role_refresh, label,
                                                f"ZN2C_NTF_PLAYERINFO v87 post-A008 role=0x{current_role_gid:016x}"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_ITEM_OPERATION:
                                            op = _v75_parse_prop_operation(app["body"])
                                            action, _effective_op = _v80_apply_prop_operation(
                                                local_inventory, op, current_role_gid
                                            )
                                            if op["operation"] == PROP_OP_EQUIP:
                                                subject = next((p for p in local_inventory if int(p.get("gid", 0)) == int(op["subject_gid"])), None)
                                                if subject is not None:
                                                    item_id = int(subject.get("item_id", 0))
                                                    if int(subject.get("location", PROP_LOC_BAG)) in (PROP_LOC_ROLE1, PROP_LOC_ROLE2) or                                                             REAL_ITEM_DEFAULT_LOCATIONS.get(item_id) in (PROP_LOC_ROLE1, PROP_LOC_ROLE2):
                                                        current_role_gid = int(subject["gid"])
                                            current_role_gid = _v87_pick_current_role_gid(local_inventory, current_role_gid)
                                            if shop_state_active:
                                                _v87_save_state(
                                                    _v87_build_state(
                                                        local_nickname, local_tp_balance,
                                                        local_gp_balance, local_mp_balance,
                                                        current_role_gid, next_local_prop_gid,
                                                        local_inventory,
                                                    ),
                                                    reason="item-operation",
                                                )
                                            log(
                                                label,
                                                "C2ZN_REQ_ITEM_OPERATION v75: "
                                                f"op={op['operation']} subject=0x{op['subject_gid']:016x} "
                                                f"target=0x{op['target_gid']:016x} loc=0x{op['location']:02x} "
                                                f"=> {action}"
                                            )
                                            rsp = _v75_build_prop_operation_response(app["body"])
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp, label,
                                                "ZN2C_RES_ITEM_OPERATION v75 result=0x8100 echo-operation"
                                            )
                                            for idx, props_pkt in enumerate(_v75_build_playerprops_packets(local_inventory)):
                                                _v48_send_app(
                                                    conn, active_tgame_key, props_pkt, label,
                                                    f"ZN2C_NTF_PLAYERPROPS v75 post-operation packet={idx+1} inventory={len(local_inventory)}"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_CHANGE_ROLE:
                                            regular_idx, rebel_idx = _v75_parse_change_role(app["body"])
                                            log(
                                                label,
                                                "C2ZN_REQ_CHANGE_ROLE v75: "
                                                f"regular_index={regular_idx} rebel_index={rebel_idx}"
                                            )
                                            rsp = _v75_build_change_role_response()
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp, label,
                                                "ZN2C_RES_CHANGE_ROLE v75 result=0x8100"
                                            )
                                            if shop_state_active:
                                                _v87_save_state(
                                                    _v87_build_state(
                                                        local_nickname, local_tp_balance,
                                                        local_gp_balance, local_mp_balance,
                                                        current_role_gid, next_local_prop_gid,
                                                        local_inventory,
                                                    ),
                                                    reason=f"change-role-ack:{regular_idx},{rebel_idx}",
                                                )

                                        elif app["cmd"] == TGAME_ZN_NTF_ANTIBOTMSG_C2S:
                                            # FF02 is a client->zone notification, not a request.
                                            # It needs no response; logging it as UNHANDLED made it
                                            # look like part of the failure when it is background
                                            # anti-bot/telemetry traffic.
                                            log(
                                                label,
                                                "C2ZN_NTF_ANTIBOTMSG v77 ignored/no-response "
                                                f"body_len={len(app['body'])}"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CARDINFO:
                                            card_uin = _v77_parse_cardinfo_request(app["body"])
                                            # This follows the shop/equip flow in the current build,
                                            # but the C00E body contains nested CardInfo data.  Do not
                                            # send a guessed structure; isolate it cleanly for the
                                            # next trace if the client actually gates on it.
                                            log(
                                                label,
                                                "C2ZN_REQ_CARDINFO v77 observed: "
                                                f"player_uin={card_uin}; response intentionally deferred "
                                                "until CardInfo schema/resource values are mapped"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_FRIEND_STATUS:
                                            fs = _v92_parse_friend_status_request(app["body"])
                                            friend_enabled = bool(
                                                role_state.get("v92_friend_accepted", False)
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_FRIENDSSTATUS v92-social: "
                                                f"count={fs['count']} type={fs['type']} "
                                                f"uins={fs['uins']} accepted={friend_enabled}"
                                            )
                                            rsp = _v92_build_friend_status_response(
                                                fs["type"], fs["uins"], friend_enabled
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp, label,
                                                "ZN2C_RES_FRIENDSTATUS v92-social "
                                                f"cmd=0xA304 count={1 if friend_enabled else 0} "
                                                f"type={fs['type']}"
                                            )

                                            # A303 is the client's native social-readiness probe.
                                            # Seed one local friend request only after this packet,
                                            # so the friend subsystem is definitely initialized.
                                            if (
                                                ENABLE_LOCAL_FRIEND_BOT
                                                and not friend_enabled
                                                and not role_state.get("v92_friend_invite_sent")
                                            ):
                                                friend_invite = _v92_build_friend_invite()
                                                _v48_send_app(
                                                    conn, active_tgame_key, friend_invite, label,
                                                    "ZN2C_REQ_ADDFRIEND v92-social "
                                                    "cmd=0xA306 proposer=LocalFriend uin=10002 "
                                                    "request_id=1"
                                                )
                                                role_state["v92_friend_invite_sent"] = True

                                        elif app["cmd"] == TGAME_ZN_REQ_ADD_FRIEND:
                                            add_req = _v92_parse_add_friend_request(app["body"])
                                            target_uin = add_req["respondent_uin"] or LOCAL_FRIEND_UIN
                                            target_name = (
                                                add_req["respondent_name"]
                                                or LOCAL_FRIEND_NICKNAME
                                            )[:31]
                                            log(
                                                label,
                                                "C2ZN_REQ_ADDFRIEND v92-social: "
                                                f"uin={target_uin} name={target_name!r} "
                                                f"remark={add_req['remark']!r} "
                                                f"tail_len={len(add_req['tail'])}"
                                            )
                                            # This local emulator has one synthetic peer.  An
                                            # outgoing add request is accepted immediately so the
                                            # normal My Friends UI can be exercised without a
                                            # second account/server process.
                                            role_state["v92_friend_accepted"] = True
                                            role_state["v92_friend_uin"] = target_uin
                                            role_state["v92_friend_name"] = target_name
                                            rsp = _v92_build_add_friend_server_response(
                                                friend_uin=target_uin,
                                                friend_name=target_name,
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp, label,
                                                "ZN2C_RES_ADDFRIEND v92-social "
                                                f"cmd=0xA308 result=0x{SNS_ERR_SUCC:04x} "
                                                f"friend={target_name!r} uin={target_uin}"
                                            )

                                        elif app["cmd"] == TGAME_ZN_RES_ADD_FRIEND_C2S:
                                            add = _v92_parse_add_friend_client_response(app["body"])
                                            # SNS success is 0x8300.  Some client branches use
                                            # zero for the local accept/reject UI enum; regard
                                            # both as acceptance for this isolated bot friend.
                                            accepted = add["result"] in (0, SNS_ERR_SUCC)
                                            log(
                                                label,
                                                "C2ZN_RES_ADDFRIEND v92-social: "
                                                f"request_id={add['request_id']} "
                                                f"result=0x{add['result']:04x} "
                                                f"proposer={add['proposer_uin']} "
                                                f"name={add['proposer_name']!r} "
                                                f"accepted={accepted}"
                                            )
                                            if accepted:
                                                role_state["v92_friend_accepted"] = True
                                                rsp = _v92_build_add_friend_server_response()
                                                _v48_send_app(
                                                    conn, active_tgame_key, rsp, label,
                                                    "ZN2C_RES_ADDFRIEND v92-social "
                                                    "cmd=0xA308 result=0x8300 "
                                                    "friend=LocalFriend uin=10002"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_DEL_FRIEND:
                                            friend_uin = _v92_parse_del_friend_request(app["body"])
                                            log(
                                                label,
                                                "C2ZN_REQ_DELFRIEND v92-social: "
                                                f"friend_uin={friend_uin}"
                                            )
                                            role_state["v92_friend_accepted"] = False
                                            role_state.pop("v92_friend_uin", None)
                                            role_state.pop("v92_friend_name", None)
                                            rsp = _v92_build_del_friend_response(friend_uin)
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp, label,
                                                "ZN2C_RES_DELFRIEND v92-social "
                                                f"cmd=0xA30A result=0x{SNS_ERR_SUCC:04x} "
                                                f"friend_uin={friend_uin}"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CHAT_P2P:
                                            try:
                                                chat = _v92_parse_chat_p2p_request(app["body"])
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CHATP2P v92-social: "
                                                    f"type=0x{chat['chat_type']:04x} "
                                                    f"to={chat['recipient_uin']} "
                                                    f"name={chat['recipient_name']!r} "
                                                    f"msg={chat['message']!r} "
                                                    f"pkg_count={chat['pkg_count']} "
                                                    f"tail_len={len(chat['tail'])}"
                                                )
                                                # Local single-player social loopback: messages
                                                # addressed to our synthetic friend get a visible
                                                # P2P reply through the normal A406 receive path.
                                                if ENABLE_LOCAL_FRIEND_BOT:
                                                    reply_text = _v92_friend_bot_reply(chat["message"])
                                                    ntf = _v92_build_chat_p2p_notify(
                                                        chat["chat_type"], reply_text
                                                    )
                                                    _v48_send_app(
                                                        conn, active_tgame_key, ntf, label,
                                                        "ZN2C_NTF_CHATP2P v92-social "
                                                        "cmd=0xA406 from=LocalFriend(10002) "
                                                        f"msg={reply_text!r}"
                                                    )
                                            except Exception as chat_e:
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CHATP2P v92-social decode FAILED: "
                                                    f"{type(chat_e).__name__}: {chat_e}; "
                                                    f"body={app['body'].hex()}"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_VERIFY_CLAN_NAME:
                                            try:
                                                verify_uin, clan_name = _v94_parse_verify_clan_name_request(
                                                    app["body"]
                                                )
                                                valid, clean_name = _v93_validate_clan_name(
                                                    clan_name
                                                )
                                                result = CLAN_ERR_SUCC if valid else CLAN_ERR_FAIL
                                                log(
                                                    label,
                                                    "C2ZN_REQ_VERIFYCLANNAME v94-clan: "
                                                    f"uin={verify_uin} name={clan_name!r} valid={valid}"
                                                )
                                                rsp = _v93_build_verify_clan_name_response(
                                                    clean_name, result=result
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key, rsp, label,
                                                    "ZN2C_RES_VERIFYCLANNAME v94-clan "
                                                    f"cmd=0xAB03 result=0x{result:04x} "
                                                    f"name={clean_name!r}"
                                                )
                                            except Exception as clan_e:
                                                log(
                                                    label,
                                                    "C2ZN_REQ_VERIFYCLANNAME v94-clan decode FAILED: "
                                                    f"{type(clan_e).__name__}: {clan_e}; "
                                                    f"body={app['body'].hex()}"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_CREATE_CLAN:
                                            try:
                                                req = _v94_parse_create_clan_request(app["body"])
                                                valid, clean_name = _v93_validate_clan_name(
                                                    req["clan_name"]
                                                )
                                                result = CLAN_ERR_SUCC if valid else CLAN_ERR_FAIL
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CREATECLAN v94-clan: "
                                                    f"uin={req['uin']} name={req['clan_name']!r} "
                                                    f"safe_code_len={len(req['safe_code'])} "
                                                    f"mail={req['certified_mail']!r} "
                                                    f"valid={valid}"
                                                )
                                                if valid:
                                                    local_clan = _v94_normalize_clan_state({
                                                        "clan_id": LOCAL_CLAN_ID,
                                                        "clan_name": clean_name,
                                                        "captain_uin": req["uin"] or LOCAL_UIN,
                                                        "captain_name": local_nickname,
                                                        "safe_code": req["safe_code"],
                                                        "certified_mail": req["certified_mail"],
                                                        "max_members": 50,
                                                        "cur_members": 1,
                                                        "recruit_type": 0,
                                                        "level_limit": 1,
                                                        "introduction": "Local Assault Fire clan",
                                                        "created_unix": int(time.time()),
                                                    })
                                                    role_state["v94_clan"] = local_clan
                                                    if shop_state_active:
                                                        _v94_save_clan_state(local_clan, reason="create-clan")
                                                rsp = _v93_build_create_clan_response(
                                                    clean_name, result=result
                                                )
                                                _v48_send_app(
                                                    conn, active_tgame_key, rsp, label,
                                                    "ZN2C_RES_CREATECLAN v94-clan "
                                                    f"cmd=0xA602 result=0x{result:04x} "
                                                    f"name={clean_name!r} "
                                                    f"clan_id=0x{int(local_clan.get('clan_id', 0)):016x}"
                                                )
                                                if valid:
                                                    clan_refresh = _v48_build_playerinfo(
                                                        (app["seq"] + 1) & 0xffffffff,
                                                        uin=LOCAL_UIN,
                                                        tgame_point=local_tp_balance,
                                                        gold_point=local_gp_balance,
                                                        month_point=local_mp_balance,
                                                        cur_role_gid=current_role_gid,
                                                        nickname=local_nickname,
                                                        clan_id=int(local_clan.get("clan_id", 0)),
                                                    )
                                                    _v48_send_app(
                                                        conn, active_tgame_key, clan_refresh, label,
                                                        "ZN2C_NTF_PLAYERINFO v94-clan post-create "
                                                        f"ClanID=0x{int(local_clan.get('clan_id', 0)):016x}"
                                                    )
                                            except Exception as clan_e:
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CREATECLAN v94-clan decode FAILED: "
                                                    f"{type(clan_e).__name__}: {clan_e}; "
                                                    f"body={app['body'].hex()}"
                                                )

                                        elif app["cmd"] == TGAME_ZN_REQ_CLAN_DETAIL:
                                            try:
                                                clan_uin = _v94_parse_clan_detail_request(app["body"])
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CLANDETAIL v94-clan: "
                                                    f"uin={clan_uin} local_clan_id=0x{int(local_clan.get('clan_id', 0)):016x}"
                                                )
                                            except Exception as clan_e:
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CLANDETAIL v94-clan decode FAILED: "
                                                    f"{type(clan_e).__name__}: {clan_e}; body={app['body'].hex()}"
                                                )
                                            _v94_clan_probe_log(label, app["cmd"], app["body"], role_state)

                                        elif app["cmd"] == TGAME_ZN_REQ_CLAN_MEMBERS:
                                            try:
                                                member_uin, is_all = _v94_parse_clan_members_request(
                                                    app["body"]
                                                )
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CLANMEMBERS v94-clan: "
                                                    f"uin={member_uin} is_all={is_all} body={app['body'].hex()}"
                                                )
                                            except Exception as clan_e:
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CLANMEMBERS v94-clan decode probe: "
                                                    f"{type(clan_e).__name__}: {clan_e}; "
                                                    f"body={app['body'].hex()}"
                                                )
                                            _v94_clan_probe_log(
                                                label, app["cmd"], app["body"], role_state
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CLAN_COMMON:
                                            try:
                                                common_uin, clan_id = _v94_parse_clan_common_request(
                                                    app["body"]
                                                )
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CLANCOMMON v94-clan: "
                                                    f"uin={common_uin} clan_id=0x{clan_id:016x}"
                                                )
                                            except Exception as clan_e:
                                                log(
                                                    label,
                                                    "C2ZN_REQ_CLANCOMMON v94-clan decode probe: "
                                                    f"{type(clan_e).__name__}: {clan_e}; "
                                                    f"body={app['body'].hex()}"
                                                )
                                            _v94_clan_probe_log(
                                                label, app["cmd"], app["body"], role_state
                                            )

                                        elif app["cmd"] in (
                                            TGAME_ZN_REQ_PUBLISH_RECRUIT,
                                            TGAME_ZN_REQ_SEARCH_CLAN_BY_NAME,
                                            TGAME_ZN_REQ_RECRUIT_LIST,
                                        ):
                                            _v94_clan_probe_log(
                                                label, app["cmd"], app["body"], role_state
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_ZONECHANNEL_LIST:
                                            main_channel_id = _v91_parse_zone_channel_list_request(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_ZONECHANNEL_LIST v91-shop-lobby: "
                                                f"main_channel_id={main_channel_id} "
                                                f"body={app['body'].hex()}"
                                            )
                                            rsp = _v91_build_zone_channel_list_response(
                                                main_channel_id=main_channel_id
                                            )
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_ZONECHANNEL_LIST v91-shop-lobby "
                                                "cmd=0xA133 zones=1 last=1 "
                                                "subchannels=1 id=1 name='Local Subchannel' "
                                                "players=1/100 endpoint=127.0.0.1:65006"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_MATCHROOMLIST:
                                            req = _v91_parse_match_room_list_request(
                                                app["body"]
                                            )
                                            rooms = _v91_default_match_lobbies()
                                            created_room = role_state.get("v91_created_match_room")
                                            if created_room is not None:
                                                rooms.insert(0, created_room)

                                            total, page = _v91_filter_match_lobbies(req, rooms)
                                            log(
                                                label,
                                                "C2ZN_REQ_MATCHROOMLIST v91-shop-lobby: "
                                                f"mode=0x{req['mode_id']:08x} "
                                                f"map=0x{req['map_id']:04x} "
                                                f"flags=0x{req['flags']:04x} "
                                                f"at_least={req['at_least_count']} "
                                                f"start={req['start_index']} "
                                                f"want={req['room_count']} -> "
                                                f"total={total} returning={len(page)}"
                                            )
                                            rsp = _v91_build_match_room_list_response(total, page)
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_MATCHROOMLIST v91-shop-lobby "
                                                f"cmd=0xA102 result=0x8100 total={total} "
                                                f"count={len(page)} rooms="
                                                + ",".join(
                                                    f"{r['display_id']}:{r['name']}"
                                                    for r in page
                                                )
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_CREATEMATCHROOM:
                                            cr = _v91_parse_create_match_room_request(
                                                app["body"]
                                            )
                                            created_room = {
                                                "room_id": 0x2001,
                                                "display_id": 4,
                                                "qqtalk_room_id": 0,
                                                "name": cr["name"],
                                                "owner_name": local_nickname,
                                                "match_settings_wire": cr["match_settings_wire"],
                                                "mode_id": cr["mode_id"],
                                                "map_id": cr["map_id"],
                                                "fighter_capacity": cr["fighter_capacity"],
                                                "observer_capacity": cr["observer_capacity"],
                                                "fighter_count": 1,
                                                "observer_count": 0,
                                                "password": cr["password"],
                                            }
                                            role_state["v91_created_match_room"] = created_room
                                            log(
                                                label,
                                                "C2ZN_REQ_CREATEMATCHROOM v91-shop-lobby: "
                                                f"name={cr['name']!r} "
                                                f"mode=0x{cr['mode_id']:08x} "
                                                f"map=0x{cr['map_id']:04x} "
                                                f"fighters={cr['fighter_capacity']} "
                                                f"observers={cr['observer_capacity']} "
                                                "stored as lobby DisplayId=4"
                                            )
                                            rsp = _v91_build_create_match_room_response()
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_CREATEMATCHROOM v91-shop-lobby "
                                                "cmd=0xA10B result=0x8100; "
                                                "room will appear on next A100 refresh"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_MAINCHNLLIST:
                                            padding = _v73_parse_main_channel_list_request(
                                                app["body"]
                                            )
                                            log(
                                                label,
                                                "C2ZN_REQ_MAINCHNLLIST v74: "
                                                f"padding=0x{padding:08x}"
                                            )

                                            rsp = _v74_build_main_channel_list_response()
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_MAINCHNLLIST v74 "
                                                "cmd=0xA356 result=0x8100 "
                                                "count=1 id=1 type=Rookie(1) "
                                                "name='Local Channel' "
                                                "players=1/100 dsa=127.0.0.1x3 wire=0100007f"
                                            )

                                        elif app["cmd"] == TGAME_ZN_REQ_STARTROOMALLOC:
                                            ra = _v72_parse_start_room_alloc(app["body"])
                                            log(
                                                label,
                                                "C2ZN_REQ_STARTROOMALLOC v72 decoded: "
                                                f"uin={ra['uin']} "
                                                f"mode=0x{ra['mode_id']:08x} "
                                                f"match_map=0x{ra['match_map_id']:04x} "
                                                f"hard={ra['hard_level']} "
                                                f"map_count={ra['map_count']} "
                                                f"maps={[hex(x) for x in ra['maps']]} "
                                                f"match_raw={ra['match'].hex()} "
                                                f"tail={ra['tail'].hex()}"
                                            )

                                            # First acknowledge the request, then publish the
                                            # queue-entry notification.  This intentionally stops
                                            # short of A3A5 (match found / DS assignment) so the
                                            # next client transition can be observed cleanly.
                                            rsp = _v72_build_start_room_alloc_success()
                                            _v48_send_app(
                                                conn, active_tgame_key, rsp,
                                                label,
                                                "ZN2C_RES_STARTROOMALLOC v72-roomalloc-accept "
                                                "cmd=0xA3A2 result=0x8100"
                                            )

                                            ntf = _v72_build_enter_room_alloc_success()
                                            _v48_send_app(
                                                conn, active_tgame_key, ntf,
                                                label,
                                                "ZN2C_NTF_ENTERROOMALLOC v72-roomalloc-accept "
                                                "cmd=0xA3A1 result=0x8100"
                                            )

                                        else:
                                            log(
                                                label,
                                                "UNHANDLED C2ZN REQUEST "
                                                f"cmd=0x{app['cmd']:04x} "
                                                f"body={app['body'].hex()}"
                                            )
                                    else:
                                        log(
                                            label,
                                            f"Unknown application magic "
                                            f"0x{app['magic']:04x}"
                                        )

                                except Exception as app_e:
                                    log(
                                        label,
                                        f"TGame application parse/dispatch FAILED: "
                                        f"{type(app_e).__name__}: {app_e}; "
                                        f"plain={plain_now.hex()}"
                                    )
                        except Exception as e:
                            log(
                                label,
                                f"TGame mode3 follow-up decode FAILED: {e}; raw={extra.hex()}"
                            )
                    elif mode_now == 4:
                        for line in tgame_decode_cmd09(extra, tgame_mode4_key):
                            log(label, line)
                    else:
                        log(label, f"TGame follow-up received under mode={mode_now}: {extra.hex()}")
                elif role_state.get("session_key"):
                    for line in role_decode_synack(extra, role_state["session_key"]):
                        log(label, line)

    except ConnectionResetError:
        log(label, "Connection reset by client")

    except Exception as e:
        log(
            label,
            f"ERROR: {type(e).__name__}: {e}"
        )

    finally:
        try:
            if locals().get("shop_state_active"):
                current_role_gid = _v87_pick_current_role_gid(
                    locals().get("local_inventory", []),
                    locals().get("current_role_gid", LOCAL_ROLE_GID),
                )
                _v87_save_state(
                    _v87_build_state(
                        locals().get("local_nickname", "LocalPlayer"),
                        locals().get("local_tp_balance", LOCAL_TP_BALANCE),
                        locals().get("local_gp_balance", LOCAL_GP_BALANCE),
                        locals().get("local_mp_balance", LOCAL_MP_BALANCE),
                        current_role_gid,
                        locals().get("next_local_prop_gid", ((LOCAL_UIN & 0xffffffff) << 32) | 4),
                        locals().get("local_inventory", _v87_default_inventory()),
                    ),
                    reason="disconnect",
                )
        except Exception as state_e:
            log("STATE", f"disconnect save FAILED: {type(state_e).__name__}: {state_e}")
        try:
            conn.close()
        except Exception:
            pass


def tdr_u8(v):
    return struct.pack(">B", v)

def tdr_u16(v):
    return struct.pack(">H", v)

def tdr_u32(v):
    return struct.pack(">I", v)

def tdr_string(s):
    b = s.encode("ascii") + b"\x00"
    return tdr_u32(len(b)) + b
def build_dir_root():
    return build_dir_category(
        0x00000000,
        0x00000000,
        "Root",
        0                    # root flag stays 0
    )
def build_dir_leaf():
    node = bytearray()

    node += tdr_u16(1)
    node += tdr_u32(0x01010101)      # LeafID
    node += tdr_u32(0x01010100)      # ParentID

    node += tdr_u32(3)               # Flag: Wnd = 3  <-- IMPORTANT

    node += tdr_string("Assault Fire Local")
    node += tdr_u32(0)               # BitmapMask
    node += tdr_string("tcp://127.0.0.1:65005")
    node += tdr_string("1.0.0.24")
    node += tdr_u32(3)               # CltAttr
    node += tdr_u32(0)               # CltAttr1
    node += tdr_string("")            # AppStaticAttr
    node += tdr_u8(1)                 # Status
    # Dir.dll PlayerSelectedServer treats DynamicInfo.ConnectUrl as:
    #     host:decimal_port;
    # It extracts text before ':' as host and text between ':' and ';' as port.
    # Using "tcp://..." makes the first ':' belong to "tcp:" and leaves the
    # numeric-port parse empty -> atoi("") == 0 -> CreateInitConnectionEx port 0.
    node += tdr_string("127.0.0.1:65005;")
    node += tdr_u16(0)               # AppDynamicAttr

    return bytes(node)

def build_dir_category(cid, pid, name, flag):
    node = bytearray()

    node += tdr_u16(0)
    node += tdr_u32(cid)
    node += tdr_u32(pid)
    node += tdr_u32(flag)

    node += tdr_string(name)
    node += tdr_u32(0)
    node += tdr_u32(0)
    node += tdr_string("")
    node += tdr_u8(1)
    node += tdr_u16(0)

    return bytes(node)
def handle_dir(conn, addr):
    try:
        req = recv_exact(conn, 26, timeout=10.0)

        log(
            "DIR",
            f"Connected from {addr} ({len(req)}B)"
        )

        if len(req) != 26:
            log("DIR", f"Bad request length: {len(req)}")
            return

        log("DIR", f"RX: {req.hex()}")

        # Minimal GetDirTree_Rsp body:
        #
        # u16 NodeCount = 0
        # remaining packing/data fields = 0
        #
        root = build_dir_root()

        category = build_dir_category(
            0x01010100,
            0x00000000,
            "Assault Fire Local",
            3                       # <-- category Flag = 3
        )

        leaf = build_dir_leaf()

        node_data = root + category + leaf

        body = (
            tdr_u16(3) +
            b"\x81" +
            tdr_u16(3) +
            tdr_u16(len(node_data)) +
            node_data
        )

        log(
            "DIR",
            f"Category={len(category)}B Leaf={len(leaf)}B "
            f"NodeData={len(node_data)}B"
        )

        # Copy request header so ServiceId, Seq, ISP, Province
        # stay exactly what the client sent.
        resp = bytearray(req)

        # BodyLen
        resp[4:8] = len(body).to_bytes(4, "big")

        # MsgID:
        # 0x1771 = GetDirTree_Req
        # 0x1772 = GetDirTree_Rsp
        resp[12:16] = (0x1772).to_bytes(4, "big")

        # ErrorCode = success
        resp[20:24] = (0).to_bytes(4, "big")

        packet = bytes(resp) + body

        log(
            "DIR",
            f"TX ({len(packet)}B): {_short_hex(packet)}"
        )

        conn.sendall(packet)

        # Keep it alive briefly so we can see what client does next.
        conn.settimeout(5.0)

        try:
            follow = conn.recv(4096)

            if follow:
                log(
                    "DIR",
                    f"FOLLOW-UP ({len(follow)}B): {follow.hex()}"
                )
            else:
                log("DIR", "Client closed connection")

        except socket.timeout:
            log("DIR", "No follow-up within 5 sec")

    except Exception as e:
        log("DIR", f"ERROR: {type(e).__name__}: {e}")

    finally:
        try:
            conn.close()
        except Exception:
            pass
# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

def listen_on_port(port, label):
    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    s.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    s.bind(
        ("0.0.0.0", port)
    )

    s.listen(10)

    log(
        label,
        f"Listening on port {port}"
    )

    while True:
        try:
            conn, addr = s.accept()

            if label == "VERSION":
                target = handle_version
                args = (conn, addr)

            elif label == "AUTH":
                target = handle_auth
                args = (conn, addr)

            elif label == "DIR":
                target = handle_dir
                args = (conn, addr)

            else:
                target = handle_placeholder
                args = (conn, addr, label)

            threading.Thread(
                target=target,
                args=args,
                daemon=True
            ).start()

        except Exception as e:
            log(
                label,
                f"accept error: {e}"
            )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

# v85 structural/semantic self-tests; fail at startup instead of gameplay.
import datetime as _v83_datetime_module
_v83_test_dt = _v83_datetime_module.datetime(2026, 9, 19, 6, 11, 12)
_v83_test_flow = _v81_pack_moneyflow_record(
    MONEYTYPE_GP, -21000, 79000, dt=_v83_test_dt
)
assert len(_v83_test_flow) == 26
assert _v83_test_flow[8:16] == bytes.fromhex("07ea091300060b0c")
assert _v83_test_flow[16] == MONEYTYPE_GP
assert _v83_test_flow[17:21] == struct.pack(">i", -21000)
assert _v83_test_flow[21:25] == struct.pack(">i", 79000)
assert _v83_test_flow[25] == MONEYREASON_BUY

# Money-flow packet serializer is self-tested and enabled in v90-shopfix.
_v85_test_moneyflow_pkt = _v81_build_moneyflow_notification([_v83_test_flow])
assert len(_v85_test_moneyflow_pkt) == 38
assert _v85_test_moneyflow_pkt[8:12] == bytes.fromhex("00000001")
assert _v85_test_moneyflow_pkt[12:] == _v83_test_flow

_v91_test_req = {
    "mode_id": 0,
    "map_id": 0,
    "flags": 0,
    "at_least_count": 0,
    "start_index": 0,
    "room_count": 20,
}
_v91_test_total, _v91_test_rooms = _v91_filter_match_lobbies(
    _v91_test_req, _v91_default_match_lobbies()
)
assert _v91_test_total == 3 and len(_v91_test_rooms) == 3
_v91_test_lobby_pkt = _v91_build_match_room_list_response(
    _v91_test_total, _v91_test_rooms
)
assert _v91_test_lobby_pkt[0:2] == bytes.fromhex("3243")
assert _v91_test_lobby_pkt[2:4] == bytes.fromhex("a102")
assert _v91_test_lobby_pkt[8:14] == bytes.fromhex("810000030003")
_v91_test_zone_pkt = _v91_build_zone_channel_list_response(1)
assert _v91_test_zone_pkt[2:4] == bytes.fromhex("a133")

# v92 social serializer sanity checks.  These do not contact any service.
_v92_test_fs_req = _v92_parse_friend_status_request(bytes.fromhex("00000001"))
assert _v92_test_fs_req == {"count": 0, "type": 1, "uins": []}
_v92_test_fs_rsp = _v92_build_friend_status_response(1, [], False)
assert _v92_test_fs_rsp[:4] == bytes.fromhex("3243a304")
assert _v92_test_fs_rsp[8:] == bytes.fromhex("00000001")
_v92_test_inv = _v92_build_friend_invite()
assert _v92_test_inv[:4] == bytes.fromhex("3243a306")
_v92_test_chat_body = (
    _v48_u16(0x0100)
    + _v48_u64(LOCAL_FRIEND_UIN)
    + _v50_geo_tdr_string(LOCAL_FRIEND_NICKNAME, 32)
    + _v50_geo_tdr_string("ping", 128)
    + _v48_u8(0)
)
_v92_test_chat = _v92_parse_chat_p2p_request(_v92_test_chat_body)
assert _v92_test_chat["recipient_uin"] == LOCAL_FRIEND_UIN
assert _v92_test_chat["message"] == "ping"
_v92_test_ntf = _v92_build_chat_p2p_notify(0x0100, "pong")
assert _v92_test_ntf[:4] == bytes.fromhex("3243a406")

# v94 clan/persistence sanity checks. Complex ClanDetailedInfo/MemberInfo
# responses remain intentionally gated on a live PH capture rather than guesses.
_v94_test_create_body = (
    _v48_u64(LOCAL_UIN)
    + _v50_geo_tdr_string("LocalClan", MAX_CLAN_NAME_LEN)
    + _v50_geo_tdr_string("1234", MAX_CLAN_SAFECODE_LEN)
    + _v50_geo_tdr_string("local@example.invalid", 256)
)
_v94_test_create = _v94_parse_create_clan_request(_v94_test_create_body)
assert _v94_test_create["uin"] == LOCAL_UIN
assert _v94_test_create["clan_name"] == "LocalClan"
assert _v94_parse_clan_detail_request(_v48_u64(LOCAL_UIN)) == LOCAL_UIN
assert _v94_parse_clan_members_request(_v48_u64(LOCAL_UIN) + _v48_u8(1)) == (LOCAL_UIN, 1)
assert _v94_parse_clan_common_request(_v48_u64(LOCAL_UIN) + _v48_u64(LOCAL_CLAN_ID)) == (LOCAL_UIN, LOCAL_CLAN_ID)
_v94_test_create_rsp = _v93_build_create_clan_response("LocalClan")
assert _v94_test_create_rsp[:4] == bytes.fromhex("3243a602")
assert _v94_test_create_rsp[8:10] == bytes.fromhex("8400")
_v94_test_verify_rsp = _v93_build_verify_clan_name_response("LocalClan")
assert _v94_test_verify_rsp[:4] == bytes.fromhex("3243ab03")

print("[BOOT] BUILD=v94-clan-persistence v93 clan + persisted ClanID + corrected clan request shapes")
print(f"[BOOT] Player state: {PLAYER_STATE_PATH}")
print(f"[BOOT] Clan state: {CLAN_STATE_PATH}")
print(f"[BOOT] MoneyFlow notifications: {'ON' if ENABLE_MONEYFLOW_NOTIFICATIONS else 'OFF'}")
print(f"[BOOT] Wallet update reasons: BUY=0x{UPDATE_REASON_BUY:02X} TPBALANCE=0x{UPDATE_REASON_TP_BALANCE:02X}")
print(f"[BOOT] MoneyFlow: cmd=0x{TGAME_ZN_NTF_MONEYFLOW:04X} BUY reason=0x{MONEYREASON_BUY:02X}")
print("[BOOT] Lobby browser: 3 synthetic Survival rooms + client-created room slot; A132/A133 + A100/A102 enabled")
print("[BOOT] Friends: A303/A304 status + A305-A308 add/accept + A309/A30A delete + LocalFriend invite")
print("[BOOT] Friend chat: A405 request -> A406 LocalFriend echo bot (plain-text ChatPkgCount=0)")
print("[BOOT] Clan v94: A601/AB02 now include leading UIN; AA05=u64 UIN; AA07=u64 UIN+IsAll; AA09=u64 UIN+u64 ClanID")
print("[BOOT] Clan v94: membership persists to assaultfire_clan_state.json and PlayerInfo.ClanID is authoritative; post-create A005 refresh enabled")

if __name__ == "__main__":
    print(
        f"[BOOT] VERSION response: "
        f"{len(VERSION_RESPONSE)}B",
        flush=True
    )

    print(
        f"[BOOT] DH prime: "
        f"{PRIME_BYTES.hex()}",
        flush=True
    )

    print(
        f"[BOOT] IV: "
        f"{IV.hex()}",
        flush=True
    )

    threading.Thread(
        target=listen_on_port,
        args=(9060, "VERSION"),
        daemon=True
    ).start()

    threading.Thread(
        target=listen_on_port,
        args=(8000, "AUTH"),
        daemon=True
    ).start()

    threading.Thread(
        target=listen_on_port,
        args=(9010, "DIR"),
        daemon=True
    ).start()

    threading.Thread(
        target=listen_on_port,
        args=(65005, "ROLE"),
        daemon=True
    ).start()

    threading.Thread(
        target=listen_on_port,
        args=(TGAME_ZONE_PORT, "ZONE"),
        daemon=True
    ).start()

    print(
        "[MAIN] All listeners running.",
        flush=True
    )

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print(
            "\n[MAIN] Shutting down.",
            flush=True
        )