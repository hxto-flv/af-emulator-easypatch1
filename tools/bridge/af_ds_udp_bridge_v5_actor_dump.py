# Stable Assault Fire PH DS bridge (v5)
# Transparent AF wire relay for local preservation testing.
# Relays 0.0.0.0:65008 <-> 127.0.0.1:7777 and writes diagnostic actor payload logs.
# Do not expose the development listener to untrusted networks.

import socket
import struct
import select
import time
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 65008
TARGET = ("127.0.0.1", 7777)

# The current AFDEV listen server selected the dynamic all-zero 128-bit DS key.
# This key is used ONLY to decode a diagnostic copy.  Packets are relayed
# byte-for-byte unchanged.
DECODE_KEY = b"\x00" * 16

SIO_UDP_CONNRESET = 0x9800000C

# v5 diagnostic actor-channel capture.  The relay itself remains transparent:
# datagrams are still forwarded byte-for-byte unchanged.
ACTOR_DUMP_PATH = Path(__file__).with_name("af_actor_payloads.log")
ACTOR_SEEN = {}
CH2_DUMP_LIMIT = 12
OTHER_CHANNEL_EARLY_DUMP_LIMIT = 2


def append_actor_dump(line):
    try:
        with ACTOR_DUMP_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as exc:
        print(f"[ACTOR-DUMP] write failed: {exc}")


def actor_payload_detail(direction, packet_id, ctl, op, cl, rel, ch, seq, ctype, nbits, payload):
    """Return/log payload details only when diagnostically useful.

    Always dump channel opens (the key event for actor creation), and also the
    first few messages on every non-control channel.  Channel 2 gets a larger
    early window because the real AF DS trace shows the initial two-way player/
    connection exchange there.

    UE3 bunch payloads are bit-packed.  payload.hex() contains zero padding in
    the unused high bits of the last byte; nbits is authoritative.
    """
    key = (direction, ch)
    count = ACTOR_SEEN.get(key, 0) + 1
    ACTOR_SEEN[key] = count

    limit = CH2_DUMP_LIMIT if ch == 2 else OTHER_CHANNEL_EARLY_DUMP_LIMIT
    reason = None
    if op:
        reason = "OPEN"
    elif count <= limit:
        reason = "EARLY"

    if reason is None:
        return ""

    tail_bits = nbits & 7
    if tail_bits == 0 and nbits:
        tail_bits = 8
    detail = (
        f"ACTOR_{reason}#{count} dumped "
        f"payload_bytes={len(payload)} valid_bits={nbits} "
        f"last_byte_valid_bits={tail_bits}"
    )

    append_actor_dump(
        f"{time.time():.6f} {direction} packet={packet_id} ch={ch} seq={seq} "
        f"ctl={ctl} open={op} close={cl} rel={rel} type={ctype} "
        f"nbits={nbits} bytes={len(payload)} reason={reason} "
        f"payload={payload.hex()}"
    )
    return detail


def disable_udp_connreset(sock):
    try:
        sock.ioctl(SIO_UDP_CONNRESET, False)
        return True
    except Exception:
        return False


def decrypt_wire(wire):
    if len(wire) < 20:
        raise ValueError("short DS datagram")
    n = struct.unpack_from("<I", wire, 0)[0]
    enc = wire[4:]
    if len(enc) % 16:
        raise ValueError("ciphertext not block aligned")
    dec = Cipher(
        algorithms.AES(DECODE_KEY), modes.ECB(),
        backend=default_backend()
    ).decryptor()
    padded = dec.update(enc) + dec.finalize()
    if n > len(padded):
        raise ValueError(f"clear length {n} > decrypted {len(padded)}")
    return padded[:n]


def bits_from_bytes(data):
    return [(b >> bit) & 1 for b in data for bit in range(8)]


def bits_to_bytes(bits):
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def read_bits(bits, pos, count):
    if pos + count > len(bits):
        raise ValueError("bitstream truncated")
    v = 0
    for i in range(count):
        v |= bits[pos + i] << i
    return v, pos + count


def read_int(bits, pos, maximum):
    v = 0
    mask = 1
    while mask < maximum:
        b, pos = read_bits(bits, pos, 1)
        if b:
            v |= mask
        mask <<= 1
    return v, pos


def parse_packet(plain):
    bits = bits_from_bytes(plain)
    stop = next(
        (i for i in range(len(bits)-1, -1, -1) if bits[i]), None
    )
    if stop is None:
        raise ValueError("no stop bit")

    pos = 0
    packet_id, pos = read_int(bits, pos, 16384)
    records = []

    while pos < stop:
        is_ack, pos = read_bits(bits, pos, 1)
        if is_ack:
            aid, pos = read_int(bits, pos, 16384)
            records.append(("ACK", aid))
            continue

        ctl, pos = read_bits(bits, pos, 1)
        op = cl = 0
        if ctl:
            op, pos = read_bits(bits, pos, 1)
            cl, pos = read_bits(bits, pos, 1)

        rel, pos = read_bits(bits, pos, 1)
        ch, pos = read_int(bits, pos, 1023)

        seq = 0
        if rel:
            seq, pos = read_int(bits, pos, 1024)

        ctype = 0
        if rel or op:
            ctype, pos = read_int(bits, pos, 8)

        nbits, pos = read_int(bits, pos, 4096)
        if pos + nbits > stop:
            raise ValueError("bunch overrun")
        payload = bits_to_bytes(bits[pos:pos+nbits])
        pos += nbits

        records.append((
            "BUNCH", ctl, op, cl, rel, ch, seq, ctype, nbits, payload
        ))

    return packet_id, records


CONTROL_NAMES = {
    0: "NMT_Hello",
    1: "NMT_Welcome",
    3: "NMT_Challenge",
    4: "NMT_Netspeed",
    5: "NMT_Login",
    6: "NMT_Failure",
    9: "NMT_Join",
}


def decode_fstring(buf, off=0):
    if off + 4 > len(buf):
        return None, off
    n = struct.unpack_from("<i", buf, off)[0]
    off += 4
    if n == 0:
        return "", off
    if n > 0:
        end = off + n
        if end > len(buf):
            return None, off
        raw = buf[off:end]
        return raw.rstrip(b"\x00").decode("latin1", "replace"), end
    count = -n
    end = off + count * 2
    if end > len(buf):
        return None, off
    raw = buf[off:end]
    return raw.decode("utf-16le", "replace").rstrip("\x00"), end


def summarize(direction, wire):
    try:
        plain = decrypt_wire(wire)
        packet_id, records = parse_packet(plain)
    except Exception as exc:
        return f"{direction} decode-error={exc}"

    parts = [f"{direction} PacketId={packet_id} clear={len(plain)}B"]
    for r in records:
        if r[0] == "ACK":
            parts.append(f"ACK({r[1]})")
            continue

        _, ctl, op, cl, rel, ch, seq, ctype, nbits, payload = r
        base = (
            f"BUNCH(ch={ch} seq={seq} ctl={ctl} open={op} "
            f"close={cl} rel={rel} type={ctype} bits={nbits})"
        )

        if ch == 0 and payload:
            msg = payload[0]
            name = CONTROL_NAMES.get(msg, f"NMT_{msg}")
            detail = name

            if msg == 3 and len(payload) >= 5:
                challenge_u32 = struct.unpack_from("<I", payload, 1)[0]
                s, _ = decode_fstring(payload, 5)
                detail += f"(u32=0x{challenge_u32:08X}, str={s!r})"

            elif msg == 6:
                s, _ = decode_fstring(payload, 1)
                detail += f"({s!r})"

            elif msg == 1:
                level, p = decode_fstring(payload, 1)
                game, _ = decode_fstring(payload, p)
                detail += f"(Level={level!r}, Game={game!r})"

            elif msg == 4 and len(payload) >= 5:
                rate = struct.unpack_from("<I", payload, 1)[0]
                detail += f"(rate={rate})"

            parts.append(base + " " + detail)
        elif ch != 0:
            detail = actor_payload_detail(
                direction, packet_id, ctl, op, cl, rel, ch, seq, ctype,
                nbits, payload
            )
            parts.append(base + ((" " + detail) if detail else ""))
        else:
            parts.append(base)

    return " | ".join(parts)


def main():
    append_actor_dump("\n=== NEW BRIDGE-v5 SESSION %.6f ===" % time.time())
    cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cs.bind((LISTEN_IP, LISTEN_PORT))
    disable_udp_connreset(cs)

    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ss.bind(("127.0.0.1", 0))
    disable_udp_connreset(ss)

    print(f"[BRIDGE-v5] transparent wire relay {LISTEN_IP}:{LISTEN_PORT} <-> {TARGET[0]}:{TARGET[1]}")
    print(f"[BRIDGE-v5] diagnostic decode key = {DECODE_KEY.hex()}")
    print(f"[BRIDGE-v5] upstream local = {ss.getsockname()}")
    print(f"[BRIDGE-v5] actor payload log = {ACTOR_DUMP_PATH}")
    print("[BRIDGE-v5] waiting for client...")

    client = None
    c2s = s2c = 0

    while True:
        try:
            readable, _, _ = select.select([cs, ss], [], [], 1.0)
        except OSError as exc:
            print(f"[select] {exc}")
            time.sleep(0.05)
            continue

        for sock in readable:
            if sock is cs:
                try:
                    wire, addr = cs.recvfrom(65535)
                except ConnectionResetError as exc:
                    print(f"[C->S] UDP reset ignored: {exc}")
                    continue
                client = addr
                c2s += 1
                print(f"[C->S #{c2s}] {summarize('C->S', wire)}")
                try:
                    ss.sendto(wire, TARGET)
                except OSError as exc:
                    print(f"[C->S #{c2s}] sendto failed: {exc}")

            else:
                try:
                    wire, src = ss.recvfrom(65535)
                except ConnectionResetError as exc:
                    print(f"[S->C] UDP reset ignored: {exc}")
                    continue
                if src != TARGET:
                    continue
                s2c += 1
                print(f"[S->C #{s2c}] {summarize('S->C', wire)}")
                if client:
                    try:
                        cs.sendto(wire, client)
                    except ConnectionResetError as exc:
                        print(f"[S->C #{s2c}] client reset ignored: {exc}")
                    except OSError as exc:
                        print(f"[S->C #{s2c}] sendto client failed: {exc}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[BRIDGE-v5] stopped")