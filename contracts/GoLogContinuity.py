# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import base64
import hashlib
import json
import re


SERVER = "https://sum.golang.org"
KEY_HINT = bytes.fromhex("033de0ae")
PUBLIC_KEY = base64.b64decode("Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8=")[1:]
SIZE_LIMIT = 1 << 40
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_MINUS_ONE = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)
BASE_POINT = bytes.fromhex("58" + "66" * 31)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def checked_base64(value):
    decoded = base64.b64decode(value, validate=True)
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("Noncanonical base64")
    return decoded


def decode_point(encoded):
    number = int.from_bytes(encoded, "little")
    sign, y = number >> 255, number & ((1 << 255) - 1)
    if len(encoded) != 32 or y >= P:
        raise ValueError("Noncanonical Ed25519 point")
    squared = y * y % P
    x_squared = (squared - 1) * pow((D * squared + 1) % P, P - 2, P) % P
    x = pow(x_squared, (P + 3) // 8, P)
    if (x * x - x_squared) % P:
        x = x * SQRT_MINUS_ONE % P
    if (x * x - x_squared) % P or (x == 0 and sign):
        raise ValueError("Invalid Ed25519 point")
    if x % 2 != sign:
        x = P - x
    return x, y, 1, x * y % P


def point_add(left, right):
    # Complete extended Edwards addition, RFC 8032 section 5.1.4.
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % P, g * h % P, f * g % P, e * h % P


def scalar_multiply(point, scalar):
    result = IDENTITY
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def verify_signature(message, signature):
    if len(signature) != 64:
        return False
    r = signature[:32]
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        return False
    try:
        challenge = int.from_bytes(hashlib.sha512(r + PUBLIC_KEY + message).digest(), "little") % L
        left = scalar_multiply(decode_point(BASE_POINT), scalar)
        right = point_add(decode_point(r), scalar_multiply(decode_point(PUBLIC_KEY), challenge))
        # Strict group equation. The pinned Go public key is a prime-order point.
        return (left[0] * right[2] - right[0] * left[2]) % P == 0 and (
            left[1] * right[2] - right[1] * left[2]) % P == 0
    except ValueError:
        return False


def verify_note(note):
    if not isinstance(note, str) or len(note) > 300:
        raise ValueError("Invalid checkpoint length")
    match = re.fullmatch(
        r"go\.sum database tree\n([1-9][0-9]{0,12})\n([A-Za-z0-9+/]{43}=)\n\n"
        r"\u2014 sum\.golang\.org ([A-Za-z0-9+/]{91}=)\n", note,
    )
    if match is None:
        raise ValueError("Invalid Go signed note")
    size_text, root_text, sig_text = match.groups()
    size = int(size_text)
    signature = checked_base64(sig_text)
    body = f"go.sum database tree\n{size_text}\n{root_text}\n".encode("ascii")
    if size >= SIZE_LIMIT or signature[:4] != KEY_HINT or not verify_signature(body, signature[4:]):
        raise ValueError("Untrusted checkpoint signature or size")
    return {"size": size, "root": checked_base64(root_text).hex(), "note": note}


def cover(start, end):
    """Canonical aligned power-of-two cover of a half-open range."""
    pieces = []
    while start < end:
        width = 1 << ((end - start).bit_length() - 1)
        if start:
            width = min(width, start & -start)
        pieces.append((start, width.bit_length() - 1))
        start += width
    return pieces


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def tree_root(pieces, values):
    stack = []
    for (_, level), value in zip(pieces, values):
        while stack and stack[-1][0] == level:
            _, left = stack.pop()
            value = node_hash(left, value)
            level += 1
        stack.append((level, value))
    root = stack[-1][1]
    for _, value in reversed(stack[:-1]):
        root = node_hash(value, root)
    return root.hex()


def validate_frontier(old, new, frontier):
    if new["size"] < old["size"]:
        raise ValueError("Checkpoint rollback")
    if new["size"] == old["size"]:
        if new["root"] != old["root"] or frontier != []:
            raise ValueError("Conflicting same-size checkpoint")
        return
    prefix = cover(0, old["size"])
    tail = cover(old["size"], new["size"])
    if not isinstance(frontier, list) or len(frontier) != len(prefix) + len(tail):
        raise ValueError("Invalid consistency proof length")
    if any(not isinstance(x, str) or not re.fullmatch(r"[0-9a-f]{64}", x) for x in frontier):
        raise ValueError("Invalid consistency hash")
    nodes = [bytes.fromhex(x) for x in frontier]
    if tree_root(prefix, nodes[:len(prefix)]) != old["root"] or tree_root(prefix + tail, nodes) != new["root"]:
        raise ValueError("Checkpoint does not preserve the existing prefix")


def tile_number(number):
    parts = [f"{number % 1000:03d}"]
    number //= 1000
    while number:
        parts.append(f"x{number % 1000:03d}")
        number //= 1000
    return "/".join(reversed(parts))


def read_tile(level, number, width):
    path = f"{SERVER}/tile/8/{level}/{tile_number(number)}"
    partial = f".p/{width}" if width < 256 else ""
    response = gl.nondet.web.get(path + partial)
    if response.status == 404 and partial:
        response = gl.nondet.web.get(path)
        if response.status == 200 and len(response.body) == 8192:
            return response.body[:width * 32]
    if response.status != 200 or len(response.body) != width * 32:
        raise ValueError("Invalid checksum log tile")
    return response.body


def fetch_frontier(old, new):
    if new["size"] <= old["size"]:
        return []
    tiles, frontier = {}, []
    for start, level in cover(0, old["size"]) + cover(old["size"], new["size"]):
        tile_level, local_level = divmod(level, 8)
        column = start >> (tile_level * 8)
        tile, offset = divmod(column, 256)
        key = (tile_level, tile)
        if key not in tiles:
            if len(tiles) >= 32:
                raise ValueError("Consistency proof exceeds the tile limit")
            width = min(256, (new["size"] >> (tile_level * 8)) - tile * 256)
            tiles[key] = read_tile(tile_level, tile, width)
        data = tiles[key][offset * 32:(offset + (1 << local_level)) * 32]
        if len(data) != (1 << local_level) * 32:
            raise ValueError("Incomplete tile subtree")
        nodes = [data[i:i + 32] for i in range(0, len(data), 32)]
        while len(nodes) > 1:
            nodes = [node_hash(nodes[i], nodes[i + 1]) for i in range(0, len(nodes), 2)]
        frontier.append(nodes[0].hex())
    return frontier


def acquire(old):
    def evaluate():
        try:
            response = gl.nondet.web.get(SERVER + "/latest")
            if response.status != 200 or not 1 <= len(response.body) <= 512:
                raise ValueError("Invalid checkpoint response")
            new = verify_note(response.body.decode("utf-8"))
            frontier = fetch_frontier(old, new)
            validate_frontier(old, new, frontier)
            return {"note": new["note"], "frontier": frontier}
        except Exception:
            raise gl.vm.UserError("[LOG_ERROR] Signed checkpoint or consistency evidence unavailable or invalid")

    def validator(result):
        if not isinstance(result, gl.vm.Return):
            return False
        try:
            candidate = result.calldata
            if not isinstance(candidate, dict) or set(candidate) != {"note", "frontier"}:
                return False
            new = verify_note(candidate["note"])
            independent = fetch_frontier(old, new)
            validate_frontier(old, new, independent)
            return candidate["frontier"] == independent
        except Exception:
            return False

    result = gl.vm.run_nondet_unsafe(evaluate, validator)
    try:
        if not isinstance(result, dict) or set(result) != {"note", "frontier"}:
            raise ValueError("Invalid consensus result")
        new = verify_note(result["note"])
        validate_frontier(old, new, result["frontier"])
    except Exception:
        raise gl.vm.UserError("[LOG_ERROR] Invalid consensus evidence")
    return new, result["frontier"]


class GoLogContinuity(gl.Contract):
    checkpoint: str
    extensions: TreeMap[str, str]

    def __init__(self, anchor_base64: str):
        if not 1 <= len(anchor_base64) <= 512:
            raise gl.vm.UserError("[EXPECTED] Invalid signed Go checksum log anchor")
        try:
            anchor = verify_note(checked_base64(anchor_base64).decode("utf-8"))
        except Exception:
            raise gl.vm.UserError("[EXPECTED] Invalid signed Go checksum log anchor")
        self.checkpoint = canonical(anchor)

    @gl.public.view
    def head(self) -> dict:
        return json.loads(self.checkpoint)

    @gl.public.write
    def sync(self) -> int:
        old = self.head()
        new, frontier = acquire(old)
        if new["size"] > old["size"]:
            self.extensions[str(new["size"])] = canonical({"old": old, "new": new, "frontier": frontier})
            self.checkpoint = canonical(new)
        return new["size"]

    @gl.public.view
    def extension(self, size: int) -> dict:
        key = str(size)
        if key not in self.extensions:
            raise gl.vm.UserError("[EXPECTED] Unknown extension")
        return json.loads(self.extensions[key])
