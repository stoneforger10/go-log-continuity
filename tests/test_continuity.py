import ast
import base64
from functools import lru_cache
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts/GoLogContinuity.py"
ANCHOR = (ROOT / "fixtures/anchor.note").read_text(encoding="utf-8")
SIZE = 71228729


@pytest.fixture
def core():
    module = ast.parse(SOURCE.read_text(encoding="utf-8"))
    module.body = [node for node in module.body if not isinstance(node, ast.ClassDef)
                   and not (isinstance(node, ast.ImportFrom) and node.module == "genlayer")]
    ns = {}
    exec(compile(module, str(SOURCE), "exec"), ns)
    return ns


@lru_cache(maxsize=None)
def reference_root(start, end):
    if end == start + 1:
        return hashlib.sha256(b"\x00" + start.to_bytes(8, "big")).digest()
    midpoint = start + 2 ** ((end - start - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + reference_root(start, midpoint) + reference_root(midpoint, end)).digest()


def fixture_head(size):
    return {"size": size, "root": reference_root(0, size).hex()}


def test_go_signature_and_wrong_signed_content(core):
    assert core["verify_note"](ANCHOR)["size"] == SIZE
    for modified in (
        ANCHOR.replace(str(SIZE), str(SIZE + 1)),
        ANCHOR.replace("Il1C", "Al1C"),
        ANCHOR.replace("sum.golang.org Az3g", "sum.golang.org Bz3g"),
        ANCHOR.replace("sum.golang.org Az3g", "example.com Az3g"),
        ANCHOR + "\n",
    ):
        with pytest.raises(ValueError):
            core["verify_note"](modified)


def test_rfc8032_vector_and_noncanonical_scalar(core, monkeypatch):
    key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                              "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    monkeypatch.setitem(core, "PUBLIC_KEY", key)
    assert core["verify_signature"](b"", signature)
    assert not core["verify_signature"](b"\x00", signature)
    scalar = int.from_bytes(signature[32:], "little") + core["L"]
    assert not core["verify_signature"](b"", signature[:32] + scalar.to_bytes(32, "little"))


def test_aligned_frontiers_rebuild_both_roots(core):
    for end in range(2, 33):
        for cut in range(1, end):
            old, new = fixture_head(cut), fixture_head(end)
            intervals = core["cover"](0, cut) + core["cover"](cut, end)
            frontier = [reference_root(start, start + 2**level).hex() for start, level in intervals]
            core["validate_frontier"](old, new, frontier)
            for i in (0, len(frontier) - 1):
                bad = frontier.copy()
                bad[i] = "00" * 32
                with pytest.raises(ValueError, match="does not preserve"):
                    core["validate_frontier"](old, new, bad)


def test_rejects_rollback_fork_and_trailing_nodes(core):
    old, new = fixture_head(3), fixture_head(7)
    with pytest.raises(ValueError, match="rollback"):
        core["validate_frontier"](new, old, [])
    with pytest.raises(ValueError, match="same-size"):
        core["validate_frontier"](old, {**old, "root": "0" * 64}, [])
    core["validate_frontier"](old, old, [])
    with pytest.raises(ValueError, match="proof length"):
        core["validate_frontier"](old, new, ["00" * 32] * 15)


def test_validators_fetch_tiles_again_and_reject_wrong_output(core, monkeypatch):
    old, new = fixture_head(511), fixture_head(1031)
    old["note"], new["note"] = "mock old", "mock new"
    calls = []

    def get(url):
        calls.append(url)
        if url.endswith("/latest"):
            return SimpleNamespace(status=200, body=b"mock new")
        pieces = url.split("/tile/8/")[1].split("/")
        level = int(pieces[0])
        digits, marker, tail = "/".join(pieces[1:]).partition(".p/")
        number = int(digits.replace("x", "").replace("/", ""))
        width = int(tail) if marker else 256
        begin, step = number * 256, 1 << (level * 8)
        tile = b"".join(reference_root(i * step, (i + 1) * step) for i in range(begin, begin + width))
        return SimpleNamespace(status=200, body=tile)

    def run(leader, validator):
        result = leader()
        leader_tiles = calls[1:]
        assert calls[0].endswith("/latest")
        assert validator(SimpleNamespace(calldata=result))
        assert calls[1 + len(leader_tiles):] == leader_tiles
        forged = {**result, "frontier": ["00" * 32, *result["frontier"][1:]]}
        assert not validator(SimpleNamespace(calldata=forged))
        return result

    monkeypatch.setitem(core, "verify_note", lambda note: {"mock new": new}[note])
    core["gl"] = SimpleNamespace(
        nondet=SimpleNamespace(web=SimpleNamespace(get=get)),
        vm=SimpleNamespace(Return=SimpleNamespace, UserError=ValueError, run_nondet_unsafe=run),
    )
    head, proof = core["acquire"](old)
    assert head == new
    assert len(proof) > 1 and core["tile_number"](123456789) == "x123/x456/789"
    assert any("/8/1/" in url for url in calls)
    assert any(".p/" in url for url in calls)


def test_signed_anchor_and_same_size_sync_in_direct_vm(direct_vm, direct_deploy):
    contract = direct_deploy(str(SOURCE), base64.b64encode(ANCHOR.encode()).decode())
    before = contract.head()
    assert before["size"] == SIZE and before["note"] == ANCHOR
    direct_vm.mock_web(r"https://sum\.golang\.org/latest", {
        "response": {"status": 200, "headers": {}, "body": ANCHOR.encode()}, "method": "GET",
    })
    assert contract.sync() == SIZE
    assert contract.head() == before
    with direct_vm.expect_revert("Unknown extension"):
        contract.extension(SIZE)
