from __future__ import annotations

import hashlib
import math
import random
import time
from dataclasses import dataclass


TRANSFER_TYPE_COT = 0x00
TRANSFER_TYPE_FILE = 0x01
TRANSFER_TYPE_COT_ASCII = 0x30
TRANSFER_TYPE_FILE_ASCII = 0x31

TYPE_DATA = 0x01
TYPE_COMPLETE = 0x02
TYPE_NEED_MORE = 0x03

MAGIC = b"FTN"
DATA_HEADER_SIZE = 11
ACK_PACKET_SIZE = 19
MAX_PAYLOAD_SIZE = 220


class JavaRandom:
    _MASK = (1 << 48) - 1
    _MULT = 25214903917
    _ADD = 11

    def __init__(self, seed: int):
        self.seed = (seed ^ 0x5DEECE66D) & self._MASK

    def _next(self, bits: int) -> int:
        self.seed = (self.seed * self._MULT + self._ADD) & self._MASK
        return self.seed >> (48 - bits)

    def next_double(self) -> float:
        return ((self._next(26) << 27) + self._next(27)) / float(1 << 53)

    def next_int(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        if (bound & (bound - 1)) == 0:
            return (bound * self._next(31)) >> 31
        while True:
            bits = self._next(31)
            value = bits % bound
            # Java's Random.nextInt(bound) relies on 32-bit signed overflow here.
            # In Python ints do not overflow, so emulate the acceptance check explicitly.
            if (bits - value + (bound - 1)) < (1 << 31):
                return value


def java_string_hashcode(value: str) -> int:
    h = 0
    for ch in value:
        h = (31 * h + ord(ch)) & 0xFFFFFFFF
    return h if h < 0x80000000 else h - 0x100000000


def compute_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:8]


def is_fountain_packet(data: bytes) -> bool:
    return len(data) >= 3 and data[:3] == MAGIC


def get_packet_type(data: bytes) -> int:
    if not is_fountain_packet(data) or len(data) < 7:
        return 0
    if len(data) == ACK_PACKET_SIZE:
        return data[6]
    if len(data) >= DATA_HEADER_SIZE:
        return TYPE_DATA
    return 0


def generate_transfer_id(sender_node_id: str | None) -> int:
    node_hash = java_string_hashcode(sender_node_id or "")
    now_low = int(time.time() * 1000) & 0xFFFF
    value = (node_hash ^ random.getrandbits(32) ^ now_low) & 0xFFFFFF
    return value or 1


def adaptive_overhead(source_block_count: int) -> float:
    if source_block_count <= 10:
        return 0.50
    if source_block_count <= 50:
        return 0.25
    return 0.15


@dataclass(slots=True)
class EncodedBlock:
    seed: int
    source_block_count: int
    total_length: int
    source_indices: list[int]
    payload: bytes


@dataclass(slots=True)
class DataBlock:
    transfer_id: int
    seed: int
    source_block_count: int
    total_length: int
    payload: bytes

    def to_bytes(self) -> bytes:
        return b"".join(
            [
                MAGIC,
                bytes(
                    [
                        (self.transfer_id >> 16) & 0xFF,
                        (self.transfer_id >> 8) & 0xFF,
                        self.transfer_id & 0xFF,
                    ]
                ),
                self.seed.to_bytes(2, "big"),
                bytes([self.source_block_count & 0xFF]),
                self.total_length.to_bytes(2, "big"),
                self.payload,
            ]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "DataBlock | None":
        if not is_fountain_packet(data) or len(data) < DATA_HEADER_SIZE:
            return None
        return cls(
            transfer_id=(data[3] << 16) | (data[4] << 8) | data[5],
            seed=int.from_bytes(data[6:8], "big"),
            source_block_count=data[8],
            total_length=int.from_bytes(data[9:11], "big"),
            payload=data[11:],
        )


@dataclass(slots=True)
class AckPacket:
    transfer_id: int
    packet_type: int
    received_blocks: int
    needed_blocks: int
    data_hash: bytes

    def to_bytes(self) -> bytes:
        hash8 = (self.data_hash or b"")[:8].ljust(8, b"\x00")
        return b"".join(
            [
                MAGIC,
                bytes(
                    [
                        (self.transfer_id >> 16) & 0xFF,
                        (self.transfer_id >> 8) & 0xFF,
                        self.transfer_id & 0xFF,
                        self.packet_type & 0xFF,
                    ]
                ),
                self.received_blocks.to_bytes(2, "big"),
                self.needed_blocks.to_bytes(2, "big"),
                hash8,
            ]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "AckPacket | None":
        if not is_fountain_packet(data) or len(data) < ACK_PACKET_SIZE:
            return None
        return cls(
            transfer_id=(data[3] << 16) | (data[4] << 8) | data[5],
            packet_type=data[6],
            received_blocks=int.from_bytes(data[7:9], "big"),
            needed_blocks=int.from_bytes(data[9:11], "big"),
            data_hash=data[11:19],
        )


class FountainCodec:
    def __init__(self, block_size: int = MAX_PAYLOAD_SIZE, c: float = 0.1, delta: float = 0.5):
        self.block_size = block_size
        self.c = c
        self.delta = delta

    def get_source_block_count(self, data_length: int) -> int:
        return max(1, int(math.ceil(float(data_length) / float(self.block_size))))

    def get_recommended_block_count(self, data_length: int, overhead: float) -> int:
        k = self.get_source_block_count(data_length)
        return max(1, int(math.ceil(k * (1.0 + overhead))))

    def encode(self, data: bytes, num_blocks: int, transfer_id: int) -> list[EncodedBlock]:
        k = self.get_source_block_count(len(data))
        source_blocks = self._split_into_source_blocks(data, k)
        encoded: list[EncodedBlock] = []
        for index in range(num_blocks):
            seed = self.generate_seed(transfer_id, index)
            if index == 0:
                encoded.append(self._encode_block_with_degree(source_blocks, k, seed, len(data), 1))
            else:
                encoded.append(self._encode_block(source_blocks, k, seed, len(data)))
        return encoded

    def decode(self, blocks: list[EncodedBlock]) -> bytes | None:
        if not blocks:
            return None
        k = blocks[0].source_block_count
        total_length = blocks[0].total_length
        block_size = len(blocks[0].payload)
        decoded: list[bytearray | None] = [None] * k
        decoded_count = 0
        working: list[tuple[bytearray, set[int]] | None] = [
            (bytearray(block.payload), set(block.source_indices)) for block in blocks
        ]
        progress = True
        while progress and decoded_count < k:
            progress = False
            for idx, item in enumerate(working):
                if item is None:
                    continue
                payload, indices = item
                remaining: set[int] = set()
                for source_idx in indices:
                    if decoded[source_idx] is None:
                        remaining.add(source_idx)
                    else:
                        self._xor_in_place(payload, decoded[source_idx] or b"")
                if len(remaining) == 1:
                    source_idx = next(iter(remaining))
                    decoded[source_idx] = bytearray(payload)
                    decoded_count += 1
                    working[idx] = None
                    progress = True
                elif not remaining:
                    working[idx] = None
                else:
                    working[idx] = (payload, remaining)
        if decoded_count < k:
            return None
        return self._reassemble([bytes(block or b"") for block in decoded], total_length, block_size)

    def regenerate_indices(self, seed: int, source_block_count: int, transfer_id: int) -> list[int]:
        rng = JavaRandom(seed)
        block0_seed = (transfer_id * 31337) & 0xFFFF
        is_first_block = seed == block0_seed
        self._sample_degree(rng, source_block_count)
        if is_first_block:
            degree = 1
        else:
            rng = JavaRandom(seed)
            degree = self._sample_degree(rng, source_block_count)
        return self._select_indices(rng, source_block_count, degree)

    @staticmethod
    def generate_seed(transfer_id: int, block_index: int) -> int:
        return (transfer_id * 31337 + block_index * 7919) & 0xFFFF

    def _split_into_source_blocks(self, data: bytes, source_block_count: int) -> list[bytes]:
        blocks: list[bytes] = []
        for index in range(source_block_count):
            start = index * self.block_size
            chunk = bytearray(self.block_size)
            payload = data[start : start + self.block_size]
            chunk[: len(payload)] = payload
            blocks.append(bytes(chunk))
        return blocks

    def _reassemble(self, blocks: list[bytes], total_length: int, block_size: int | None = None) -> bytes:
        size = int(block_size or self.block_size or 0)
        output = bytearray(total_length)
        pos = 0
        for block in blocks:
            length = min(size, total_length - pos)
            if length <= 0:
                break
            output[pos : pos + length] = block[:length]
            pos += length
        return bytes(output)

    def _encode_block(self, source_blocks: list[bytes], source_block_count: int, seed: int, total_length: int) -> EncodedBlock:
        rng = JavaRandom(seed)
        degree = self._sample_degree(rng, source_block_count)
        indices = self._select_indices(rng, source_block_count, degree)
        payload = bytearray(self.block_size)
        for idx in indices:
            self._xor_in_place(payload, source_blocks[idx])
        return EncodedBlock(seed, source_block_count, total_length, indices, bytes(payload))

    def _encode_block_with_degree(
        self,
        source_blocks: list[bytes],
        source_block_count: int,
        seed: int,
        total_length: int,
        forced_degree: int,
    ) -> EncodedBlock:
        rng = JavaRandom(seed)
        self._sample_degree(rng, source_block_count)
        degree = min(forced_degree, source_block_count)
        indices = self._select_indices(rng, source_block_count, degree)
        payload = bytearray(self.block_size)
        for idx in indices:
            self._xor_in_place(payload, source_blocks[idx])
        return EncodedBlock(seed, source_block_count, total_length, indices, bytes(payload))

    def _sample_degree(self, rng: JavaRandom, source_block_count: int) -> int:
        cdf = self._build_robust_soliton_cdf(source_block_count)
        value = rng.next_double()
        for degree in range(1, source_block_count + 1):
            if value <= cdf[degree]:
                return degree
        return source_block_count

    def _build_robust_soliton_cdf(self, source_block_count: int) -> list[float]:
        rho = [0.0] * (source_block_count + 1)
        tau = [0.0] * (source_block_count + 1)
        mu = [0.0] * (source_block_count + 1)
        cdf = [0.0] * (source_block_count + 1)
        rho[1] = 1.0 / source_block_count
        for degree in range(2, source_block_count + 1):
            rho[degree] = 1.0 / (degree * (degree - 1))
        s = self.c * math.log(source_block_count / self.delta) * math.sqrt(source_block_count)
        threshold = int(math.floor(source_block_count / s)) if s > 0 else 0
        for degree in range(1, source_block_count + 1):
            if degree < threshold:
                tau[degree] = s / (source_block_count * degree)
            elif degree == threshold and threshold > 0:
                tau[degree] = s * math.log(s / self.delta) / source_block_count
        normalizer = 0.0
        for degree in range(1, source_block_count + 1):
            mu[degree] = rho[degree] + tau[degree]
            normalizer += mu[degree]
        cumulative = 0.0
        for degree in range(1, source_block_count + 1):
            cumulative += mu[degree] / normalizer
            cdf[degree] = cumulative
        return cdf

    def _select_indices(self, rng: JavaRandom, source_block_count: int, degree: int) -> list[int]:
        degree = min(max(1, degree), source_block_count)
        selected: set[int] = set()
        while len(selected) < degree:
            selected.add(rng.next_int(source_block_count))
        return sorted(selected)

    @staticmethod
    def _xor_in_place(target: bytearray, source: bytes | bytearray) -> None:
        for idx in range(min(len(target), len(source))):
            target[idx] ^= source[idx]
