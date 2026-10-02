"""Bounded simulated memory with sparse pages and access checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

PAGE_SIZE = 4096
ADDRESS_LIMIT = 1 << 64


class MemoryFault(Exception):
    """A simulated allocation or access failure with a stable diagnostic code."""

    def __init__(self, code: str, message: str, address: int = 0, size: int = 0) -> None:
        """Store the diagnostic and the attempted address range.

        Args:
            code: Stable diagnostic identifier.
            message: Description of the failure.
            address: Start of the attempted access.
            size: Requested number of bytes.
        """
        super().__init__(message)
        self.code = code
        self.address = address
        self.size = size


@dataclass
class Region:
    """An allocated range; the end address is exclusive."""

    start: int
    size: int
    name: str
    writable: bool = True
    initialized: bool = True

    @property
    def end(self) -> int:
        """Return the first address outside the region.

        Returns:
            Exclusive end address.
        """
        return self.start + self.size


class Memory:
    """Track allocated bytes separately from the pages containing their values."""

    def __init__(self, limit: int) -> None:
        """Create an empty address space with a positive byte budget.

        Raises:
            ValueError: If the budget is not positive.
        """
        if limit < 1:
            raise ValueError("memory limit must be positive")
        self.limit = limit
        self.regions: List[Region] = []
        self.pages: Dict[int, bytearray] = {}
        self.written: Dict[int, int] = {}
        self.allocated = 0
        self.peak = 0

    def check_capacity(self, size: int) -> None:
        """Reject an allocation before constructing its backing storage.

        Raises:
            MemoryFault: On a negative size or an exhausted simulated budget.
        """
        if size < 0:
            raise MemoryFault("MEM_SIZE", "negative memory allocation size", size=size)
        if self.allocated + size > self.limit:
            raise MemoryFault(
                "MEM_LIMIT",
                "out of memory: requested %d bytes; %d of %d bytes already allocated"
                % (size, self.allocated, self.limit),
                size=size,
            )

    def allocate(
        self, start: int, size: int, name: str, writable: bool = True, initialized: bool = True
    ) -> Region:
        """Map a nonoverlapping region without allocating zero-filled host pages.

        Args:
            start: First address.
            size: Requested bytes.
            name: Region label for diagnostics.
            writable: Whether program writes are permitted.
            initialized: Whether unwritten bytes have a defined zero value.

        Returns:
            The mapped region, which may be empty.

        Raises:
            MemoryFault: If the range overlaps, wraps or exceeds the budget.
        """
        self.check_capacity(size)
        if start < 0 or start + size > ADDRESS_LIMIT:
            raise MemoryFault("MEM_ACCESS", "allocation exceeds the address space", start, size)
        if size and any(start < r.end and start + size > r.start for r in self.regions if r.size):
            raise MemoryFault(
                "MEM_ACCESS", "memory allocation overlaps another region", start, size
            )
        region = Region(start, size, name, writable, initialized)
        self.regions.append(region)
        self.allocated += size
        self.peak = max(self.peak, self.allocated)
        return region

    def resize(self, region: Region, start: int, size: int) -> None:
        """Resize a heap or stack region, preserving data in the retained range.

        Args:
            region: Existing region to change.
            start: New first address.
            size: New size in bytes.

        Raises:
            MemoryFault: If growth exceeds the budget or overlaps another region.
        """
        if size < 0:
            raise MemoryFault("MEM_SIZE", "negative memory allocation size", start, size)
        self.check_capacity(max(0, size - region.size))
        if (
            start < 0
            or start + size > ADDRESS_LIMIT
            or any(
                r is not region and r.size and size and start < r.end and start + size > r.start
                for r in self.regions
            )
        ):
            raise MemoryFault("MEM_ACCESS", "resized memory range is invalid", start, size)
        old_start, old_end = region.start, region.end
        if start > old_start:
            self._discard(old_start, min(start, old_end))
        if start + size < old_end:
            self._discard(max(start + size, old_start), old_end)
        self.allocated += size - region.size
        self.peak = max(self.peak, self.allocated)
        region.start, region.size = start, size

    def _discard(self, start: int, end: int) -> None:
        """Clear committed bytes and initialization bits in a freed range."""
        for page in list(self.pages):
            base = page * PAGE_SIZE
            low, high = max(start, base) - base, min(end, base + PAGE_SIZE) - base
            if low >= high:
                continue
            if low == 0 and high == PAGE_SIZE:
                del self.pages[page]
                self.written.pop(page, None)
            else:
                self.pages[page][low:high] = bytes(high - low)
                self.written[page] &= ~(((1 << (high - low)) - 1) << low)

    def check(self, address: int, size: int, write: bool = False) -> Region:
        """Check that the whole access fits in a single allocated region.

        Args:
            address: First address of the access.
            size: Access size in bytes.
            write: Whether writable permission is required.

        Returns:
            Region containing the access.

        Raises:
            MemoryFault: For an unmapped, wrapping or read-only access.
        """
        if size < 0 or address < 0 or address + size > ADDRESS_LIMIT:
            raise MemoryFault("MEM_ACCESS", "memory access wraps the address space", address, size)
        for region in self.regions:
            if region.start <= address and address + size <= region.end and region.size:
                if write and not region.writable:
                    raise MemoryFault(
                        "MEM_READONLY", "write to read-only region %s" % region.name, address, size
                    )
                return region
        raise MemoryFault(
            "MEM_ACCESS",
            "%s outside allocated memory at 0x%x (%d bytes)"
            % ("write" if write else "read", address, size),
            address,
            size,
        )

    def peek(self, address: int) -> int:
        """Inspect a byte without access checks or execution side effects.

        Returns:
            Stored byte, or zero for an uncommitted page.
        """
        page, offset = divmod(address, PAGE_SIZE)
        data = self.pages.get(page)
        return data[offset] if data is not None else 0

    def initialized(self, address: int, size: int) -> bool:
        """Check every byte of an allocated range for initialization.

        Returns:
            Whether all bytes have a defined value.
        """
        region = self.check(address, size)
        if region.initialized:
            return True
        for current in range(address, address + size):
            page, offset = divmod(current, PAGE_SIZE)
            if not (self.written.get(page, 0) >> offset) & 1:
                return False
        return True

    def store(self, address: int, data: bytes) -> None:
        """Store bytes in already validated memory, allocating pages as needed."""
        offset = 0
        while offset < len(data):
            page, within = divmod(address + offset, PAGE_SIZE)
            length = min(len(data) - offset, PAGE_SIZE - within)
            if page not in self.pages:
                self.pages[page] = bytearray(PAGE_SIZE)
            self.pages[page][within : within + length] = data[offset : offset + length]
            self.written[page] = self.written.get(page, 0) | (((1 << length) - 1) << within)
            offset += length

    def fill(self, address: int, pattern: bytes, count: int) -> None:
        """Load an initializer in bounded chunks, keeping all-zero data sparse.

        Args:
            address: First destination address, already validated.
            pattern: Bytes to repeat.
            count: Number of repetitions.
        """
        if not pattern or not count or not any(pattern):
            return
        chunk_count = max(1, PAGE_SIZE // len(pattern))
        chunk = pattern * min(count, chunk_count)
        while count:
            take = min(count, chunk_count)
            self.store(address, chunk[: take * len(pattern)])
            address += take * len(pattern)
            count -= take

    def snapshot(self) -> Dict[str, int]:
        """Report logical allocation and committed page storage in bytes.

        Returns:
            Current usage, peak usage, limit and committed page bytes.
        """
        return {
            "allocated_bytes": self.allocated,
            "peak_bytes": self.peak,
            "limit_bytes": self.limit,
            "committed_bytes": len(self.pages) * PAGE_SIZE,
        }
