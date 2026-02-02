import argparse
import os
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


@dataclass
class Hit:
    type: str
    offset: int
    text: str


@dataclass
class CountResult:
    ascii: int = 0
    utf16le: int = 0
    truncated: bool = False

    def total(self) -> int:
        return self.ascii + self.utf16le


def is_ascii_printable_basic(b: int) -> bool:
    return 0x20 <= b <= 0x7E


def is_ascii_printable_bintext_default(b: int) -> bool:
    return (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D)


def has_repeat_run_bytes(buf: bytes, limit: int) -> bool:
    if limit <= 0:
        return False
    if not buf:
        return False
    if limit == 1:
        return True
    run = 1
    prev = buf[0]
    for cur in buf[1:]:
        if cur == prev:
            run += 1
            if run >= limit:
                return True
        else:
            prev = cur
            run = 1
    return False


def scan_ascii(
    path: str,
    *,
    min_len: int,
    max_len: int,
    max_hits: int,
    is_printable: Callable[[int], bool],
    repeat_run_limit: int,
    max_bytes: Optional[int] = None,
    block_size: int = 1 << 20,
) -> Tuple[List[Hit], bool]:
    hits: List[Hit] = []
    truncated = False

    cur = bytearray()
    cur_start = 0
    in_run = False

    total = os.path.getsize(path)
    if max_bytes is not None and max_bytes > 0 and max_bytes < total:
        total = max_bytes
    file_off = 0
    with open(path, "rb") as f:
        while file_off < total:
            if max_hits > 0 and len(hits) >= max_hits:
                truncated = True
                break

            buf = f.read(min(block_size, total - file_off))
            if not buf:
                break

            for i, b in enumerate(buf):
                if is_printable(b):
                    if not in_run:
                        in_run = True
                        cur_start = file_off + i
                        cur.clear()
                    cur.append(b)
                    if len(cur) >= max_len:
                        if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                            text = cur[:max_len].decode("latin1", errors="ignore")
                            hits.append(Hit("ascii", cur_start, text))
                            if max_hits > 0 and len(hits) >= max_hits:
                                truncated = True
                                break
                        in_run = False
                        cur.clear()
                else:
                    if in_run:
                        if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                            text = cur[:max_len].decode("latin1", errors="ignore")
                            hits.append(Hit("ascii", cur_start, text))
                            if max_hits > 0 and len(hits) >= max_hits:
                                truncated = True
                                break
                        in_run = False
                        cur.clear()

            if truncated:
                break
            file_off += len(buf)

    if not truncated and in_run:
        if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
            text = cur[:max_len].decode("latin1", errors="ignore")
            hits.append(Hit("ascii", cur_start, text))
            if max_hits > 0 and len(hits) >= max_hits:
                truncated = True

    return hits, truncated


def scan_utf16le_ascii_subset(
    path: str,
    *,
    min_len: int,
    max_len: int,
    max_hits: int,
    is_printable: Callable[[int], bool],
    repeat_run_limit: int,
    max_bytes: Optional[int] = None,
    block_size: int = 1 << 20,
) -> Tuple[List[Hit], bool]:
    hits: List[Hit] = []
    truncated = False

    cur = bytearray()
    cur_start = 0
    in_run = False

    total = os.path.getsize(path)
    if max_bytes is not None and max_bytes > 0 and max_bytes < total:
        total = max_bytes
    file_off = 0
    have_carry = False
    carry = 0

    with open(path, "rb") as f:
        while file_off < total:
            if max_hits > 0 and len(hits) >= max_hits:
                truncated = True
                break

            buf = f.read(min(block_size, total - file_off))
            if not buf:
                break

            i = 0
            if have_carry:
                lo = carry
                hi = buf[0]
                if hi == 0x00 and is_printable(lo):
                    if not in_run:
                        in_run = True
                        cur_start = file_off - 1
                        cur.clear()
                    cur.append(lo)
                    if len(cur) >= max_len:
                        if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                            text = cur[:max_len].decode("latin1", errors="ignore")
                            hits.append(Hit("utf16le", cur_start, text))
                            if max_hits > 0 and len(hits) >= max_hits:
                                truncated = True
                                break
                        in_run = False
                        cur.clear()
                else:
                    if in_run:
                        if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                            text = cur[:max_len].decode("latin1", errors="ignore")
                            hits.append(Hit("utf16le", cur_start, text))
                            if max_hits > 0 and len(hits) >= max_hits:
                                truncated = True
                                break
                        in_run = False
                        cur.clear()
                have_carry = False
                i = 1

            if truncated:
                break

            n = len(buf)
            while i + 1 < n:
                lo = buf[i]
                hi = buf[i + 1]
                if hi == 0x00 and is_printable(lo):
                    if not in_run:
                        in_run = True
                        cur_start = file_off + i
                        cur.clear()
                    cur.append(lo)
                    if len(cur) >= max_len:
                        if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                            text = cur[:max_len].decode("latin1", errors="ignore")
                            hits.append(Hit("utf16le", cur_start, text))
                            if max_hits > 0 and len(hits) >= max_hits:
                                truncated = True
                                break
                        in_run = False
                        cur.clear()
                else:
                    if in_run:
                        if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                            text = cur[:max_len].decode("latin1", errors="ignore")
                            hits.append(Hit("utf16le", cur_start, text))
                            if max_hits > 0 and len(hits) >= max_hits:
                                truncated = True
                                break
                        in_run = False
                        cur.clear()
                i += 2

            if truncated:
                break

            if i < n:
                carry = buf[i]
                have_carry = True

            file_off += len(buf)

    if not truncated and in_run:
        if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
            text = cur[:max_len].decode("latin1", errors="ignore")
            hits.append(Hit("utf16le", cur_start, text))
            if max_hits > 0 and len(hits) >= max_hits:
                truncated = True

    return hits, truncated


def summarize_counts(counts: CountResult, max_hits: int) -> str:
    parts = [f"total={counts.total()}"]
    if counts.ascii:
        parts.append(f"ascii={counts.ascii}")
    if counts.utf16le:
        parts.append(f"utf16le={counts.utf16le}")
    if max_hits > 0:
        parts.append(f"maxHits={max_hits}")
    parts.append(f"truncated={'yes' if counts.truncated else 'no'}")
    return ", ".join(parts)


def print_samples(hits: List[Hit]) -> None:
    hits_sorted = sorted(hits, key=lambda h: (h.offset, h.type))
    for h in hits_sorted:
        text = h.text
        preview = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
        if len(preview) > 120:
            preview = preview[:120] + "..."
        print(f"0x{h.offset:08X}\t{h.type}\tlen={len(h.text)}\t{preview}")


def run_once_count(
    path: str,
    *,
    min_len: int,
    max_len: int,
    max_hits: int,
    scan_ascii_enabled: bool,
    scan_utf16le_enabled: bool,
    ascii_charset: str,
    repeat_run_limit: int,
    max_bytes: Optional[int],
    sample_count: int,
) -> Tuple[CountResult, List[Hit]]:
    if ascii_charset == "bintext":
        is_printable = is_ascii_printable_bintext_default
    else:
        is_printable = is_ascii_printable_basic

    counts = CountResult()
    samples: List[Hit] = []

    total = os.path.getsize(path)
    if max_bytes is not None and max_bytes > 0 and max_bytes < total:
        total = max_bytes

    if scan_ascii_enabled:
        cur = bytearray()
        cur_start = 0
        in_run = False

        file_off = 0
        with open(path, "rb") as f:
            while file_off < total:
                if max_hits > 0 and counts.total() >= max_hits:
                    counts.truncated = True
                    break
                buf = f.read(min(1 << 20, total - file_off))
                if not buf:
                    break
                for i, b in enumerate(buf):
                    if is_printable(b):
                        if not in_run:
                            in_run = True
                            cur_start = file_off + i
                            cur.clear()
                        cur.append(b)
                        if len(cur) >= max_len:
                            if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                                counts.ascii += 1
                                if sample_count > 0 and len(samples) < sample_count:
                                    text = cur[:max_len].decode("latin1", errors="ignore")
                                    samples.append(Hit("ascii", cur_start, text))
                                if max_hits > 0 and counts.total() >= max_hits:
                                    counts.truncated = True
                                    break
                            in_run = False
                            cur.clear()
                    else:
                        if in_run:
                            if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                                counts.ascii += 1
                                if sample_count > 0 and len(samples) < sample_count:
                                    text = cur[:max_len].decode("latin1", errors="ignore")
                                    samples.append(Hit("ascii", cur_start, text))
                                if max_hits > 0 and counts.total() >= max_hits:
                                    counts.truncated = True
                                    break
                            in_run = False
                            cur.clear()
                if counts.truncated:
                    break
                file_off += len(buf)
        if not counts.truncated and in_run:
            if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                counts.ascii += 1
                if sample_count > 0 and len(samples) < sample_count:
                    text = cur[:max_len].decode("latin1", errors="ignore")
                    samples.append(Hit("ascii", cur_start, text))
                if max_hits > 0 and counts.total() >= max_hits:
                    counts.truncated = True

    if scan_utf16le_enabled and not counts.truncated:
        utf16_max_hits = (max_hits - counts.total()) if max_hits > 0 else 0
        cur = bytearray()
        cur_start = 0
        in_run = False
        have_carry = False
        carry = 0

        file_off = 0
        with open(path, "rb") as f:
            while file_off < total:
                if utf16_max_hits > 0 and counts.utf16le >= utf16_max_hits:
                    counts.truncated = True
                    break
                buf = f.read(min(1 << 20, total - file_off))
                if not buf:
                    break
                i = 0
                if have_carry:
                    lo = carry
                    hi = buf[0]
                    if hi == 0x00 and is_printable(lo):
                        if not in_run:
                            in_run = True
                            cur_start = file_off - 1
                            cur.clear()
                        cur.append(lo)
                        if len(cur) >= max_len:
                            if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                                counts.utf16le += 1
                                if sample_count > 0 and len(samples) < sample_count:
                                    text = cur[:max_len].decode("latin1", errors="ignore")
                                    samples.append(Hit("utf16le", cur_start, text))
                                if utf16_max_hits > 0 and counts.utf16le >= utf16_max_hits:
                                    counts.truncated = True
                                    break
                            in_run = False
                            cur.clear()
                    else:
                        if in_run:
                            if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                                counts.utf16le += 1
                                if sample_count > 0 and len(samples) < sample_count:
                                    text = cur[:max_len].decode("latin1", errors="ignore")
                                    samples.append(Hit("utf16le", cur_start, text))
                                if utf16_max_hits > 0 and counts.utf16le >= utf16_max_hits:
                                    counts.truncated = True
                                    break
                            in_run = False
                            cur.clear()
                    have_carry = False
                    i = 1
                if counts.truncated:
                    break
                n = len(buf)
                while i + 1 < n:
                    lo = buf[i]
                    hi = buf[i + 1]
                    if hi == 0x00 and is_printable(lo):
                        if not in_run:
                            in_run = True
                            cur_start = file_off + i
                            cur.clear()
                        cur.append(lo)
                        if len(cur) >= max_len:
                            if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                                counts.utf16le += 1
                                if sample_count > 0 and len(samples) < sample_count:
                                    text = cur[:max_len].decode("latin1", errors="ignore")
                                    samples.append(Hit("utf16le", cur_start, text))
                                if utf16_max_hits > 0 and counts.utf16le >= utf16_max_hits:
                                    counts.truncated = True
                                    break
                            in_run = False
                            cur.clear()
                    else:
                        if in_run:
                            if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                                counts.utf16le += 1
                                if sample_count > 0 and len(samples) < sample_count:
                                    text = cur[:max_len].decode("latin1", errors="ignore")
                                    samples.append(Hit("utf16le", cur_start, text))
                                if utf16_max_hits > 0 and counts.utf16le >= utf16_max_hits:
                                    counts.truncated = True
                                    break
                            in_run = False
                            cur.clear()
                    i += 2
                if counts.truncated:
                    break
                if i < n:
                    carry = buf[i]
                    have_carry = True
                file_off += len(buf)

        if not counts.truncated and in_run:
            if len(cur) >= min_len and not has_repeat_run_bytes(cur, repeat_run_limit):
                counts.utf16le += 1
                if sample_count > 0 and len(samples) < sample_count:
                    text = cur[:max_len].decode("latin1", errors="ignore")
                    samples.append(Hit("utf16le", cur_start, text))
                if utf16_max_hits > 0 and counts.utf16le >= utf16_max_hits:
                    counts.truncated = True

    return counts, samples


def run_once(
    path: str,
    *,
    min_len: int,
    max_len: int,
    max_hits: int,
    scan_ascii_enabled: bool,
    scan_utf16le_enabled: bool,
    ascii_charset: str,
    repeat_run_limit: int,
    max_bytes: Optional[int],
    sample_count: int,
) -> Tuple[List[Hit], bool]:
    if ascii_charset == "bintext":
        is_printable = is_ascii_printable_bintext_default
    else:
        is_printable = is_ascii_printable_basic

    hits: List[Hit] = []
    truncated = False

    if scan_ascii_enabled:
        h, t = scan_ascii(
            path,
            min_len=min_len,
            max_len=max_len,
            max_hits=max_hits,
            is_printable=is_printable,
            repeat_run_limit=repeat_run_limit,
            max_bytes=max_bytes,
        )
        hits.extend(h)
        truncated = truncated or t

    if scan_utf16le_enabled and not truncated:
        remaining = max_hits - len(hits) if max_hits > 0 else 0
        h, t = scan_utf16le_ascii_subset(
            path,
            min_len=min_len,
            max_len=max_len,
            max_hits=remaining if max_hits > 0 else 0,
            is_printable=is_printable,
            repeat_run_limit=repeat_run_limit,
            max_bytes=max_bytes,
        )
        hits.extend(h)
        truncated = truncated or t

    hits.sort(key=lambda h: (h.offset, h.type))
    if sample_count > 0:
        print_samples(hits[:sample_count])
    return hits, truncated


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="待扫描的文件路径")
    ap.add_argument("--preset", choices=["old", "aligned"], default=None, help="预置参数对比：old=旧行为，aligned=对齐行为")
    ap.add_argument("--compare", action="store_true", help="同时跑 old 与 aligned 并输出对比")
    ap.add_argument("--min-len", type=int, default=5)
    ap.add_argument("--max-len", type=int, default=4096)
    ap.add_argument("--max-hits", type=int, default=3000000)
    ap.add_argument("--ascii", action="store_true", default=False)
    ap.add_argument("--utf16le", action="store_true", default=False)
    ap.add_argument("--both", action="store_true", default=False)
    ap.add_argument("--ascii-charset", choices=["basic", "bintext"], default="bintext")
    ap.add_argument("--repeat-run", type=int, default=8, help="连续重复字符阈值(<=0 表示关闭)")
    ap.add_argument("--max-bytes", type=int, default=0, help="最多扫描字节数(<=0 表示全文件)")
    ap.add_argument("--samples", type=int, default=0, help="打印前 N 条样例")
    ap.add_argument("--count-only", action="store_true", help="只统计数量(低内存)，不保存所有命中")
    args = ap.parse_args()

    path = args.file
    if not os.path.isfile(path):
        print(f"文件不存在: {path}", file=sys.stderr)
        return 2

    max_bytes = args.max_bytes if args.max_bytes and args.max_bytes > 0 else None

    if args.compare:
        presets = ["old", "aligned"]
    elif args.preset:
        presets = [args.preset]
    else:
        presets = []

    if args.both or (not args.ascii and not args.utf16le and not args.both):
        scan_ascii_enabled = True
        scan_utf16le_enabled = True
    else:
        scan_ascii_enabled = args.ascii
        scan_utf16le_enabled = args.utf16le

    def cfg_for_preset(name: str):
        if name == "old":
            return {
                "min_len": 4,
                "ascii_charset": "basic",
                "repeat_run_limit": 0,
            }
        return {
            "min_len": 5,
            "ascii_charset": "bintext",
            "repeat_run_limit": 8,
        }

    if presets:
        results = {}
        for p in presets:
            cfg = cfg_for_preset(p)
            print(f"[{p}] minLen={cfg['min_len']}, asciiCharset={cfg['ascii_charset']}, repeatRun={cfg['repeat_run_limit']}, maxLen={args.max_len}, maxHits={args.max_hits}")
            if args.count_only:
                counts, samples = run_once_count(
                    path,
                    min_len=cfg["min_len"],
                    max_len=args.max_len,
                    max_hits=args.max_hits,
                    scan_ascii_enabled=scan_ascii_enabled,
                    scan_utf16le_enabled=scan_utf16le_enabled,
                    ascii_charset=cfg["ascii_charset"],
                    repeat_run_limit=cfg["repeat_run_limit"],
                    max_bytes=max_bytes,
                    sample_count=args.samples,
                )
                results[p] = counts.total()
                if samples:
                    print_samples(samples)
                print(summarize_counts(counts, args.max_hits))
            else:
                hits, truncated = run_once(
                    path,
                    min_len=cfg["min_len"],
                    max_len=args.max_len,
                    max_hits=args.max_hits,
                    scan_ascii_enabled=scan_ascii_enabled,
                    scan_utf16le_enabled=scan_utf16le_enabled,
                    ascii_charset=cfg["ascii_charset"],
                    repeat_run_limit=cfg["repeat_run_limit"],
                    max_bytes=max_bytes,
                    sample_count=args.samples,
                )
                results[p] = len(hits)
                print(summarize_counts(CountResult(ascii=len([h for h in hits if h.type=='ascii']), utf16le=len([h for h in hits if h.type=='utf16le']), truncated=truncated), args.max_hits))
            print()
        if len(presets) == 2:
            a = results["old"]
            b = results["aligned"]
            print(f"[diff] old-total={a}, aligned-total={b}, delta={b - a}")
        return 0

    print(
        f"minLen={args.min_len}, maxLen={args.max_len}, maxHits={args.max_hits}, asciiCharset={args.ascii_charset}, repeatRun={args.repeat_run}, mode={'both' if (scan_ascii_enabled and scan_utf16le_enabled) else ('ascii' if scan_ascii_enabled else 'utf16le')}"
    )
    if args.count_only:
        counts, samples = run_once_count(
            path,
            min_len=args.min_len,
            max_len=args.max_len,
            max_hits=args.max_hits,
            scan_ascii_enabled=scan_ascii_enabled,
            scan_utf16le_enabled=scan_utf16le_enabled,
            ascii_charset=args.ascii_charset,
            repeat_run_limit=args.repeat_run,
            max_bytes=max_bytes,
            sample_count=args.samples,
        )
        if samples:
            print_samples(samples)
        print(summarize_counts(counts, args.max_hits))
    else:
        hits, truncated = run_once(
            path,
            min_len=args.min_len,
            max_len=args.max_len,
            max_hits=args.max_hits,
            scan_ascii_enabled=scan_ascii_enabled,
            scan_utf16le_enabled=scan_utf16le_enabled,
            ascii_charset=args.ascii_charset,
            repeat_run_limit=args.repeat_run,
            max_bytes=max_bytes,
            sample_count=args.samples,
        )
        ascii_n = len([h for h in hits if h.type == "ascii"])
        utf16_n = len(hits) - ascii_n
        print(summarize_counts(CountResult(ascii=ascii_n, utf16le=utf16_n, truncated=truncated), args.max_hits))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
