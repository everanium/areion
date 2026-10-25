#!/usr/bin/env python3
"""Static disassembly audit, interleaved A/B microbenchmarks, and CPU profile
attribution for epilogue register and stack clearing (commit 72a892a vs
commit c74d39a).
"""
import argparse
import os
import pathlib
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent

PRE_COMMIT = "c74d39a"
POST_COMMIT = "72a892a"
REF_GHZ_AMD64 = 3.60
REF_GHZ_ARM64 = 2.80

INTERFACES = [
    # (bench_name, display_name, input_bytes)
    ("BenchmarkAES128EncryptBlock", "AES128EncryptBlock", 16),
    ("BenchmarkPermute256", "Permute256", 32),
    ("BenchmarkPermute512", "Permute512", 64),
    ("BenchmarkInversePermute256", "InversePermute256", 32),
    ("BenchmarkInversePermute512", "InversePermute512", 64),
    ("BenchmarkSoEM256", "SoEM256", 32),
    ("BenchmarkSoEM512", "SoEM512", 64),
    ("BenchmarkAES128Encrypt4Blocks", "AES128Encrypt4Blocks", 64),
    ("BenchmarkPermute256x4", "Permute256x4", 128),
    ("BenchmarkPermute512x4", "Permute512x4", 256),
    ("BenchmarkInversePermute256x4", "InversePermute256x4", 128),
    ("BenchmarkInversePermute512x4", "InversePermute512x4", 256),
    ("BenchmarkSoEM256x4", "SoEM256x4", 128),
    ("BenchmarkSoEM512x4", "SoEM512x4", 256),
]

TIERS_AMD64 = ["purego", "aesni", "vex", "vaesavx2", "avx512"]
TIERS_ARM64 = ["purego", "arm64"]

# Mapping from (interface_display_name, tier_or_arch) to (.abi0 kernel symbol, wrapper symbol, wrapper_clobber_calls, wrapper_wipe_calls)
KERNEL_MAP = {
    "AES128EncryptBlock": {
        "aesni": ("aes128EncryptBlockAsm.abi0", "aes128EncryptBlock", 0, 0),
        "vex": ("aes128EncryptBlockVexAsm.abi0", "aes128EncryptBlock", 0, 0),
        "vaesavx2": ("aes128EncryptBlockVexAsm.abi0", "aes128EncryptBlock", 0, 0),
        "avx512": ("aes128EncryptBlockVexAsm.abi0", "aes128EncryptBlock", 0, 0),
        "arm64": ("aes128EncryptBlockAsm.abi0", "aes128EncryptBlock", 0, 0),
        "purego": (None, "aes128EncryptBlockSoftware", 1, 1),
    },
    "Permute256": {
        "aesni": ("areion256PermuteRCAsm.abi0", "areion256PermuteRC", 0, 0),
        "vex": ("areion256PermuteVexRCAsm.abi0", "areion256PermuteRC", 0, 0),
        "vaesavx2": ("areion256PermuteVexRCAsm.abi0", "areion256PermuteRC", 0, 0),
        "avx512": ("areion256PermuteVexRCAsm.abi0", "areion256PermuteRC", 0, 0),
        "arm64": ("areion256PermuteRCAsm.abi0", "areion256PermuteRC", 0, 0),
        "purego": (None, "areion256PermuteSoftwareRC", 1, 1),
    },
    "Permute512": {
        "aesni": ("areion512PermuteRCAsm.abi0", "areion512PermuteRC", 0, 0),
        "vex": ("areion512PermuteVexRCAsm.abi0", "areion512PermuteRC", 0, 0),
        "vaesavx2": ("areion512PermuteVexRCAsm.abi0", "areion512PermuteRC", 0, 0),
        "avx512": ("areion512PermuteVexRCAsm.abi0", "areion512PermuteRC", 0, 0),
        "arm64": ("areion512PermuteRCAsm.abi0", "areion512PermuteRC", 0, 0),
        "purego": (None, "areion512PermuteSoftwareRC", 1, 1),
    },
    "InversePermute256": {
        "aesni": ("areion256InversePermuteRCAsm.abi0", "areion256InversePermuteRC", 0, 0),
        "vex": ("areion256InversePermuteVexRCAsm.abi0", "areion256InversePermuteRC", 0, 0),
        "vaesavx2": ("areion256InversePermuteVexRCAsm.abi0", "areion256InversePermuteRC", 0, 0),
        "avx512": ("areion256InversePermuteVexRCAsm.abi0", "areion256InversePermuteRC", 0, 0),
        "arm64": ("areion256InversePermuteRCAsm.abi0", "areion256InversePermuteRC", 0, 0),
        "purego": (None, "areion256InversePermuteSoftwareRC", 1, 1),
    },
    "InversePermute512": {
        "aesni": ("areion512InversePermuteRCAsm.abi0", "areion512InversePermuteRC", 0, 0),
        "vex": ("areion512InversePermuteVexRCAsm.abi0", "areion512InversePermuteRC", 0, 0),
        "vaesavx2": ("areion512InversePermuteVexRCAsm.abi0", "areion512InversePermuteRC", 0, 0),
        "avx512": ("areion512InversePermuteVexRCAsm.abi0", "areion512InversePermuteRC", 0, 0),
        "arm64": ("areion512InversePermuteRCAsm.abi0", "areion512InversePermuteRC", 0, 0),
        "purego": (None, "areion512InversePermuteSoftwareRC", 1, 1),
    },
    "SoEM256": {
        "aesni": ("areionSoEM256Asm.abi0", "areionSoEM256", 1, 0),
        "vex": ("areionSoEM256VexAsm.abi0", "areionSoEM256", 1, 0),
        "vaesavx2": ("areionSoEM256VexAsm.abi0", "areionSoEM256", 1, 0),
        "avx512": ("areionSoEM256VexAsm.abi0", "areionSoEM256", 1, 0),
        "arm64": ("areionSoEM256Asm.abi0", "areionSoEM256", 1, 0),
        "purego": (None, "soem256Software", 1, 1),
    },
    "SoEM512": {
        "aesni": ("areionSoEM512Asm.abi0", "areionSoEM512", 1, 0),
        "vex": ("areionSoEM512VexAsm.abi0", "areionSoEM512", 1, 0),
        "vaesavx2": ("areionSoEM512VexAsm.abi0", "areionSoEM512", 1, 0),
        "avx512": ("areionSoEM512VexAsm.abi0", "areionSoEM512", 1, 0),
        "arm64": ("areionSoEM512Asm.abi0", "areionSoEM512", 1, 0),
        "purego": (None, "soem512Software", 1, 1),
    },
    "AES128Encrypt4Blocks": {
        "aesni": ("aes128Encrypt4BlocksAesNiAsm.abi0", "aes128Encrypt4Blocks", 0, 0),
        "vex": ("aes128Encrypt4BlocksVexAsm.abi0", "aes128Encrypt4Blocks", 0, 0),
        "vaesavx2": ("aes128Encrypt4BlocksYmmAsm.abi0", "aes128Encrypt4Blocks", 0, 0),
        "avx512": ("aes128Encrypt4BlocksZmmAsm.abi0", "aes128Encrypt4Blocks", 0, 0),
        "arm64": ("aes128Encrypt4BlocksAsm.abi0", "aes128Encrypt4Blocks", 0, 0),
        "purego": (None, "aes128Encrypt4BlocksSoftware", 1, 1),
    },
    "Permute256x4": {
        "aesni": ("areion256Permutex4AesNiRC.abi0", "areion256Permutex4Tables", 1, 0),
        "vex": ("areion256Permutex4VexRC.abi0", "areion256Permutex4Tables", 1, 0),
        "vaesavx2": ("areion256Permutex4Avx2RC.abi0", "areion256Permutex4Tables", 1, 0),
        "avx512": ("areion256Permutex4RC.abi0", "areion256Permutex4Tables", 1, 0),
        "arm64": ("areion256Permutex4RC.abi0", "areion256Permutex4Table", 1, 0),
        "purego": (None, "areion256Permutex4SoftwareRC", 2, 1),
    },
    "Permute512x4": {
        "aesni": ("areion512Permutex4AesNiRC.abi0", "areion512Permutex4Tables", 1, 0),
        "vex": ("areion512Permutex4VexRC.abi0", "areion512Permutex4Tables", 1, 0),
        "vaesavx2": ("areion512Permutex4Avx2RC.abi0", "areion512Permutex4Tables", 1, 0),
        "avx512": ("areion512Permutex4RC.abi0", "areion512Permutex4Tables", 1, 0),
        "arm64": ("areion512Permutex4RC.abi0", "areion512Permutex4Table", 1, 0),
        "purego": (None, "areion512Permutex4SoftwareRC", 2, 1),
    },
    "InversePermute256x4": {
        "aesni": ("areion256InversePermutex4AesNiRC.abi0", "areion256InversePermutex4Tables", 1, 0),
        "vex": ("areion256InversePermutex4VexRC.abi0", "areion256InversePermutex4Tables", 1, 0),
        "vaesavx2": ("areion256InversePermutex4Avx2RC.abi0", "areion256InversePermutex4Tables", 1, 0),
        "avx512": ("areion256InversePermutex4RC.abi0", "areion256InversePermutex4Tables", 1, 0),
        "arm64": ("areion256InversePermutex4RC.abi0", "areion256InversePermutex4Table", 1, 0),
        "purego": (None, "areion256InversePermutex4SoftwareRC", 2, 1),
    },
    "InversePermute512x4": {
        "aesni": ("areion512InversePermutex4AesNiRC.abi0", "areion512InversePermutex4Tables", 1, 0),
        "vex": ("areion512InversePermutex4VexRC.abi0", "areion512InversePermutex4Tables", 1, 0),
        "vaesavx2": ("areion512InversePermutex4Avx2RC.abi0", "areion512InversePermutex4Tables", 1, 0),
        "avx512": ("areion512InversePermutex4RC.abi0", "areion512InversePermutex4Tables", 1, 0),
        "arm64": ("areion512InversePermutex4RC.abi0", "areion512InversePermutex4Table", 1, 0),
        "purego": (None, "areion512InversePermutex4SoftwareRC", 2, 1),
    },
    "SoEM256x4": {
        "aesni": ("areion256SoEMPermutex4AesNi.abi0", "areionSoEM256x4", 1, 0),
        "vex": ("areion256SoEMPermutex4Vex.abi0", "areionSoEM256x4", 1, 0),
        "vaesavx2": ("areion256SoEMPermutex4VaesAvx2.abi0", "areionSoEM256x4", 1, 0),
        "avx512": ("areion256SoEMPermutex4Interleaved.abi0", "areionSoEM256x4", 1, 0),
        "arm64": ("areion256SoEMPermutex4NEON.abi0", "areionSoEM256x4", 1, 0),
        "purego": (None, "soem256x4Software", 3, 3),
    },
    "SoEM512x4": {
        "aesni": ("areion512SoEMPermutex4AesNi.abi0", "areionSoEM512x4", 1, 0),
        "vex": ("areion512SoEMPermutex4Vex.abi0", "areionSoEM512x4", 1, 0),
        "vaesavx2": ("areion512SoEMPermutex4VaesAvx2.abi0", "areionSoEM512x4", 1, 0),
        "avx512": ("areion512SoEMPermutex4Interleaved.abi0", "areionSoEM512x4", 1, 0),
        "arm64": ("areion512SoEMPermutex4NEON.abi0", "areionSoEM512x4", 1, 0),
        "purego": (None, "soem512x4Software", 3, 3),
    },
}


def objdump_funcs(bin_path):
    out = subprocess.check_output(
        ["go", "tool", "objdump", "-s", r"^github\.com/everanium/areion\.", str(bin_path)],
        text=True,
    )
    funcs = {}
    cur = None
    insns = []
    for line in out.splitlines():
        m = re.match(r"^TEXT\s+github\.com/everanium/areion\.(\S+)\(SB\)", line)
        if m:
            if cur:
                funcs[cur] = insns
            cur = m.group(1)
            insns = []
        elif cur and "\t0x" in line:
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            if parts:
                insns.append(parts[-1])
    if cur:
        funcs[cur] = insns

    cleaned = {}
    for k, seq in funcs.items():
        while seq and (
            seq[-1].startswith("INT ")
            or seq[-1] == "UDF"
            or seq[-1] == "?"
            or seq[-1].startswith("WORD ")
        ):
            seq = seq[:-1]
        cleaned[k] = seq
    return cleaned


def parse_asm_source_epilogues(root_dir):
    res = {}
    for p in sorted(pathlib.Path(root_dir).glob("*.s")):
        cur = None
        body = []
        for line in p.read_text().splitlines():
            m = re.match(r"^TEXT\s+·(\w+)\(SB\)", line)
            if m:
                if cur:
                    res[(p.name, cur)] = body
                cur = m.group(1)
                body = []
            elif cur:
                s = line.strip()
                if s and not s.startswith("//"):
                    body.append(s)
        if cur:
            res[(p.name, cur)] = body
    return res


def summarize_epilogue_insns(lines):
    simd = 0
    gpr = 0
    vzeroupper = 0
    for l in lines:
        op = l.split()[0]
        if op in ("PXOR", "VPXOR", "VPXORD", "VEOR"):
            simd += 1
        elif op in ("XORQ", "MOVD"):
            gpr += 1
        elif op == "VZEROUPPER":
            vzeroupper += 1
    parts = []
    if simd:
        parts.append(f"{simd} SIMD")
    if gpr:
        parts.append(f"{gpr} GPR")
    if vzeroupper:
        parts.append("VZEROUPPER")
    return ", ".join(parts) if parts else "none"


def print_static_audit(v011_dir, v012_dir, f11_amd64, f12_amd64, f11_arm64, f12_arm64):
    print("== 1. Static disassembly & epilogue instruction-count audit (c74d39a vs 72a892a)")
    e11 = parse_asm_source_epilogues(v011_dir)
    e12 = parse_asm_source_epilogues(v012_dir)

    print("\n-- 1a. Assembly kernels (.abi0) across amd64 and arm64 --")
    header = (
        f"{'Arch/File':28s} {'Kernel':36s} {'c74d39a':>7s} {'72a892a':>7s} "
        f"{'+dInsn':>6s}  {'c74d39a epilogue':22s} {'72a892a epilogue'}"
    )
    print(header)
    print("-" * len(header))

    for (fname, kname) in sorted(e12.keys()):
        if kname in ("cpuid", "dumpSIMDRegs", "dirtySIMDRegForTest", "clobberScratchGPRs"):
            continue
        is_arm = "arm64" in fname
        f11 = f11_arm64 if is_arm else f11_amd64
        f12 = f12_arm64 if is_arm else f12_amd64
        sym = f"{kname}.abi0"
        n11 = len(f11.get(sym, e11.get((fname, kname), [])))
        n12 = len(f12.get(sym, e12[(fname, kname)]))
        b11 = e11.get((fname, kname), [])
        b12 = e12[(fname, kname)]
        idx = 0
        while idx < len(b11) and idx < len(b12) and b11[idx] == b12[idx]:
            idx += 1
        ep11 = summarize_epilogue_insns(b11[idx:])
        ep12 = summarize_epilogue_insns(b12[idx:])
        print(
            f"{fname:28s} {kname:36s} {n11:7d} {n12:7d} {n12 - n11:+6d}  {ep11:22s} {ep12}"
        )

    w_static_amd64 = len(f12_amd64.get("wipeSoftwareStack", []))
    c_static_amd64 = len(f12_amd64.get("clobberScratchGPRs.abi0", []))
    w_static_arm64 = len(f12_arm64.get("wipeSoftwareStack", []))
    c_static_arm64 = len(f12_arm64.get("clobberScratchGPRs.abi0", []))
    print("\n-- 1b. Shared clearing helpers added in 72a892a --")
    print(
        f"  wipeSoftwareStack (purego, 1024 B = [128]uint64 stack scrub): "
        f"amd64={w_static_amd64} static insns (94 dynamic insns/call: 16x4 MOVUPS X15 loop); "
        f"arm64={w_static_arm64} static insns (109 dynamic insns/call: 16x4 STP.P (ZR, ZR) loop)"
    )
    print(
        f"  clobberScratchGPRs.abi0 (register scrub helper):              "
        f"amd64={c_static_amd64} insns (16 PXOR X0..X15 + 13 XORQ + RET); "
        f"arm64={c_static_arm64} insns (32 VEOR V0..V31 + 27 MOVD ZR + RET)"
    )

    print("\n-- 1c. Per-interface instruction delta (+dInsn: kernel / Go wrapper+helpers) --")
    row_hdr = (
        f"{'Interface':22s} {'B':>4s} | {'purego-amd64 (st/dyn)':>21s} | {'purego-arm64 (st/dyn)':>21s} | "
        f"{'aesni':>10s} | {'vex':>10s} | {'vaesavx2':>10s} | {'avx512':>10s} | {'arm64':>10s}"
    )
    print(row_hdr)
    print("-" * len(row_hdr))
    for _, iface, nbytes in INTERFACES:
        cells = {}
        # purego on amd64 and arm64
        _, wsym_pg, n_clobber_pg, n_wipe_pg = KERNEL_MAP[iface]["purego"]
        for arch_tag, f11, f12, w_st, w_dyn, c_st, disp_dw in [
            ("purego-amd64", f11_amd64, f12_amd64, w_static_amd64, 94, c_static_amd64, 4),
            ("purego-arm64", f11_arm64, f12_arm64, w_static_arm64, 109, c_static_arm64, 1),
        ]:
            dw = len(f12.get(wsym_pg, [])) - len(f11.get(wsym_pg, []))
            sub_dw = 0
            if iface == "SoEM256x4":
                sub_dw = 2 * (len(f12["areion256Permutex4SoftwareRC"]) - len(f11["areion256Permutex4SoftwareRC"]))
            elif iface == "SoEM512x4":
                sub_dw = 2 * (len(f12["areion512Permutex4SoftwareRC"]) - len(f11["areion512Permutex4SoftwareRC"]))
            elif iface in ("Permute256x4", "InversePermute256x4", "Permute512x4", "InversePermute512x4"):
                sub_dw = disp_dw
            static_tot = dw + sub_dw + n_wipe_pg * w_st + n_clobber_pg * c_st
            dyn_tot = dw + sub_dw + n_wipe_pg * w_dyn + n_clobber_pg * c_st
            cells[arch_tag] = f"+{static_tot} (+{dyn_tot}d)"

        for tier in ["aesni", "vex", "vaesavx2", "avx512", "arm64"]:
            ksym, wsym, n_clobber, _ = KERNEL_MAP[iface][tier]
            f11 = f11_arm64 if tier == "arm64" else f11_amd64
            f12 = f12_arm64 if tier == "arm64" else f12_amd64
            dk = (len(f12.get(ksym, [])) - len(f11.get(ksym, []))) if ksym else 0
            dw = len(f12.get(wsym, [])) - len(f11.get(wsym, []))
            hw_dw = dw - 4 if iface.endswith("x4") and "Permute" in iface and tier != "arm64" else (
                dw - 1 if iface.endswith("x4") and "Permute" in iface and tier == "arm64" else dw
            )
            c_insns = c_static_arm64 if tier == "arm64" else c_static_amd64
            wrapper_tot = hw_dw + n_clobber * c_insns
            cells[tier] = f"+{dk}/+{wrapper_tot}"
        print(
            f"{iface:22s} {nbytes:4d} | {cells['purego-amd64']:>21s} | {cells['purego-arm64']:>21s} | "
            f"{cells['aesni']:>10s} | {cells['vex']:>10s} | {cells['vaesavx2']:>10s} | "
            f"{cells['avx512']:>10s} | {cells['arm64']:>10s}"
        )


def parse_bench_output(text):
    res = {}
    for line in text.splitlines():
        m = re.match(r"^(Benchmark\w+)(?:-\d+)?\s+\d+\s+([\d.]+)\s+ns/op", line)
        if m:
            res[m.group(1)] = float(m.group(2))
    return res


def run_cmd_pinned(cmd, env, cpu_pin):
    if cpu_pin is not None and shutil.which("taskset"):
        cmd = ["taskset", "-c", str(cpu_pin)] + cmd
    return subprocess.check_output(cmd, env=env, text=True, stderr=subprocess.STDOUT)


def run_ab_benchmarks(bin_v011, bin_v012, tiers, repeats, benchtime, cpu_pin):
    samples = {t: {"pre": {b: [] for b, _, _ in INTERFACES}, "post": {b: [] for b, _, _ in INTERFACES}} for t in tiers}

    for tier in tiers:
        env = os.environ.copy()
        env["AREION_FORCE_TIER"] = tier
        env["GOMAXPROCS"] = "1"
        for b, _, _ in INTERFACES:
            b_pat = f"^{b}$"
            for r in range(repeats):
                out_pre = run_cmd_pinned(
                    [str(bin_v011), "-test.run=^$", f"-test.bench={b_pat}", f"-test.benchtime={benchtime}"],
                    env,
                    cpu_pin,
                )
                out_post = run_cmd_pinned(
                    [str(bin_v012), "-test.run=^$", f"-test.bench={b_pat}", f"-test.benchtime={benchtime}"],
                    env,
                    cpu_pin,
                )
                p_pre = parse_bench_output(out_pre)
                p_post = parse_bench_output(out_post)
                if b in p_pre:
                    samples[tier]["pre"][b].append(p_pre[b])
                if b in p_post:
                    samples[tier]["post"][b].append(p_post[b])
    return samples


def run_pprof_attribution(bin_v012, tiers, prof_dir, benchtime, cpu_pin):
    bench_regex = "^(" + "|".join(b for b, _, _ in INTERFACES) + ")$"
    results = {}
    for tier in tiers:
        env = os.environ.copy()
        env["AREION_FORCE_TIER"] = tier
        env["GOMAXPROCS"] = "1"
        prof_path = pathlib.Path(prof_dir) / f"prof_{tier}.pb.gz"
        run_cmd_pinned(
            [
                str(bin_v012),
                "-test.run=^$",
                f"-test.bench={bench_regex}",
                f"-test.benchtime={benchtime}",
                f"-test.cpuprofile={prof_path}",
            ],
            env,
            cpu_pin,
        )
        top_out = subprocess.check_output(
            [
                "go",
                "tool",
                "pprof",
                "-top",
                "-nodefraction=0",
                "-edgefraction=0",
                "-nodecount=200",
                str(bin_v012),
                str(prof_path),
            ],
            text=True,
            stderr=subprocess.STDOUT,
        )
        wipe_flat_pct = 0.0
        wipe_cum_pct = 0.0
        clobber_flat_pct = 0.0
        clobber_cum_pct = 0.0
        total_s = 0.0
        for line in top_out.splitlines():
            m_tot = re.search(r"Total samples = ([\d.]+)(ms|s)", line)
            if m_tot:
                val = float(m_tot.group(1))
                total_s = val / 1000.0 if m_tot.group(2) == "ms" else val
            if "wipeSoftwareStack" in line:
                parts = line.split()
                # flat flat% sum% cum cum% name
                if len(parts) >= 5 and parts[1].endswith("%") and parts[4].endswith("%"):
                    wipe_flat_pct = float(parts[1].rstrip("%"))
                    wipe_cum_pct = float(parts[4].rstrip("%"))
            elif "clobberScratchGPRs" in line:
                parts = line.split()
                if len(parts) >= 5 and parts[1].endswith("%") and parts[4].endswith("%"):
                    clobber_flat_pct = float(parts[1].rstrip("%"))
                    clobber_cum_pct = float(parts[4].rstrip("%"))
        results[tier] = {
            "total_s": total_s,
            "wipe_flat_pct": wipe_flat_pct,
            "wipe_cum_pct": wipe_cum_pct,
            "clobber_flat_pct": clobber_flat_pct,
            "clobber_cum_pct": clobber_cum_pct,
        }
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true", help="fewer repeats and shorter benchtime")
    ap.add_argument("--repeats", type=int, default=None, help="A/B repeats per tier (default: 5 full, 2 quick)")
    ap.add_argument("--benchtime", default=None, help="go test -benchtime per benchmark (default: 60ms full, 25ms quick)")
    ap.add_argument("--cpu", type=int, default=7, help="CPU core for taskset pinning (default: 7)")
    args = ap.parse_args()

    repeats = args.repeats if args.repeats is not None else (2 if args.quick else 5)
    benchtime = args.benchtime if args.benchtime is not None else ("25ms" if args.quick else "60ms")
    prof_benchtime = "40ms" if args.quick else "120ms"

    is_arm64_host = platform.machine() in ("aarch64", "arm64")
    active_tiers = TIERS_ARM64 if is_arm64_host else TIERS_AMD64
    ref_ghz = REF_GHZ_ARM64 if is_arm64_host else REF_GHZ_AMD64
    host_label = "AWS Graviton 4 (Neoverse V2)" if is_arm64_host else "Intel Core i7-11700K"
    sec_label = "2b" if is_arm64_host else "2a"

    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="areion-clearing-"))
    wt_dir = tmpdir / "v011"
    try:
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(wt_dir), PRE_COMMIT],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        bin_v011_amd64 = tmpdir / "bench_v011_amd64.test"
        bin_v012_amd64 = tmpdir / "bench_v012_amd64.test"
        bin_v011_arm64 = tmpdir / "bench_v011_arm64.test"
        bin_v012_arm64 = tmpdir / "bench_v012_arm64.test"

        env_amd = os.environ.copy()
        env_amd["GOARCH"] = "amd64"
        subprocess.run(["go", "test", "-c", "-o", str(bin_v011_amd64), "."], cwd=wt_dir, env=env_amd, check=True)
        subprocess.run(["go", "test", "-c", "-o", str(bin_v012_amd64), "."], cwd=ROOT, env=env_amd, check=True)

        env_arm = os.environ.copy()
        env_arm["GOARCH"] = "arm64"
        subprocess.run(["go", "test", "-c", "-o", str(bin_v011_arm64), "."], cwd=wt_dir, env=env_arm, check=True)
        subprocess.run(["go", "test", "-c", "-o", str(bin_v012_arm64), "."], cwd=ROOT, env=env_arm, check=True)

        f11_amd64 = objdump_funcs(bin_v011_amd64)
        f12_amd64 = objdump_funcs(bin_v012_amd64)
        f11_arm64 = objdump_funcs(bin_v011_arm64)
        f12_arm64 = objdump_funcs(bin_v012_arm64)

        print_static_audit(wt_dir, ROOT, f11_amd64, f12_amd64, f11_arm64, f12_arm64)

        bin_v011_live = bin_v011_arm64 if is_arm64_host else bin_v011_amd64
        bin_v012_live = bin_v012_arm64 if is_arm64_host else bin_v012_amd64

        print(
            f"\n== {sec_label}. Interleaved A/B microbenchmarks — {host_label} ({repeats} interleaved pairs/tier, "
            f"-benchtime={benchtime}, CPU core {args.cpu}, c/B at {ref_ghz:.2f} GHz)"
        )
        samples = run_ab_benchmarks(bin_v011_live, bin_v012_live, active_tiers, repeats, benchtime, args.cpu)

        for tier in active_tiers:
            print(f"\n-- Tier: {tier} --")
            hdr = (
                f"{'Interface':22s} {'B':>4s} {'c74d39a ns':>11s} {'72a892a ns':>11s} "
                f"{'d_ns':>9s} {'c74d39a c/B':>12s} {'72a892a c/B':>12s} {'d_c/B':>9s} {'d_%':>8s}"
            )
            print(hdr)
            print("-" * len(hdr))
            for bname, dname, nbytes in INTERFACES:
                pre_list = samples[tier]["pre"][bname]
                post_list = samples[tier]["post"][bname]
                pre_ns = statistics.median(pre_list)
                post_ns = statistics.median(post_list)
                dns = post_ns - pre_ns
                pre_cb = (pre_ns * ref_ghz) / nbytes
                post_cb = (post_ns * ref_ghz) / nbytes
                dcb = post_cb - pre_cb
                dpct = (dns / pre_ns) * 100.0 if pre_ns else 0.0
                print(
                    f"{dname:22s} {nbytes:4d} {pre_ns:11.2f} {post_ns:11.2f} "
                    f"{dns:+9.2f} {pre_cb:12.3f} {post_cb:12.3f} {dcb:+9.3f} {dpct:+7.1f}%"
                )

        print(f"\n== 3. CPU profile attribution (go tool pprof, -benchtime={prof_benchtime})")
        pprof_res = run_pprof_attribution(bin_v012_live, active_tiers, tmpdir, prof_benchtime, args.cpu)
        phdr = (
            f"{'Tier':14s} {'Samples (s)':>12s} {'wipeSoftwareStack (flat/cum)':>30s} "
            f"{'clobberScratchGPRs (flat/cum)':>31s}"
        )
        print(phdr)
        print("-" * len(phdr))
        for tier in active_tiers:
            pr = pprof_res[tier]
            w_str = f"{pr['wipe_flat_pct']:.2f}% / {pr['wipe_cum_pct']:.2f}%"
            c_str = f"{pr['clobber_flat_pct']:.2f}% / {pr['clobber_cum_pct']:.2f}%"
            print(f"{tier:14s} {pr['total_s']:12.2f} {w_str:>30s} {c_str:>31s}")
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(wt_dir)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if tmpdir.exists():
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
