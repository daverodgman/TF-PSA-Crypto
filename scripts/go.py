#!/usr/bin/env python3

import os
import time
import argparse
import datetime
import json
import shutil
import subprocess
import statistics
from deepdiff import DeepDiff

# 0 = only end results, 1 = brief, 2 = full
VERBOSE = 1
#args.bench = 15 # 5 ok, 9 good, 15 best. about 1.5s for one run of AES-GCM-128, ie 15x = 6m for all non-ctr cfgs

OPT_DEFS = {
}

HASHES = {"baseline": "350639635", "v1": "4a7deab20"}

# subset of above - the set tested with -X, mapped to CLI argument
VARIANT_FLAGS = {
    "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH": "only_128",
    "MBEDTLS_AESCE_C": "aesce",
    #"PSA_WANT_ALG_GCM": "gcm",
    #"PSA_WANT_ALG_CTR": "ctr",
    #"PSA_WANT_KEY_TYPE_AES": "aes",
    #"PSA_WANT_KEY_TYPE_CAMELLIA": "camellia",
    #"MBEDTLS_AES_USE_HARDWARE_ONLY": None,
    #"MBEDTLS_BLOCK_CIPHER_NO_DECRYPT": None,
    "MBEDTLS_AESCE_OPTIMISE_FOR_SIZE": "opt_size"
}

VALIDATION_VARIANT_FLAGS = {
    "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH": "only_128",
    "MBEDTLS_AESCE_C": "aesce",
    "PSA_WANT_ALG_GCM": "gcm",
    "PSA_WANT_ALG_CTR": "ctr",
    "PSA_WANT_KEY_TYPE_AES": "aes",
    "PSA_WANT_KEY_TYPE_CAMELLIA": "camellia",
    "PSA_WANT_KEY_TYPE_ARIA": "aria",
    "PSA_WANT_KEY_TYPE_CHACHA20": "chacha",
    "MBEDTLS_AES_USE_HARDWARE_ONLY": None,
    "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT": None,
    "MBEDTLS_AESCE_OPTIMISE_FOR_SIZE": "opt_size"
}

# these are the ones that must be defined, are logged, etc
LOG_FLAGS = [
    "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH",
    "MBEDTLS_AESCE_C",
    "PSA_WANT_ALG_GCM",
    "PSA_WANT_ALG_CTR",
    "MBEDTLS_AES_USE_HARDWARE_ONLY",
    "MBEDTLS_BLOCK_CIPHER_NO_DECRYPT",
    "MBEDTLS_AESCE_OPTIMISE_FOR_SIZE"
]

CFLAGS    = "-Wno-unused-parameter -Wno-unused-variable -Os -Wno-unreachable-code -Wno-unused-parameter -Wno-unused-label -Wno-type-limits -Wno-uninitialized "
COMPILERS = ["clang-17", "gcc-15"] # "clang-17", "gcc-15", "clang-21" ]
OPTS      = []
OPT_FLAG  = "-Os"
CCACHE    = True

BENCH_SLEEP = 0  #.25


ALWAYS_FAST_CLEAN = False
ROOT       = "/Users/davrod01/code/mbedtls/TF-PSA-Crypto"
BUILD_DIR  = f"{ROOT}/build"
OPTS_FILE  = f"{ROOT}/drivers/builtin/src/opts.h"
if False:
    TEST_SUITES = [ "test_suite_chacha20",
                "test_suite_aria",
                "test_suite_camellia",
                "test_suite_cipher.chacha20",
                "test_suite_cipher.gcm",
                "test_suite_gcm.camellia",
                "test_suite_gcm.aes128_de",
                "test_suite_gcm.aes128_en",
                "test_suite_gcm.aes192_de",
                "test_suite_gcm.aes192_en",
                "test_suite_gcm.aes256_de",
                "test_suite_gcm.aes256_en",
                "test_suite_aes.ctr",
                "test_suite_aes.ecb" ]
else:
    TEST_SUITES = [
                "test_suite_cipher.aes",
                "test_suite_aes.rest",
                #"test_suite_aes.ctr"
                "test_suite_gcm.aes128_de",
                "test_suite_gcm.aes128_en"
                ]

LOG        = f"{ROOT}/scripts/log.json"
CRYPTO_CONFIG_FILE = f"{ROOT}/include/psa/crypto_config.h"


TEMP_COMMIT_MSG = "temp commit for benchmarking"

SHOW_RAW_BUILD = False
SHOW_RAW_BENCH = False
SHOW_RAW_TEST  = False

BENCHMARKS = ["aes_gcm", "aes_ctr" ] #"ctr_drbg", ]

NO_MATCH_KEYS = ["MBEDTLS_AESCE_GCM_MULTIBLOCK"]

NO_SHOW_KEYS = {}# "MBEDTLS_AES_USE_HARDWARE_ONLY" }

PATCHES = [
    {
        "hash": "734ac30e9cfb9d2dbcf072e5079d698b8032ebd5",
        "note": "config",
        "when": "build"
    },
    {
        "hash": "0e903c7e629f750400b20219ad9f057d96f4c493",
        "note": "gitignore",
        "when": "always"
    },
    {
        "hash": "c61b64b791284e689155fd30e37f4e547c2e960a",
        "note": "reduce over-testing in existing test",
        "when": "build"
    },
    {
        "hash": "654ad57624be61077f3892cfe4951f6afd06e20e",
        "note": "add test",
        "when": "build"
    }
]

def gen_opt_combos():
    if args.full_test:
        # generate cross-product of OPTIONS
        ls = [{}]
        for o in VARIANT_FLAGS:
            l2 = []
            for d in ls:
                for b in (True, False):
                    cli_arg_name = VARIANT_FLAGS[o]
                    if cli_arg_name:
                        # don't vary if specified at cli
                        cli_arg_value = getattr(args, cli_arg_name) if cli_arg_name is not None else None
                        if cli_arg_value not in (b, None):
                            continue
                    d = d.copy()
                    if o == "MBEDTLS_AESCE_OPTIMISE_FOR_SIZE": b = 1 if b else 0
                    d.update({o: b})
                    l2.append(d)
            ls = l2
    else:
        # generate a single set of options based on CLI flags
        ls = [{
            "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH": args.only_128 if args.only_128 is not None else True,
            "MBEDTLS_AESCE_C": args.aesce if args.aesce is not None else True,
            "PSA_WANT_ALG_GCM": args.gcm if args.gcm is not None else True,
            "PSA_WANT_ALG_CTR": args.ctr if args.ctr is not None else False
        }]

    # add OPT = 1, OPT = 2, ...
    for opt_n, opt_vs in OPT_DEFS.items():
        l2 = []
        for opt_v in opt_vs:
            for d in ls:
                d = {k:v for k, v in d.items()}
                d[opt_n] = opt_v
                l2.append(d)
        ls = l2

    # add derived or missing options
    for d in ls:
        d.setdefault("MBEDTLS_AES_USE_HARDWARE_ONLY", d["MBEDTLS_AESCE_C"])
        d.setdefault("MBEDTLS_BLOCK_CIPHER_NO_DECRYPT", True)
        d.setdefault("PSA_WANT_ALG_CTR", args.ctr == True)
        d.setdefault("PSA_WANT_ALG_GCM", args.gcm in {None, True})
        d.setdefault("MBEDTLS_AESCE_OPTIMISE_FOR_SIZE", args.opt_size in {None, True})
        d.setdefault("PSA_WANT_KEY_TYPE_CAMELLIA", args.camellia == True)
        d.setdefault("PSA_WANT_KEY_TYPE_ARIA", args.aria == True)
        d.setdefault("PSA_WANT_KEY_TYPE_CHACHA20", args.chacha == True)
        d.setdefault("PSA_WANT_KEY_TYPE_AES", args.aes in {None, True})
        d.setdefault("MBEDTLS_CTR_DRBG_C",      d["PSA_WANT_KEY_TYPE_AES"])
        d.setdefault("MBEDTLS_HMAC_DRBG_C", not d["PSA_WANT_KEY_TYPE_AES"])
        #d.setdefault("PSA_WANT_ALG_ECB_NO_PADDING", True)

        #tl = "PSA_WANT_ALG_CTR PSA_WANT_ALG_CCM PSA_WANT_ALG_CBC"
        #for x in tl.split():
        #    d.setdefault(x, True)
        #d.setdefault("MBEDTLS_AES_C",      d["PSA_WANT_KEY_TYPE_AES"])
        #d.setdefault("MBEDTLS_CAMELLIA_C", d["PSA_WANT_KEY_TYPE_CAMELLIA"])
        d.setdefault("MBEDTLS_MD_C",       d["MBEDTLS_HMAC_DRBG_C"])
        #d.setdefault("MBEDTLS_CCM_C", True)
        #d.setdefault("PSA_WANT_ALG_CBC", False)
        #d.setdefault("MBEDTLS_CIPHER_MODE_CBC", False)
        #d.setdefault("MBEDTLS_CIPHER_PADDING_PKCS7", True)
        #d.setdefault("MBEDTLS_CIPHER_MODE_CFB", True)
        #d.setdefault("MBEDTLS_CIPHER_MODE_CTR", True)

    def option_varies(o):
        os = [d.get(o, False) for d in ls]
        return not( all(os) or all(not x for x in os) )

    # remove not-useful combinations
    ls2 = []
    for d in ls:
        if d["MBEDTLS_AES_USE_HARDWARE_ONLY"] and not d["MBEDTLS_AESCE_C"]: continue
        #if not (d["PSA_WANT_ALG_GCM"] or d["PSA_WANT_ALG_CTR"]): continue
        if not (d["PSA_WANT_KEY_TYPE_AES"] or d["PSA_WANT_KEY_TYPE_CAMELLIA"]): continue
        if option_varies("MBEDTLS_AESCE_OPTIMISE_FOR_SIZE"):
            if d["MBEDTLS_AESCE_OPTIMISE_FOR_SIZE"] == 1 and not d["MBEDTLS_AESCE_C"]: continue
        if not d["MBEDTLS_HMAC_DRBG_C"] and not d["MBEDTLS_CTR_DRBG_C"]: continue
        ls2.append(d)
    ls = ls2

    # remove dupes
    ls2 = []
    for d in ls:
        for e in ls2:
            dl = sorted((k, v) for k, v in d.items())
            el = sorted((k, v) for k, v in e.items())
            if dl == el:
                break
        else:
            ls2.append(d)
    ls = ls2

    # check all main flags defined
    for x in LOG_FLAGS:
        for d in ls:
            assert(x in d)

    # combine with compilers
    ls2 = []
    for cc in args.compilers:
        for l in ls:
            ls2.append({"cc": cc, "options": l})

    return ls2


def update_file(fn, content):
    with open(fn) as f:
        content_current = f.read()
    if content != content_current:
        with(open(fn, "w")) as f:
             f.write(content)


def write_opts(l):
    s = "#ifndef OPTS_H\n#define OPTS_H\n\n"
    # #ifndef MBEDTLS_AESCE_C\n#define MBEDTLS_AESCE_C 1\n#endif\n\n"
    for o, e in l["options"].items():
        if not o in OPT_DEFS.keys(): continue
        #if o.startswith("MBEDTLS_") and not o in VARIANT_FLAGS.keys(): continue
        #if o.startswith("PSA_"): continue
        s += f"#define {o} {e}\n"
    s += "#endif"
    update_file(OPTS_FILE, s)
    

def set_config(config):
    ls = []
    ls.append("// START TEST SECTION")
    for c, e in config["options"].items():
        if c == "MBEDTLS_AESCE_OPTIMISE_FOR_SIZE":
            ls.append(f"#define MBEDTLS_AESCE_OPTIMISE_FOR_SIZE {str(int(e))}")
        else:
            v = " 1" if c.startswith("PSA_") else ""
            comment = "" if e else "//"
            ls.append(f"{comment}#define {c}{v}")
    ls.append("// END TEST SECTION")
    ls.append("")
    ls = [x + "\n" for x in ls]

    with open(CRYPTO_CONFIG_FILE) as f:
        fs = f.readlines()
    fs_raw = fs[:]
    fs2 = fs[:]
    
    fs2 = []
    in_test_sec = False
    for i, l in enumerate(fs):
        if l.startswith("// START TEST SECTION"):
            in_test_sec = True
        if i > 1 and fs[i - 2].startswith("// END TEST SECTION"):
            in_test_sec = False
        if not in_test_sec:
            fs2.append(l)
    fs = fs2

    if True:
        for i, l in enumerate(fs):
            for c in config["options"]:
                if l.startswith(f"#define {c}"):
                    fs[i] = "//" + fs[i]

    if True:
        for i, l in enumerate(fs):
            if l.startswith("#define PSA_CRYPTO_CONFIG_H"):
                fs2 = fs[:i] + ls + fs[i:]
    
    if "".join(fs_raw) != "".join(fs2):
        content = "".join(fs2)
        update_file(CRYPTO_CONFIG_FILE, content)


def run(cmd: str, env={}, fatal=True, dir=None, verbose=False) -> tuple[int, str]:
    e = {}
    e.update(os.environ)
    e.update(env)
    result = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=e,
        cwd=dir
    )
    if verbose or (result.returncode != 0 and fatal):
        print(result.stdout)
        print()
        print(cmd)
        print(f"returncode: {result.returncode}")
        if result.returncode != 0 and fatal:
            exit(result.returncode)
    return (result.returncode, result.stdout)


def cmake(cc):
    bdir = f"{BUILD_DIR}/{cc.split("/")[-1]}"
    if cc == "clang-17":
        cc = "/usr/bin/clang"
    elif cc == "gcc-15":
        cc = "/opt/homebrew/bin/gcc-15"
    elif cc == "clang-21":
        cc = "/opt/homebrew/opt/llvm/bin//clang-21"
    else:
        assert(False)
    cflags = f"{OPT_FLAG} {CFLAGS}"
    if "gcc" in cc:
        cflags += " -march=armv8.4-a+crypto+sha3+simd "
        cflags += " -Wno-unused-but-set-variable"
        cflags += " -Wno-unused-function"
        cflags += " -Wno-discarded-qualifiers"
    else:
        cflags += " -Wno-error=unused-variable "
        cflags += " -Wno-error=unused-but-set-variable "
        cflags += " -Wno-error=unused-function "
        cflags += " -fcolor-diagnostics "
        cflags += " -Wno-error=incompatible-pointer-types-discards-qualifiers "
    try:
        shutil.rmtree(bdir, ignore_errors=True)
    except:
        pass
    ccflags = \
        f"-DCMAKE_C_COMPILER={cc} " \
        f"-DCMAKE_CXX_COMPILER={cc} "     \
        f"-DCMAKE_C_FLAGS=\"{cflags}\" " \
        f"-DCMAKE_CXX_FLAGS=\"{cflags}\" "

    ccache = "-DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache" if CCACHE else ""

    cmd = f"cmake -S {ROOT} -B {bdir} {ccflags} {ccache}"
    run(cmd, env={"CFLAGS": CFLAGS}, verbose=SHOW_RAW_BUILD)


def current_cc():
    try:
        assert(False)
        with open(f"{BUILD_DIR}/{cc}/CMakeCache.txt") as f:
            ls = f.readlines()
        for l in ls:
            if l.startswith("CMAKE_C_COMPILER:STRING"):
                cc = l.split("/")[-1].strip()
                if cc == "clang": cc = "clang-17"
                return cc
    except:
        return None


def build(config):
    tests = [
        ""
    ]
    #os.makedirs(f"{BUILD_DIR}/{config["cc"]}/programs/test", exist_ok=True)
    #os.makedirs(f"{BUILD_DIR}/{config["cc"]}/core", exist_ok=True)
    #os.makedirs(f"{BUILD_DIR}/{config["cc"]}/tests", exist_ok=True)
    os.makedirs(f"{BUILD_DIR}/{config["cc"]}", exist_ok=True)

    set_config(config)
    #write_opts(config)

    #if current_cc() != config["cc"]:
    #    clean = True

    if args.clean or args.cmake:
        if VERBOSE >= 2: print("full clean")
        #run(f"make -C {BUILD_DIR}/{config["cc"]} clean", verbose=SHOW_RAW_BUILD)
        run(f"rm -rf {BUILD_DIR}/{config["cc"]}")
    else:
        if ALWAYS_FAST_CLEAN:
            if VERBOSE >= 2: print("fast clean")
            for x in \
                ["tests/" + x for x in TEST_SUITES] + \
                ["tests/CMakeFiles/{t}.dir/" for t in TEST_SUITES] + \
                ["drivers/builtin/CMakeFiles/builtin.dir/src/aesce.c.o",
                 "drivers/builtin/CMakeFiles/builtin.dir/src/aesce.c.o.d",
                 "drivers/builtin/CMakeFiles/builtin.dir/src/aes.c.o",
                 "drivers/builtin/CMakeFiles/builtin.dir/src/gcm.c.o",
                 "programs/test/benchmark", "core/libtfpsacrypto.a"]:
                p = f"{BUILD_DIR}/{config["cc"]}/{x}"
                if os.path.exists(p):
                    if os.path.isdir(p):
                        shutil.rmtree(p)
                    else:
                        os.remove(p)

    cmakefile = f"{BUILD_DIR}/{config["cc"]}/CMakeCache.txt"
    if args.cmake or not os.path.exists(cmakefile):
        if VERBOSE >= 2: print("cmake")
        cmake(config["cc"])

    bench = args.bench
    test  = args.test #or (not args.bench)
    test |= args.bench != 0
    test &= len(TEST_SUITES) > 0
    if VERBOSE >= 2: print("make")
    
    build_cmds = []
    if test:
        build_cmds.append(("tests", " ".join(TEST_SUITES)))
    if bench:
        build_cmds.append(("programs/test", "benchmark"))
    if not build_cmds:
        build_cmds.append(("core", "tfpsacrypto"))

    for d, t in build_cmds:
        cmd1 = "make VERBOSE=0 --silent -j12 "
        cmd = f"-C {BUILD_DIR}/{config["cc"]}/{d} {t}"
        rc, _ = run(cmd1 + cmd, verbose=False, fatal=False)
        if rc != 0:
            cmd1 = f"make VERBOSE=0 --silent -j1 "
            run(cmd1 + cmd, verbose=False, fatal=False)
            cmd1 = f"make VERBOSE=1 -j1 "
            run(cmd1 + cmd, verbose=True, fatal=False)
            print()
            print("FAILED TO BUILD")
            print(config2str(config))
            exit(1)

    if args.size:
        size = get_size(config, quiet=True)
        size = {k: v for k, v in size.items() if k in {"aes.c","aesce.c", "gcm.c"}}
        print(json.dumps(size, indent=4))


def test(config):
    results = {}
    for s in TEST_SUITES:
        rc, output = run(f"{BUILD_DIR}/{config["cc"]}/tests/{s}", verbose=False)
        #print(s,rc)
        results[s] = {
            "output": output.splitlines()[-1] if rc == 0 else output,
            "rc": rc
        }
    return results


def get_size(config, quiet=True):
    _, output = run(f"size {BUILD_DIR}/{config["cc"]}/core/libtfpsacrypto.a")
    ls = output.strip().split("\n")[1:]
    #ls = [l.split("\t")[:2] + [l.split("\t")][-1] for l in ls if "aes" in l and not "aesni" in l]
    ls = [l.split("\t") for l in ls]
    ls = [l for l in ls if l[0] + l[1] != "00"]
    ls = sorted(ls, key=lambda t:int(t[0]) + int(t[1]))
    ls = [l[:-1] + [l[-1].split("(")[-1][:-3]] for l in ls]
    if not quiet:
        for x in ls:
            print("\t".join(x))
    
    size = {
    }
    sm = 0
    for l in ls:
        src = l[-1]
        st = int(l[0])
        sd = int(l[1])
        size[src] = { "text": st, "data": sd, "sum": st + sd }
        sm += st + sd
    size["total"] = sm
    size["aes"] = sum(size[x]["sum"] for x in size.keys() if "aes" in x or "gcm" in x)
    return size


def bench(config):
    hashes = get_hash()
    timestamp = datetime.datetime.now().isoformat()
    size = get_size(config, quiet=True)

    if args.test:
        if VERBOSE >= 2: print("test")
        test_result = test(config)
        for t, r in test_result.items():
            if r["rc"] == 0:
                #if not args.quiet: print(f"    {t}: ok")
                if SHOW_RAW_TEST:
                    print(r['output'])
            else:
                print(f"{t} FAILED\n{r['output']}\n")
    else:
        test_result = {"skipped": True, "suite": " ".join(TEST_SUITES), "returncode": None, "output": None}
    best_results = {}
    raw_results = {}
    if args.bench:
        if VERBOSE >= 2: print(f"bench (n={args.bench})")
        # TODO handle multiple algs better
        for i in range(0, args.bench):
            if i > 0: time.sleep(BENCH_SLEEP)
            for bench in BENCHMARKS:
                if "ctr" in bench and not config["options"]["PSA_WANT_ALG_CTR"]:
                    continue
                if "gcm" in bench and not config["options"]["PSA_WANT_ALG_GCM"]:
                    continue
                cmd = f"{BUILD_DIR}/{config["cc"]}/programs/test/benchmark {bench}"
                rc, output = run(cmd, verbose=False, fatal=False)
                if "FAILED:" in output:
                    fl = [l for l in output.splitlines() if "FAILED:" in l]
                    if config["options"]["MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"]:
                        fl = [l for l in fl if not ("-192" in l or "-256" in l)]
                    if fl:
                        print("ERROR in benchmarking:\n")
                        print(output + "\n\n")
                        print(config2str(config))
                        exit(1)
                if SHOW_RAW_BENCH and i == (args.bench - 1): print(output + "\n\n")
                #assert(rc == 0)
                br = {l.split(":")[0].strip(): float(l.split(":")[1].strip().split()[0]) / 1024 for l in output.split("\n") if "KiB/s" in l}
                for k, v in br.items():
                    if config["options"]["MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"] and ("-192" in k or "-256" in k):
                        continue
                    raw_results.setdefault(k, []).append(v)
        for k in raw_results:
            best_results[k] = max(raw_results[k])
    result = {
        "size": size,
        "hash_tmp": hashes[0],
        "hash": hashes[1],
        "timestamp": timestamp,
        "test": test_result,
        "config": config,
        "raw_perf": raw_results,
        "best_perf": best_results
    }
    return result


def run_contains(search, cmd):
    rc, output = run(cmd)
    assert(rc == 0)
    return search in output


def get_hash(_result=[]):
    """get hash for current tree: (temp commit, actual commit)"""
    if not _result:
        changed = [x for x in run("git status --porcelain")[1].splitlines() if not x.startswith("?? ")]
        changed = [x for x in changed if x.split()[-1] not in ["framework", "include/psa/crypto_config.h" ]]
        if not changed:
            hashes = (None, run("git log -1 --format=%h")[1].strip())
        else:
            run("git add -u .")
            run(f"git commit -m '{TEMP_COMMIT_MSG}'")
            hashes = run("git log -2 --format=%h")[1].split("\n")
            run("git reset --mixed HEAD~1")
        _result.append(hashes)
    return _result[0]


def log_result(result):
    if os.path.exists(LOG):
        with open(LOG, "r") as f:
            j = json.loads(f.read())
        id = max(x["id"] for x in j) + 1
    else:
        j = []
        id = 0
    result["id"] = id
    j.append(result)
    with open(LOG, "w") as f:
        f.write(json.dumps(j, indent=4))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-L", "--baseline", action="store", default=None)

    parser.add_argument("-l", "--log", action="store_true", default=False)

    parser.add_argument("-c", "--clean", action="store_true", default=False)
    parser.add_argument("-m", "--cmake", action="store_true", default=False)

    parser.add_argument("-b", "--bench", action="store", type=int, nargs="?", default=0, const=3)
    parser.add_argument("-B", "--no-bench", action="store_true", default=False)
    parser.add_argument("-t", "--test", action="store_true", default=True)
    parser.add_argument("-T", "--no-test", action="store_true", default=False)


    parser.add_argument("-a", "--aesce", action="store_true", default=None)
    parser.add_argument("-A", "--no-aesce", action="store_true", default=None)
    parser.add_argument("-o", "--only-128", action="store_true", default=None)
    parser.add_argument("-O", "--no-only-128", action="store_true", default=None)
    parser.add_argument("-g", "--gcm", action="store_true", default=None)
    parser.add_argument("-G", "--no-gcm", action="store_true", default=None)
    parser.add_argument("--no-ctr", action="store_true", default=None)
    parser.add_argument("-OS", "--no-opt-size", action="store_true", default=None)
    parser.add_argument("-os", "--opt-size", action="store_true", default=None)

    parser.add_argument("--ctr", action="store_true", default=None)
    parser.add_argument("--gcc", action="store_true", default=None)
    parser.add_argument("--clang", action="store_true", default=None)

    parser.add_argument("-X", "--full-test", action="store_true", default=False)
    #parser.add_argument("-Y", "--no-config-change", action="store_true", default=False)
    parser.add_argument("-V", "--full-validate", action="store_true", default=False)
    parser.add_argument("-q", "--quiet", action="store_true", default=False)
    parser.add_argument("-Z", "--no-change-crypto-config", action="store_true", default=False)
    parser.add_argument("-H", "--hash", action="store", const="HEAD", help="print results for given hash", nargs="?")
    parser.add_argument("--rebuild", action="store_true", default=False)
    parser.add_argument("--size", action="store_true", default=False)

    parser.add_argument("--camellia", action="store_true", default=None)
    parser.add_argument("--no-camellia", action="store_true", default=None)
    parser.add_argument("--aria", action="store_true", default=None)
    parser.add_argument("--no-aria", action="store_true", default=None)
    parser.add_argument("--chacha", action="store_true", default=None)
    parser.add_argument("--no-chacha", action="store_true", default=None)
    parser.add_argument("--aes", action="store_true", default=None)
    parser.add_argument("--no-aes", action="store_true", default=False)

    args = parser.parse_args()

    if args.full_validate:
        global VARIANT_FLAGS
        VARIANT_FLAGS = VALIDATION_VARIANT_FLAGS
        args.bench = False
        args.test = True
        args.full_test = True

    if args.no_camellia: args.camellia = False
    if args.no_aes: args.aes = False
    if args.no_chacha: args.chacha = False
    if args.no_aria: args.aria = False
    args.aesce = False if args.no_aesce else args.aesce
    args.gcm = False if args.no_gcm else args.gcm
    args.only_128 = False if args.no_only_128 else args.only_128
    args.opt_size = False if args.no_opt_size else args.opt_size
    args.ctr = False if args.no_ctr else args.ctr

    if args.no_bench: args.bench = 0
    args.bench = args.bench

    if args.full_test:
        #args.bench = True
        #args.quiet = True
        pass

    args.test  &= not args.no_test

    # decode branch names etc
    if args.hash in HASHES: args.hash = HASHES[args.hash]
    if args.baseline in HASHES: args.baseline = HASHES[args.baseline]
    if args.hash is not None:
        args.hash = run(f"git log -1 --format=%h {args.hash}")[1].strip()
    if args.baseline is not None:
        args.baseline = run(f"git log -1 --format=%h {args.baseline}")[1].strip()

    if args.gcc:
        args.compilers = ["gcc-15"]
    elif args.clang:
        args.compilers = ["clang-17"]
    else:
        args.compilers = COMPILERS
    return args


def get_results(hash=None):
    with open(LOG, "r") as f:
        j = json.loads(f.read())
    return [x for x in j if hash.startswith(x["hash"])]


def fixup_results():
    #todo remove
    with open(LOG, "r") as f:
        j = json.loads(f.read())
    j2 = []
    for i, x in enumerate(j):
        x["id"] = i
        if x["hash"] == "112bd9c97":
            x["comment"] = "baseline"
        j2.append(x)

    if True and j2:
        with open(LOG, "w") as f:
            f.write(json.dumps(j2, indent=4))

#fixup_results()
#exit(0)


def get_data_from_log_raw(config, hash):
    with open(LOG, "r") as f:
        raw_log = json.loads(f.read())

    # newest first
    j = list(reversed([x for x in raw_log if \
                       x["hash"].startswith(hash) or hash.startswith(x["hash"]) \
                       or \
                        (x["hash_tmp"] is not None and \
                            (x["hash_tmp"].startswith(hash) or hash.startswith(x["hash_tmp"])) \
                        ) \
                    ]))

    #for d in j:
    #    if "OPT_SIZE_PERF" in d["config"]["options"] and "MBEDTLS_AESCE_OPTIMISE_FOR_SIZE" not in d["config"]["options"]:
    #        d["config"]["options"]["MBEDTLS_AESCE_OPTIMISE_FOR_SIZE"] = 1 - d["config"]["options"]["OPT_SIZE_PERF"]

    ct = set((k,v) for k, v in config["options"].items() if
            not k.startswith("OPT_")
            and k not in NO_MATCH_KEYS
        )

    for x in j:
        xc = x["config"]
        if xc["cc"] != config["cc"]:
            continue
        xt = set((k,v) for k, v in xc["options"].items() if
                not k.startswith("OPT_")
                and k not in NO_MATCH_KEYS
            )
        # match if all tuples in log config match current config
        # ie current may be a superset
        if all(t in ct for t in xt):
            yield x
        #else:
        #    print("not ss:", [t for t in xt if t not in ct])
    #exit(0)


def get_data_from_log(config, hash, aggregate=True):
    datas = list(get_data_from_log_raw(config, hash))
    if not datas: return None
    if not aggregate:
        return datas[0]
    ds = []
    if len(datas) >= 2:
        for d in datas:
            if DeepDiff(d["size"], datas[0]["size"], ignore_order=True):
                # different size info, skip
                continue
            ds.append(d)
    else:
        ds = datas

    r = {
        "size": ds[0]["size"],
        "hash": ds[0]["hash"],
        "raw_perf": {},
        "best_perf": {}
    }

    for d in ds:
        for k, v in d["raw_perf"].items():
            r["raw_perf"].setdefault(k, [])
            r["raw_perf"][k] += v

    for k in r["raw_perf"]:
        best = max(r["raw_perf"][k])
        r["best_perf"][k] = best

    return r


def get_tag():
    hs = run('git log -2 --format="%h"')[1].strip().splitlines()
    if "112bd9c97" in hs: return "baseline"
    br = [x for x in run('git branch')[1].strip().splitlines() if x.startswith("* ")][0].split()[-1]
    if br == "baseline": return "baseline"
    return None


def is_baseline(result):
    return result["comment"] == "baseline"


def abbreviate_option(k):
    if k.startswith("MBEDTLS_"): k = k[8:]
    if k.startswith("PSA_WANT_ALG_"): k = k[13:]
    if k == "PSA_WANT_KEY_TYPE_AES": k = "AES"
    if k == "PSA_WANT_KEY_TYPE_ARIA": k = "ARIA"
    if k == "PSA_WANT_KEY_TYPE_CAMELLIA": k = "CAMELLIA"
    if k == "PSA_WANT_KEY_TYPE_CHACHA20": k = "CHACHA"
    if k == "AESCE_C": k = "AESCE"
    if k == "AES_USE_HARDWARE_ONLY": k="HW_ONLY"
    if k == "AES_ONLY_128_BIT_KEY_LENGTH": k="ONLY_128"
    if k == "BLOCK_CIPHER_NO_DECRYPT": k="NO_DEC"
    if k == "AESCE_OPTIMISE_FOR_SIZE": k="OPT_SIZE"
    return k


def print_results(data, show_header=True, confluence=False, github=True, show_opts=True):
    KEY_ORDER = [ "cc", "MBEDTLS_AESCE_C", "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH" ]

    # config keys
    keys1 = []
    s = set()
    for d in data:
        s = s.union(d["config"]["options"].keys())

    # update no-show keys
    no_show_keys = set(NO_SHOW_KEYS)
    for k in s:
        if all(not d["config"]["options"][k] for d in data) or all(d["config"]["options"][k] for d in data):
            no_show_keys.add(k)
    #print([d["config"]["options"]["MBEDTLS_AESCE_OPTIMISE_FOR_SIZE"] for d in data])


    keys1 = ["cc"] + list(sorted(s))
    keys1 = [k for k in keys1 if k not in no_show_keys]
    if not show_opts:
        keys1 = [k for k in keys1 if not k.startswith("OPT_")]
    #if args.ctr   is not None: keys1 = [k for k in keys1 if "CTR" not in k]
    #if args.gcm   is not None: keys1 = [k for k in keys1 if "MULTIBLOCK" in k or "GCM" not in k]
    #if args.aesce is not None: keys1 = [k for k in keys1 if "MULTIBLOCK" in k or "AESCE_C" not in k]
    #if not any("clang" in c for c in args.compilers): keys1 = [k for k in keys1 if "cc" not in k]
    #if not any("gcc" in c for c in args.compilers): keys1 = [k for k in keys1 if "cc" not in k]

    # sort columns
    keys11 = []
    for k in KEY_ORDER:
        if k in keys1:
            keys11.append(k)
    for k in keys1:
        if k not in KEY_ORDER:
            keys11.append(k)
    keys1 = keys11

    # result keys
    s = set()
    for d in data:
        s = s.union(d["raw_perf"].keys())
    keys2 = ["size"] + sorted(s)
    keys2 = [k for k in keys2 if k not in NO_SHOW_KEYS]
    keys = keys1 + keys2

    # sort rows
    #for k in reversed(keys1):
    #    if k in d["config"]["options"]:
    #        data = sorted(data, key=lambda d: d["config"]["options"][k])
    data = sorted(data, key=lambda d: d["config"]["options"]["MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"])
    data = sorted(data, key=lambda d: d["config"]["options"]["MBEDTLS_AESCE_C"])
    data = sorted(data, key=lambda d: d["config"]["cc"])

    # aggregate rows
    data2 = {}
    for d in data:
        c = tuple([d["config"]["cc"]] + [(k, v) for k, v in sorted(d["config"]["options"].items(), key=lambda t: t[0])])
        if c not in data2:
            data2[c] = d
        else:
            a = data2[c]
            for k in d["raw_perf"]:
                if k not in a["raw_perf"]: a["raw_perf"][k] = []
                for r in d["raw_perf"][k]:
                    a["raw_perf"][k].append(r)
    data = list(data2.values())

    baseline = get_data_from_log(data[0]["config"], args.baseline) if args.baseline else None
    if args.hash:
        hash = args.hash
    else:
        hash = [x for x in get_hash() if x is not None][0]
    #if baseline is not None:
    #    print(f"hash = {hash}, baseline = {baseline['hash']}")

    # gather items to print as tuple (data, baseline)
    have_relative = []
    table = []
    for d in data:
        b = get_data_from_log(d["config"], args.baseline) if args.baseline else None
        row = []
        for k in keys1:
            if k == "cc":
                row.append(d["config"]["cc"])
            elif k in d["config"]["options"]:
                row.append(d["config"]["options"][k])
            else:
                row.append(None)
        for k in keys2:
            nd = 1
            nb = 1
            if k == "size":
                dd = d["size"]["aes"]
                bd = None if b is None else b["size"]["aes"]
            else:
                if k not in d["raw_perf"]:
                    dd = None
                    bd = None
                else:
                    dd = d["raw_perf"][k]
                    bd = None if b is None or k not in b["raw_perf"] else b["raw_perf"][k]
            if type(dd) is list:
                if len(dd) > 1:
                    rsd = statistics.stdev(dd) / statistics.mean(dd)
                    assert(rsd < 0.15)
                nd = len(dd)
                dd = max(dd)
                #dd = statistics.mean(dd)
            if type(bd) is list:
                if len(bd) > 1:
                    rsd = statistics.stdev(bd) / statistics.mean(bd)
                    assert(rsd < 0.15)
                nb = len(bd)
                bd = max(bd)
                #bd = statistics.mean(bd)
            if dd is None: nd = 0
            if bd is None: nb = 0
            row.append((k, dd, bd, nd, nb))
            while len(have_relative) < len(row): have_relative.append(False)
            if bd:
                have_relative[len(row) - 1] = True
        table += [row]

    show_rel = True
    show_abs = True

    # convert to str
    stable = []
    for row in table:
        srow = []
        for col, c in enumerate(row):
            rel = False
            if type(c) is tuple:
                k, dd, bd, nd, nb = c
                if bd is None:
                    # no baseline data, show absolute value
                    d = (dd, None)
                elif dd is None:
                    d = ("", None)
                else:
                    rel=True
                    if k == "size":
                        d = (dd, dd - bd)
                    else:
                        d = (dd, dd / bd - 1)
            else:
                d = (c, None)
            
            # d = (absolute, relative)
            d_abs, d_rel = d

            if d_abs is None:
                s = ""
            elif type(d_abs) is bool:
                s = "1" if d_abs else "0"
            elif type(d_abs) is str:
                s = d_abs
            else:
                if type(d_abs) is float:
                    if have_relative[col]:
                        if d_rel is None:
                            s = f"{d_abs:4.0f}   {'':7}"
                        else:
                            if show_abs:
                                pc = 100 * d_rel
                                if pc < 100:
                                    s = f"{d_abs:4.0f}   {pc:+4.0f}%"
                                else:
                                    x = (pc + 100) / 100
                                    s = f"{d_abs:4.0f}   {x: 4.1f}x"
                            else:
                                pc = 100 * d_rel
                                if pc < 100:
                                    s = f"{pc:+4.0f}%"
                                else:
                                    x = (pc + 100) / 100
                                    s = f"{x: 4.1f}x"
                    else:
                        s = f"{d_abs:4.0f}"
                elif type(d_abs) is int:
                    if have_relative[col]:
                        if d_rel is None:
                            s = f"{d_abs:5}   {'':5}"
                        else:
                            if show_abs:
                                s = f"{d_abs:5}   {d_rel:+5}"
                            else:
                                s = f"{d_rel:+5}"
                    else:
                        s = f"{d_abs:4.0f}"
            srow.append(s)
        stable.append(srow)

    if VERBOSE >= 2:
        print("fixed options:")
        for k in no_show_keys:
            v = data[0]["config"]["options"][k]
            print(f"    {abbreviate_option(k)} = {v}")
    if VERBOSE >= 1:
        h = data[0]["hash"]
        h = ([f"{k} ({v})" for k, v in HASHES.items() if v == h] + [h])[0]
        if baseline:
            bh = baseline['hash']
            bh = ([f"{k} ({v})" for k, v in HASHES.items() if v == bh] + [bh])[0]
            print(f"hash: {h}, comparison: {bh}")
        else:
            print(f"hash: {data[0]['hash']}")


    if show_header:
        stable = [[abbreviate_option(x) for x in keys]] + stable

    # get col widths
    ws = [max([len(r[i]) for r in stable]) for i in range(0, len(stable[0]))]

    # print aligned text
    hsep = False
    if confluence:
        seps = [("|| ", " || ", " ||"), ("|  ", "  | ", "  |")]
    elif github:
        seps = [("| ", " | ", " |"), ("| ", " | ", " |")]
        hsep = True
    else:
        seps = [("", ", ", ""), ("", ", ", "")]
    for row_i, r in enumerate(stable):
        ss = seps[0 if row_i == 0 else 1]
        for i, c in enumerate(r):
            pre_sep = ss[0] if i == 0 else ""
            sep = ss[1] if i > 0 else ""
            pad = " " * (ws[i] - len(c))
            print(f"{pre_sep}{sep}{pad}{c}", end="")
        print(ss[-1])
        if hsep and row_i == 0:
            ls = []
            for i, c in enumerate(r):
                l = "-" * (2 + ws[i])
                ls.append(l)
            print("|" + "|".join(ls) + "|")
    print()


def config2str(config):
    return f"{config['cc']}: " + ", ".join([abbreviate_option(x) + "=" + ("1" if config["options"][x] else "0") for x in config["options"]])

def main():
    if args.rebuild:
        #todo
        build(None)

    if args.hash:
        results = get_results(hash=args.hash)
        for i, r in enumerate(results[:]):
            if args.ctr == True and not r["config"]["options"]["PSA_WANT_ALG_CTR"]: results[i] = None
            if args.ctr == False and r["config"]["options"]["PSA_WANT_ALG_CTR"]: results[i] = None
            if args.gcm == True and not r["config"]["options"]["PSA_WANT_ALG_GCM"]: results[i] = None
            if args.gcm == False and r["config"]["options"]["PSA_WANT_ALG_GCM"]: results[i] = None
            if args.only_128 == True and not r["config"]["options"]["MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"]: results[i] = None
            if args.only_128 == False and r["config"]["options"]["MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"]: results[i] = None
            if args.aesce == True and not r["config"]["options"]["MBEDTLS_AESCE_C"]: results[i] = None
            if args.aesce == False and r["config"]["options"]["MBEDTLS_AESCE_C"]: results[i] = None
            if args.opt_size == True and r["config"]["options"]["MBEDTLS_AESCE_OPTIMISE_FOR_SIZE"] == 0: results[i] = None
            if args.opt_size == False and r["config"]["options"]["MBEDTLS_AESCE_OPTIMISE_FOR_SIZE"] == 1: results[i] = None
            if r["config"]["cc"] not in args.compilers: results[i] = None
        results = [x for x in results if x is not None]
        if results:
            print_results(results)
        exit(0)

    try:
        if args.no_change_crypto_config:
            if os.path.exists(CRYPTO_CONFIG_FILE + ".bak"):
                os.remove(CRYPTO_CONFIG_FILE + ".bak")
            shutil.copy2(CRYPTO_CONFIG_FILE, CRYPTO_CONFIG_FILE + ".bak")

        results = []
        configs = gen_opt_combos()

        if args.full_test:
            print(f"running against {len(configs)} configs:")

        for i, config in enumerate(configs):
            #if not args.quiet:
            #    print(config2str(config))

            baseline = get_data_from_log(config, args.baseline) if args.baseline else None
            build(config)
            result=bench(config)
            results.append(result)

            if args.log:
                log_result(result)

            if args.test:
                if any(x["rc"] != 0 for x in result["test"].values()):
                    for s in result["test"]:
                        if result['test'][s]["rc"] != 0:
                            print(f"{s}:\n{result['test'][s]['output']}\n")
                        else:
                            print(f"{s}: ok")
                else:
                    if VERBOSE >= 2:
                        print(f"{len(result['test'])} test suites ok: {', '.join(result['test'].keys())}")

            if (VERBOSE >= 1) or (i == len(configs) - 1):
                print_results(results)

            if False:
                if args.full_test:
                    cs = f"{config['cc']:8}: aesce={get_option(config, "AESCE_C")}, 128={get_option(config, "ONLY_128")}"
                    s = result['size']['aes']
                    rs = f"{cs}, size={s}"
                    if args.bench:
                        rs += f", ctr-128={result['best_perf']['AES-CTR-128']:5.0f}"
                        if args.gcm:
                            rs += f", gcm-128={result['best_perf']['AES-GCM-128']:5.0f}"
                        #print(json.dumps(result,indent=4))
                        rs += f", ctr-drbg-nopr={result['best_perf']['CTR_DRBG (NOPR)']:5.0f}"
                    print(rs)
                    if False:
                        l = [config["cc"]]
                        for o in config["options"]:
                            if o[0].startswith("MBEDTLS"):
                                l.append(f"{o[0][8:]}={o[1]}")
                        #print(", ".join(l))
                        if args.bench:
                            print(f"before: {baseline[0]} {baseline[1]:.0f}")
                            print(f"after:  {s}, {p:.0f}")
                            print(f"diff:   {s - baseline[0]:+.0f}, {(100.0 * p/baseline[1]) - 100.0:+.0f}%")
                        else:
                            print(f"before: {baseline[0]}")
                            print(f"after:  {s}")
                            print(f"diff:   {s - baseline[0]:+.0f}")
                else:
                    #print(json.dumps(result, indent=4))
                    #print()
                    for k, v in result['best_perf'].items():
                        print(f"{k}: {v:7.1f} MB/s")
                    print()

                    s = result['size']['aes']
                    p = result['best_perf']['AES-CTR-128'] if args.bench else 0
                    if False:
                        print(f"openssl:                  perf = 17816.1 MB/s")
                        print(f"baseline:   size = {baseline[0]:5}, perf = {baseline[1]:7.1f} MB/s")
                        print(f"this build: size = {s:5}, perf = {p:7.1f} MB/s")
                    sd = s - baseline[0]
                    if args.bench:
                        print(f"//            {config['cc']}: size = {sd:+5}, perf = {100.0 * (p / baseline[1] - 1.0):+.0f}%")
                    else:
                        print(f"//            {config['cc']}: size = {sd:+5}")
                    print("//")

    finally:
        if args.no_change_crypto_config:
            if run(f"diff -q -s {CRYPTO_CONFIG_FILE} {CRYPTO_CONFIG_FILE}.bak", verbose=False, fatal=False)[0] != 0:
                os.remove(CRYPTO_CONFIG_FILE)
                shutil.copy2(CRYPTO_CONFIG_FILE + ".bak", CRYPTO_CONFIG_FILE)
            os.remove(CRYPTO_CONFIG_FILE + ".bak")


args = parse_args()
main()
