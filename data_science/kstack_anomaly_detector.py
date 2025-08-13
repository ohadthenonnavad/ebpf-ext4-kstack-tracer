#!/usr/bin/env python3
import argparse, collections, csv, json, math, os, random, sys
from typing import List, Dict, Tuple, Iterable

# ---------------- Tokenization / Canonicalization ----------------

BUCKETS = [(0,1),(2,15),(16,63),(64,255)]  # 0..1, 2..15, 16..63, 64..255, else 256+
FAMILIES = ("ext4","btrfs","xfs","overlay","selinux","security","bpf","ftrace","livepatch")
SKIP_TRAMPOLINES = ("ftrace_", "bpf_trampoline", "kretprobe_trampoline", "livepatch_")

def off_bucket(off_hex: str) -> str:
    try:
        s = off_hex.lower().replace("0x","")
        off = int(s, 16)
    except Exception:
        off = 0
    for i,(a,b) in enumerate(BUCKETS):
        if a <= off <= b: return str(i)
    return "4"

def family_of(sym: str) -> str:
    s = sym.lower()
    for f in FAMILIES:
        if s.startswith(f + "_"): return f
    return "core"

def norm_sym(sym: str) -> str:
    if sym in ("do_syscall_64","x64_sys_call"): return "sys_entry"
    return sym

def tokenize_frames(frames: List[Dict], skip_trampolines=True) -> List[str]:
    toks = ["<bos>"]
    for fr in frames:
        sym = norm_sym(fr.get("symbol","").strip())
        if skip_trampolines and sym.startswith(SKIP_TRAMPOLINES):
            continue
        fam = family_of(sym)
        bucket = off_bucket(fr.get("offset","0x0"))
        toks.append(f"{fam}:{sym}:{bucket}")
    toks.append("<eos>")
    return toks

def syscall_name(frames: List[Dict]) -> str:
    for fr in frames:
        s = fr.get("symbol","")
        if s.startswith("__x64_sys_"): return s
    return "unknown"

# ---------------- Bigram model with weights ----------------

class Bigram:
    def __init__(self):
        self.ct = collections.Counter()       # (a,b) -> float
        self.uni = collections.Counter()      # a -> float
        self.V  = set()

    def fit_weighted(self, seqs: Iterable[List[str]], weights: Iterable[float]):
        for seq, w in zip(seqs, weights):
            if w <= 0: continue
            for a,b in zip(seq, seq[1:]):
                self.ct[(a,b)] += w
                self.uni[a]    += w
                self.V.add(a); self.V.add(b)

    def nll(self, seq: List[str], k: float = 1.0) -> Tuple[float,int,Dict[Tuple[str,str],float]]:
        """Return (negative log-likelihood, unseen_edge_count, per-edge surprise dict)."""
        V = max(1, len(self.V))
        s = 0.0
        unseen = 0
        edge_surprise = {}
        for a,b in zip(seq, seq[1:]):
            num = self.ct.get((a,b), 0.0) + k
            den = self.uni.get(a, 0.0) + k * V
            p = num / den
            if (a,b) not in self.ct: unseen += 1
            val = -math.log(p)
            edge_surprise[(a,b)] = val
            s += val
        return s, unseen, edge_surprise

# ---------------- Utilities ----------------

def quantile(vals: List[float], q: float) -> float:
    if not vals: return 0.0
    xs = sorted(vals)
    idx = int(q * (len(xs)-1))
    return xs[idx]

def sublinear_weight(count: int) -> float:
    return 1.0 + math.log1p(max(1, count))

def seq_key(seq: List[str]) -> Tuple[str,...]:
    return tuple(seq)

def edges_of(seq: List[str]) -> List[Tuple[str,str]]:
    return list(zip(seq, seq[1:]))

def families_different(edge: Tuple[str,str]) -> bool:
    def fam(tok: str) -> str:
        if tok in ("<bos>","<eos>"): return "meta"
        return tok.split(":",1)[0]
    a,b = edge
    return fam(a) != fam(b)

# ---------------- Training ----------------

def load_sequences(jsonl_path: str, skip_trampolines=True) -> List[Tuple[str,List[str]]]:
    seqs = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            ev = json.loads(line)
            frames = ev.get("frames", [])
            sc = syscall_name(frames)
            seq = tokenize_frames(frames, skip_trampolines=skip_trampolines)
            seqs.append((sc, seq))
    return seqs

def dedup_by_syscall(seqs: List[Tuple[str,List[str]]]):
    """Return: per-syscall -> {seq_key: count}, and raw per-syscall list preserving duplicates"""
    per_sc_counts = collections.defaultdict(lambda: collections.Counter())
    per_sc_raw = collections.defaultdict(list)
    for sc, seq in seqs:
        per_sc_counts[sc][seq_key(seq)] += 1
        per_sc_raw[sc].append(seq)
    return per_sc_counts, per_sc_raw

def train_models(per_sc_counts, per_sc_raw, holdout_frac=0.2, k_smooth=1.0, coverage_csv=None):
    models = {}
    thresholds = {}
    seen_edges_by_sc = {}
    # edge coverage tracking (on raw stream preserving duplicates)
    if coverage_csv:
        covw = open(coverage_csv, "w", newline="", encoding="utf-8")
        cov_writer = csv.writer(covw)
        cov_writer.writerow(["syscall","batch_idx","start_idx","end_idx","traces","edges_in_batch","new_edges","new_edge_ratio","cum_unique_edges"])
    for sc, counter in per_sc_counts.items():
        # Weighted fit on unique sequences
        uniq_seqs = [list(key) for key in counter.keys()]
        weights   = [sublinear_weight(counter[key]) for key in counter.keys()]
        model = Bigram()
        model.fit_weighted(uniq_seqs, weights)
        models[sc] = model
        # Build seen_edges set from unique sequences (duplicates don't inflate)
        seen_edges = set()
        for s in uniq_seqs:
            for e in edges_of(s): seen_edges.add(e)
        seen_edges_by_sc[sc] = seen_edges
        # Thresholds: NLL on hold-out slice that preserves natural duplication
        raw = per_sc_raw[sc]
        if not raw:
            thresholds[sc] = 0.0
            continue
        cut = max(1, int(len(raw) * (1.0 - holdout_frac)))
        train_like = raw[:cut]     # unused except for coverage calc
        holdout    = raw[cut:]
        if not holdout: holdout = raw  # if too small, use all
        nlls = [model.nll(s, k=k_smooth)[0] for s in holdout]
        thresholds[sc] = quantile(nlls, 0.99) if nlls else 0.0
        # Edge coverage (optional; on the raw stream in batches)
        if coverage_csv:
            BATCH = 100
            seen = set()
            total_idx = 0
            batch_idx = 0
            while total_idx < len(train_like):
                batch = train_like[total_idx: total_idx+BATCH]
                total_idx += len(batch)
                batch_idx += 1
                edges_in_batch = 0
                new_edges = 0
                for seq in batch:
                    for e in edges_of(seq):
                        edges_in_batch += 1
                        if e not in seen:
                            seen.add(e)
                            new_edges += 1
                ratio = (new_edges / max(1, edges_in_batch))
                cov_writer.writerow([sc,batch_idx,total_idx-len(batch),total_idx,len(batch),edges_in_batch,new_edges,round(ratio,6),len(seen)])
    if coverage_csv:
        covw.close()
    # Serialize
    blob = {"k_smooth": k_smooth, "thresholds": thresholds, "models": {}, "seen_edges": {}}
    for sc, m in models.items():
        # store as simple dicts
        uni = {k: m.uni[k] for k in m.uni}
        bi  = {f"{a}\t{b}": m.ct[(a,b)] for (a,b) in m.ct}
        V   = list(m.V)
        blob["models"][sc] = {"uni": uni, "bi": bi, "V": V}
        blob["seen_edges"][sc] = [f"{a}\t{b}" for (a,b) in seen_edges_by_sc[sc]]
    return blob

def save_model(model_blob, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(model_blob, f)

def load_model(path):
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    # Rehydrate
    models = {}
    for sc, data in blob["models"].items():
        m = Bigram()
        m.uni = collections.Counter(data["uni"])
        m.ct  = collections.Counter({tuple(k.split("\t")): v for k,v in data["bi"].items()})
        m.V   = set(data["V"])
        models[sc] = m
    seen_edges = {sc: set(tuple(s.split("\t")) for s in lst) for sc,lst in blob["seen_edges"].items()}
    return models, blob["thresholds"], blob.get("k_smooth",1.0), seen_edges

# ---------------- Scoring ----------------

def score_event(ev, models, thresholds, k_smooth, seen_edges):
    frames = ev.get("frames", [])
    sc = syscall_name(frames)
    seq = tokenize_frames(frames, skip_trampolines=True)
    model = models.get(sc)
    if model is None:
        return {"syscall": sc, "decision": "review", "reasons": ["no baseline"], "nll": None, "unseen_edges": None}
    nll, unseen, edge_s = model.nll(seq, k=k_smooth)
    th = thresholds.get(sc, 0.0)
    # unseen cross-family?
    unseen_edges = []
    crossfam = False
    for e in edges_of(seq):
        if e not in seen_edges.get(sc,set()):
            unseen_edges.append(f"{e[0]} -> {e[1]}")
            if families_different(e): crossfam = True
    decision = "ok"
    reasons = []
    if sc == "unknown":
        decision = "high"; reasons.append("missing __x64_sys_* frame")
    if nll > th:
        decision = "suspicious"; reasons.append(f"NLL {nll:.2f} > {th:.2f}")
    if unseen_edges:
        reasons.append(f"{len(unseen_edges)} unseen edges")
        if crossfam:
            decision = "suspicious" if decision=="ok" else decision
            reasons.append("includes cross-family unseen edge")
    # Most surprising edges (top-3)
    top_edges = sorted(edge_s.items(), key=lambda kv: kv[1], reverse=True)[:3]
    top_edges = [f"{a[0]} -> {a[1]} ({v:.3f})" for a,v in top_edges]
    return {
        "syscall": sc,
        "decision": decision,
        "reasons": reasons,
        "nll": nll,
        "threshold": th,
        "unseen_edges": unseen_edges,
        "top_edges": top_edges,
    }

# ---------------- CLI ----------------

def cmd_train(args):
    seqs = load_sequences(args.input, skip_trampolines=(not args.keep_trampolines))
    per_sc_counts, per_sc_raw = dedup_by_syscall(seqs)
    model_blob = train_models(
        per_sc_counts, per_sc_raw,
        holdout_frac=args.holdout,
        k_smooth=args.k,
        coverage_csv=args.coverage
    )
    save_model(model_blob, args.model)
    print(f"[train] saved model to {args.model}")
    if args.coverage:
        print(f"[train] wrote edge coverage CSV: {args.coverage}")
        print("       Inspect new_edge_ratio per batch; when it stays <0.01 for ~5 batches, coverage is stable.")

def cmd_score(args):
    models, thresholds, k_smooth, seen_edges = load_model(args.model)
    out = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
    n=0
    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            ev = json.loads(line)
            res = score_event(ev, models, thresholds, k_smooth, seen_edges)
            if not args.explain:
                res.pop("top_edges", None)
                res.pop("unseen_edges", None)
            out.write(json.dumps(res) + "\n")
            n+=1
    if out is not sys.stdout: out.close()
    print(f"[score] wrote {n} results to {args.output}")

def main():
    ap = argparse.ArgumentParser(description="Kernel stacktrace anomaly detector (n-gram + coverage + dedup)")
    sub = ap.add_subparsers()

    ap_train = sub.add_parser("train", help="Train from benign JSONL")
    ap_train.add_argument("--input", required=True, help="benign traces JSONL (one event per line)")
    ap_train.add_argument("--model", required=True, help="path to write model.json")
    ap_train.add_argument("--coverage", default=None, help="optional CSV to write edge coverage per batch")
    ap_train.add_argument("--holdout", type=float, default=0.2, help="fraction for hold-out to compute thresholds")
    ap_train.add_argument("-k", type=float, default=1.0, help="Laplace smoothing")
    ap_train.add_argument("--keep-trampolines", action="store_true", help="keep ftrace/bpf/livepatch trampolines")
    ap_train.set_defaults(func=cmd_train)

    ap_score = sub.add_parser("score", help="Score JSONL with a trained model")
    ap_score.add_argument("--model", required=True, help="model.json from training")
    ap_score.add_argument("--input", required=True, help="events JSONL to score")
    ap_score.add_argument("--output", default="-", help="where to write scores JSONL (default stdout)")
    ap_score.add_argument("--explain", action="store_true", help="include unseen edges & top surprising edges")
    ap_score.set_defaults(func=cmd_score)

    args = ap.parse_args()
    if not hasattr(args, "func"):
        ap.print_help(); sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
