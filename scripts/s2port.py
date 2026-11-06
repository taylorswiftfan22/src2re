"""s2port - carry an address from one build of a module to another (after a game update).

port(old, new, rva) works for:
  code   the function containing rva is matched in the new build, then the instruction inside it is mapped
  data   strings, vtables, convar/concommand objects and schema class infos map by name; other globals are
         ported through the instructions that reference them

Function matching = anchors that survive updates, then a similarity score:
  anchors     same vtable class + slot (10), unique strings referenced (6 / #functions using the string),
              convars read (5 / #readers), exact signature (8) or loose signature (5), call graph: a ported
              caller's call at the same position (4) / a ported callee's callers (2 / #callers)
  similarity  instruction mnemonic sequence (x3), strings (x2), size, imports, constants, call count
  score       anchors + 10 x similarity; the margin to the runner-up is reported as the confidence

Old builds come from the snapshot store (s2pe.Image.snapshot), filled automatically whenever a new build is
indexed, or from any DLL path.
"""
import difflib
from collections import defaultdict, namedtuple

from capstone.x86 import X86_OP_IMM

import s2pe
import s2source2

Candidate = namedtuple("Candidate", "start score anchor similarity parts evidence")
PortResult = namedtuple("PortResult", "kind old_function candidates mapped notes")


class FuncInfo:
    """Features of one function that survive recompilation reasonably well."""

    def __init__(self, img, start):
        self.start = start
        self.insns = img.insns(start)
        self.mnems = [i.mnemonic for i in self.insns]
        self.size = sum(e - b for b, e in img.function_ranges(start))
        self.strings, self.imports, self.consts, self.data = set(), set(), set(), set()
        self.calls = []  # (site, target) in order
        imps = img.imports()
        for ins in self.insns:
            t = img.target_of(ins)
            if t is not None:
                if t in imps:
                    self.imports.add(imps[t].replace("[delay] ", ""))
                elif ins.mnemonic == "call" and img.is_code(t):
                    self.calls.append((ins.address, t))
                elif img.section_of(t) in (".rdata", ".data"):
                    s = img.printable_at(t)
                    if s:
                        self.strings.add(s)
                    elif img.section_of(t) == ".data":
                        self.data.add(t)
                continue
            for op in ins.operands:
                if op.type == X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFFFFFFFFFF
                    if 0x100 <= v < 0x100000000:
                        self.consts.add(v)


def _jacc(a, b):
    return len(a & b) / len(a | b) if (a or b) else None


def similarity(fa, fb):
    parts = {"size": min(fa.size, fb.size) / max(fa.size, fb.size, 1)}
    a, b = fa.mnems[:2500], fb.mnems[:2500]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    parts["code"] = sm.ratio() if sm.real_quick_ratio() > 0.3 else sm.real_quick_ratio() * 0.5
    for k in ("strings", "imports", "consts"):
        parts[k] = _jacc(getattr(fa, k), getattr(fb, k))
    na, nb = len(fa.calls), len(fb.calls)
    parts["calls"] = min(na, nb) / max(na, nb) if (na or nb) else None
    weights = {"code": 3, "strings": 2, "size": 1, "imports": 1, "consts": 1, "calls": 1}
    tot = sum(weights[k] for k, v in parts.items() if v is not None)
    return sum(weights[k] * v for k, v in parts.items() if v is not None) / tot, parts


class Porter:
    def __init__(self, old, new):
        self.old, self.new = old, new
        self._finfo = {}
        self._quick = {}

    def info(self, img, start):
        key = (id(img), start)
        if key not in self._finfo:
            self._finfo[key] = FuncInfo(img, start)
        return self._finfo[key]

    # ------------------------------------------------------------------ anchors
    def _anchors(self, F, fi, graph=True, use_strings=True):
        old, new = self.old, self.new
        votes = defaultdict(lambda: [0.0, []])

        def vote(fn, w, why):
            if fn is None:
                return
            v = votes[fn]
            v[0] += w
            v[1].append(why)

        for p in old.stored_at(F):  # vtable class + slot
            vs = old.vtable_slot(p)
            if not vs:
                continue
            v_old, slot = vs
            for v in new.vtables():
                if v.cls == v_old.cls and v.col_offset == v_old.col_offset and slot < v.slots:
                    t = new.vtable_slots(v)[slot]
                    vote(new.function_start(t) or t, 10, f"{new.demangle_type(v.cls)} vtable slot [{slot}]")
        if use_strings:
            for s in fi.strings:
                fns = {new.function_start(r) for h in new.find_cstr(s) for r in new.xrefs(h)} - {None}
                if 0 < len(fns) <= 20:
                    for fn in fns:
                        vote(fn, 6 / len(fns), f'string "{s[:48]}"' + (f" (1 of {len(fns)})" if len(fns) > 1 else ""))
        old_objs = s2source2.registration_by_object(old)
        new_regs = s2source2.registration_by_object(new).values()
        new_by_name = {r.name: r for r in new_regs}
        new_inits = {r.init for r in new_regs}
        for r in old_objs.values():  # F registers a convar / concommand: its initializer maps by name
            if r.init == F and r.name in new_by_name:
                vote(new_by_name[r.name].init, 10, f"registers {r.name}")
        for d in fi.data:  # convars / concommands referenced (object or object+8)
            r = old_objs.get(d) or old_objs.get(d - 8)
            if not r or r.init == F or r.name not in new_by_name:
                continue
            nobj = new_by_name[r.name].obj
            fns = {f for _, _, f in new.object_readers(nobj)} - {None} - new_inits
            if 0 < len(fns) <= 20:
                for fn in fns:
                    vote(fn, 5 / len(fns), f"reads convar {r.name}" + (f" (1 of {len(fns)})" if len(fns) > 1 else ""))
        for loose, w in ((False, 8), (True, 5)):  # signature carried over
            pat, n, unique, _ = old.make_sig(F, 40, loose)
            if unique:
                hits = new.scan(pat, "code", limit=2)
                if len(hits) == 1:
                    vote(new.function_start(hits[0]) or hits[0], w, ("loose" if loose else "exact") + f" signature ({n} insns)")
                    break
        if graph:
            self._graph_anchors(F, fi, vote)
        return votes

    def _graph_anchors(self, F, fi, vote):
        old, new = self.old, self.new
        callers = sorted({old.function_start(r) for r in old.xrefs(F)} - {None, F})[:6]
        for C in callers:
            Cn = self.quick(C)
            if Cn is None:
                continue
            ci, cn = self.info(old, C), self.info(new, Cn)
            ks = [k for k, (_, t) in enumerate(ci.calls) if t == F]
            for k in ks[:2]:
                for dk, w in ((0, 4.0), (-1, 1.5), (1, 1.5)):
                    if 0 <= k + dk < len(cn.calls):
                        t = cn.calls[k + dk][1]
                        vote(new.function_start(t) or t, w, f"call #{k + dk} of ported caller {C:#x}->{Cn:#x}")
        for _, G in fi.calls[:12]:
            Gn = self.quick(G)
            if Gn is None:
                continue
            fns = {new.function_start(r) for r in new.xrefs(Gn)} - {None}
            if 0 < len(fns) <= 10:
                for fn in fns:
                    vote(fn, 2 / len(fns), f"calls ported callee {G:#x}->{Gn:#x}")

    def quick(self, F):
        """Confident match without call-graph recursion, or None."""
        if F not in self._quick:
            self._quick[F] = None
            fi = self.info(self.old, F)
            votes = self._anchors(F, fi, graph=False)
            ranked = sorted(votes.items(), key=lambda kv: -kv[1][0])
            if ranked and ranked[0][1][0] >= 6 and (len(ranked) == 1 or ranked[0][1][0] >= 2 * ranked[1][1][0]):
                self._quick[F] = ranked[0][0]
        return self._quick[F]

    # ------------------------------------------------------------------ functions
    def port_function(self, F, top=5, graph=True, use_strings=True):
        fi = self.info(self.old, F)
        votes = self._anchors(F, fi, graph=graph, use_strings=use_strings)
        pool = sorted(votes.items(), key=lambda kv: -kv[1][0])[:25]
        out = []
        for fn, (anchor, why) in pool:
            if not self.new.is_code(fn):
                continue
            sim, parts = similarity(fi, self.info(self.new, fn))
            out.append(Candidate(fn, anchor + 10 * sim, anchor, sim, parts, why))
        out.sort(key=lambda c: -c.score)
        return out[:top]

    def map_instruction(self, F, Fn, rva):
        a, b = self.info(self.old, F), self.info(self.new, Fn)
        idx = next((i for i, ins in enumerate(a.insns) if ins.address <= rva < ins.address + ins.size), None)
        if idx is None or not b.insns:
            return None, "not inside the old function"
        sm = difflib.SequenceMatcher(None, a.mnems, b.mnems, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if i1 <= idx < i2:
                if tag == "equal":
                    return b.insns[j1 + idx - i1].address, "exact (inside an identical run)"
                if tag == "replace" and i2 - i1 == j2 - j1:
                    return b.insns[j1 + idx - i1].address, "same position in a changed run"
                j = min(j1, len(b.insns) - 1)
                return b.insns[j].address, f"approximate ({tag} {i2 - i1} -> {j2 - j1} insns)"
        return None, "unmapped"

    # ------------------------------------------------------------------ data
    def port_data(self, rva):
        old, new = self.old, self.new
        notes = []
        s = old.printable_at(rva, minlen=2)
        if s and old.section_of(rva) in (".rdata", ".data") and (rva == 0 or old.mem[rva - 1] == 0):
            hits = new.find_cstr(s)
            return [(h, f'same string "{s[:60]}"', 1) for h in hits], notes
        vt = old.vtable_at(rva)
        if vt:
            res = [(v.start, f"vtable of {new.demangle_type(v.cls)}", 1) for v in new.vtables()
                   if v.cls == vt.cls and v.col_offset == vt.col_offset]
            return res, notes
        reg = s2source2.registration_by_object(old).get(rva)
        if reg:
            res = [(r.obj, f"object of {r.name}", 1) for r in s2source2.registration_by_object(new).values() if r.name == reg.name]
            return res, notes
        sc = next((c for c in s2source2.schema_classes(old) if c.info == rva), None)
        if sc:
            nc = s2source2.schema_class_map(new).get(sc.name)
            return ([(nc.info, f"schema class info of {sc.name}", 1)] if nc else []), notes
        votes = defaultdict(int)
        sites = old.xrefs(rva)[:10]
        for site in sites:
            F = old.function_start(site)
            if F is None:
                continue
            cands = self.port_function(F, top=2, graph=False)
            if not cands or (len(cands) > 1 and cands[0].score < cands[1].score + 3):
                continue
            nsite, how = self.map_instruction(F, cands[0].start, site)
            ins = new.insn_at(nsite) if nsite is not None else None
            t = new.target_of(ins) if ins else None
            if t is not None:
                votes[t] += 1
        if not sites:
            notes.append("nothing references this address in the old build")
        res = sorted(((t, f"referenced from {n} ported site(s)", n) for t, n in votes.items()), key=lambda x: -x[2])
        return res, notes

    # ------------------------------------------------------------------ entry point
    def port(self, rva, top=5):
        old = self.old
        if old.is_code(rva):
            F = old.function_start(rva)
            if F is None:  # leaf without .pdata: treat rva as its start
                F = rva
            cands = self.port_function(F, top=top)
            mapped = None
            if cands and rva != F:
                mapped = self.map_instruction(F, cands[0].start, rva)
            return PortResult("code", F, cands, mapped, [])
        res, notes = self.port_data(rva)
        return PortResult("data", None, res, None, notes)


def confidence(cands):
    if not cands:
        return "none"
    if len(cands) == 1:
        return "high" if cands[0].score >= 12 else "medium"
    gap = cands[0].score - cands[1].score
    return "high" if gap >= 6 and cands[0].score >= 12 else ("medium" if gap >= 2.5 else "low")
