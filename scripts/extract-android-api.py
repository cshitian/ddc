#!/usr/bin/env python3
"""Build the ddc framework API database blob (android-api.fwdb).

Sources, merged:
  1. android.jar class files — names, descriptors, SUPER/INTERFACES and
     ACCESS FLAGS (static/abstract/public — the stub synthesizer needs
     abstract-vs-static-vs-default precision that api-versions.xml lacks).
  2. data/api-versions.xml — classes REMOVED from the modern jar but still
     referenced by old APKs (org.apache.http family, removed="23"...);
     these carry no flag info and are marked FLAG_UNKNOWN so flag-sensitive
     consumers skip them while subtype/exists queries still resolve.

Output: a compact little-endian binary designed for include_bytes! +
zero-copy binary-search access at runtime (no decompression, no parse —
the dae self-contained-profile pattern; a generated-Rust-source variant
was rejected: multi-MB of literals costs compile time and a bigger
binary than the raw string pool).

Layout (all u32 LE):
  header  magic 'FWDB' | version=1 | class_count | pool_len
          | off_pool | off_classes | off_impls | off_methods | off_fields | reserved
  pool    deduped UTF-8 string bytes (no separators; slices via offsets)
  classes sorted by name bytes; per class 9 u32:
          name_off | super_off (NONE=0xFFFFFFFF) | cflags
          | impl_start | impl_len | meth_start | meth_len | field_start | field_len
  impls   string offsets (interface names), grouped per class
  methods records { str_off (combined "name(args)ret"), flags }
  fields  records { str_off (name), flags }

Flag bits:
  class   0=interface 1=abstract 2=enum 31=unknown(xml-only)
  member  0=public 1=protected 2=private 3=static 4=abstract 5=final
          31=unknown(xml-only)

Usage:
  extract-android-api.py [--jar android.jar] [--xml api-versions.xml]
                         [-o crates/ddc-dec/data/android-api.fwdb]
Defaults target the local SDK's android-37 platform.
"""
import argparse
import os
import struct
import sys
import zipfile
import xml.etree.ElementTree as ET
from bisect import bisect_left

MAGIC = 0x42445746  # 'FWDB'
VERSION = 1
SUPER_NONE = 0xFFFFFFFF

# access flags (class file spec)
ACC_PUBLIC, ACC_PRIVATE, ACC_PROTECTED = 0x0001, 0x0002, 0x0004
ACC_STATIC, ACC_FINAL = 0x0008, 0x0010
ACC_INTERFACE, ACC_ABSTRACT = 0x0200, 0x0400
ACC_ENUM = 0x4000
ACC_BRIDGE, ACC_SYNTHETIC = 0x0040, 0x1000

FLAG_UNKNOWN = 1 << 31


def parse_class_file(data: bytes):
    """Minimal .class parser: constant pool, class header, fields, methods.
    Returns (access, super_name|None, [iface_names], [(name,desc,access)] x2).
    Attribute bodies are skipped (never read)."""
    # ---- constant pool (single pass, deferred class-ref resolution) ----
    cp_utf = {}        # idx -> str
    cp_class = {}      # idx -> name_utf_idx
    p = 10             # magic(4) + minor(2) + major(2) + cp_count(2)
    cp_count = struct.unpack_from('>H', data, 8)[0]
    i = 1
    while i < cp_count:
        tag = data[p]
        p += 1
        if tag == 1:
            ln = struct.unpack_from('>H', data, p)[0]
            p += 2
            cp_utf[i] = data[p:p + ln].decode('utf-8', 'replace')
            p += ln
        elif tag == 7:
            cp_class[i] = struct.unpack_from('>H', data, p)[0]
            p += 2
        elif tag in (8, 16, 19, 20):
            p += 2
        elif tag == 15:
            p += 3
        elif tag in (5, 6):
            p += 8
            i += 1  # long/double occupy two slots
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            p += 4
        else:
            raise ValueError(f'unknown cp tag {tag} at idx {i}')
        i += 1

    def cls_name(idx):
        if idx == 0:
            return None
        return cp_utf.get(cp_class.get(idx, 0))

    # ---- class header ----
    access, _this_idx, super_idx = struct.unpack_from('>HHH', data, p)
    p += 6
    ifc_n = struct.unpack_from('>H', data, p)[0]
    p += 2
    ifaces = []
    for _ in range(ifc_n):
        ifaces.append(cls_name(struct.unpack_from('>H', data, p)[0]))
        p += 2
    ifaces = [x for x in ifaces if x]

    def members():
        nonlocal p
        n = struct.unpack_from('>H', data, p)[0]
        p += 2
        out = []
        for _ in range(n):
            macc, mname, mdesc, attrs = struct.unpack_from('>HHHH', data, p)
            p += 8
            for _ in range(attrs):
                ln = struct.unpack_from('>I', data, p + 2)[0]
                p += 6 + ln
            out.append((cp_utf[mname], cp_utf[mdesc], macc))
        return out

    fields = members()
    methods = members()
    return access, cls_name(super_idx), ifaces, fields, methods


def member_flags(acc):
    fl = 0
    if acc & ACC_PUBLIC:
        fl |= 1
    if acc & ACC_PROTECTED:
        fl |= 2
    if acc & ACC_PRIVATE:
        fl |= 4
    if acc & ACC_STATIC:
        fl |= 8
    if acc & ACC_ABSTRACT:
        fl |= 16
    if acc & ACC_FINAL:
        fl |= 32
    if acc & ACC_BRIDGE:
        fl |= 64
    if acc & ACC_SYNTHETIC:
        fl |= 128
    return fl


def parse_jar(jar_path):
    db = {}
    with zipfile.ZipFile(jar_path) as z:
        names = [n for n in z.namelist() if n.endswith('.class')]
        for i, n in enumerate(names):
            try:
                access, sup, ifaces, fields, methods = parse_class_file(z.read(n))
            except Exception as e:
                print(f'  [warn] {n}: {e}', file=sys.stderr)
                continue
            cname = n[:-6]
            if sup == 'java/lang/Object':
                sup = None
            cflags = 0
            if access & ACC_INTERFACE:
                cflags |= 1
            if access & ACC_ABSTRACT:
                cflags |= 2
            if access & ACC_ENUM:
                cflags |= 4
            db[cname] = (
                cflags,
                sup,
                ifaces,
                [(mn + md, member_flags(ma)) for (mn, md, ma) in methods],
                [(fn, member_flags(fa)) for (fn, _fd, fa) in fields],
            )
            if (i + 1) % 2000 == 0:
                print(f'  jar: {i + 1}/{len(names)}', file=sys.stderr)
    return db


def merge_xml(xml_path, db):
    """Add classes absent from the jar (removed-API families), FLAG_UNKNOWN."""
    added = 0
    try:
        root = ET.parse(xml_path).getroot()
    except (FileNotFoundError, ET.ParseError) as e:
        print(f'  [warn] xml: {e}', file=sys.stderr)
        return 0
    for c in root.findall('class'):
        name = c.get('name')
        if name in db:
            continue
        sup = None
        ext = c.find('extends')
        if ext is not None and ext.get('name') != 'java/lang/Object':
            sup = ext.get('name')
        ifaces = [i.get('name') for i in c.findall('implements')]
        ms = [(m.get('name'), FLAG_UNKNOWN) for m in c.findall('method')]
        fs = [(f.get('name'), FLAG_UNKNOWN) for f in c.findall('field')]
        db[name] = (FLAG_UNKNOWN, sup, ifaces, ms, fs)
        added += 1
    return added


def build_blob(db):
    pool = bytearray()
    offs = {}

    def intern(s):
        o = offs.get(s)
        if o is None:
            o = len(pool)
            pool.extend(s.encode('utf-8'))
            pool.append(0)  # NUL terminator — the reader scans for it
            offs[s] = o
        return o

    classes = sorted(db.keys(), key=lambda n: n.encode('utf-8'))
    recs, impls, meths, fields = [], [], [], []
    for cname in classes:
        cflags, sup, ifaces, ms, fs = db[cname]
        impl_start = len(impls)
        impls.extend(intern(x) for x in ifaces)
        meth_start = len(meths)
        meths.extend((intern(md), fl) for (md, fl) in ms)
        field_start = len(fields)
        fields.extend((intern(fn), fl) for (fn, fl) in fs)
        recs.append((
            intern(cname),
            intern(sup) if sup else SUPER_NONE,
            cflags,
            impl_start, len(ifaces),
            meth_start, len(ms),
            field_start, len(fs),
        ))
    off_pool = 40
    off_classes = off_pool + len(pool)
    off_impls = off_classes + 36 * len(recs)
    off_methods = off_impls + 4 * len(impls)
    off_fields = off_methods + 8 * len(meths)
    hdr = struct.pack('<IIIIIIIIII', MAGIC, VERSION, len(recs), len(pool),
                      off_pool, off_classes, off_impls, off_methods, off_fields, 0)
    body = bytearray()
    for r in recs:
        body.extend(struct.pack('<IIIIIIIII', *r))
    for o in impls:
        body.extend(struct.pack('<I', o))
    for (o, fl) in meths:
        body.extend(struct.pack('<II', o, fl))
    for (o, fl) in fields:
        body.extend(struct.pack('<II', o, fl))
    return bytes(hdr) + bytes(pool) + bytes(body)


def selfcheck(blob, db):
    """Verify the blob round-trips a few known queries (binary search + sections)."""
    magic, ver, n, pool_len, off_pool, off_cls, off_impl, off_meth, off_fld, _ = \
        struct.unpack_from('<IIIIIIIIII', blob, 0)
    assert (magic, ver, n) == (MAGIC, VERSION, len(db))
    def s_at(off):
        end = blob.index(b'\x00', off_pool + off)
        return blob[off_pool + off: end]
    names = []
    for i in range(n):
        no = struct.unpack_from('<I', blob, off_cls + 36 * i)[0]
        names.append(s_at(no))
    assert names == sorted(names), 'class table not sorted'
    # spot queries
    idx = {nm: i for i, nm in enumerate(names)}
    def rec(i):
        return struct.unpack_from('<IIIIIIIII', blob, off_cls + 36 * i)
    vg = rec(idx[b'android/view/ViewGroup'])
    assert s_at(vg[1]) == b'android/view/View', 'ViewGroup super'
    vw = rec(idx[b'android/view/View'])
    fld_names = set()
    for k in range(vw[6 + 1], vw[6 + 1] + 0): pass
    fs_start, fs_len = vw[7], vw[8]
    for k in range(fs_len):
        so, _fl = struct.unpack_from('<II', blob, off_fld + 8 * (fs_start + k))
        fld_names.add(s_at(so))
    assert b'X' in fld_names, 'View.X field'
    thr = rec(idx[b'java/lang/Throwable'])
    ms = []
    for k in range(thr[6]):
        so, _fl = struct.unpack_from('<II', blob, off_meth + 8 * (thr[5] + k))
        ms.append(s_at(so))
    assert b'<init>(Ljava/lang/String;)V' in ms, 'Throwable ctor'
    assert b'org/apache/http/HttpResponse' in idx, 'removed-API class present'
    hr = rec(idx[b'org/apache/http/HttpResponse'])
    assert hr[2] & (1 << 31), 'xml-only flagged UNKNOWN'
    print(f'  selfcheck: {n} classes sorted ✓, ViewGroup<:View ✓, View.X ✓, '
          f'Throwable ctors ✓, apache removed-family ✓', file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    home = os.path.expanduser('~/Library/Android/sdk/platforms/android-37.0')
    ap.add_argument('--jar', default=f'{home}/android.jar')
    ap.add_argument('--xml', default=f'{home}/data/api-versions.xml')
    ap.add_argument('-o', default='crates/ddc-dec/data/android-api.fwdb')
    a = ap.parse_args()
    print(f'parsing {a.jar} ...', file=sys.stderr)
    db = parse_jar(a.jar)
    print(f'jar classes: {len(db)}', file=sys.stderr)
    added = merge_xml(a.xml, db)
    print(f'xml-only (removed-API) classes: {added}', file=sys.stderr)
    blob = build_blob(db)
    selfcheck(blob, db)
    os.makedirs(os.path.dirname(a.o) or '.', exist_ok=True)
    with open(a.o, 'wb') as f:
        f.write(blob)
    n_m = sum(len(v[3]) for v in db.values())
    n_f = sum(len(v[4]) for v in db.values())
    print(f'wrote {a.o}: {len(blob) / 1e6:.2f}MB '
          f'(classes={len(db)} methods={n_m} fields={n_f})', file=sys.stderr)


if __name__ == '__main__':
    main()
