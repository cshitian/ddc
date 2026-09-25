#!/usr/bin/env python3
"""Extract the Android platform API database from the SDK's api-versions.xml.

One file already merges every API level: each class/member carries since /
deprecated / removed intervals (the official encoding of the per-version diff
— no need to download and unpack every platform jar). Output is a compact
JSON union database for embedding into ddc (dae-style self-contained SDK
profiles): framework subtype edges, method descriptors (overload sets), and
field names per class.

Usage: extract-android-api.py [api-versions.xml] [-o out.json]
"""
import json, sys, os, zlib
import xml.etree.ElementTree as ET

def main():
    src = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else \
        os.path.expanduser('~/Library/Android/sdk/platforms/android-37.0/data/api-versions.xml')
    out = 'android-api.json'
    if '-o' in sys.argv:
        out = sys.argv[sys.argv.index('-o') + 1]
    tree = ET.parse(src)
    root = tree.getroot()
    classes = {}
    n_m = n_f = 0
    for c in root.findall('class'):
        name = c.get('name')
        ent = {}
        for attr in ('since', 'deprecated', 'removed'):
            v = c.get(attr)
            if v and v != '1':
                ent[attr] = v
        ext = c.find('extends')
        if ext is not None and ext.get('name') != 'java/lang/Object':
            ent['e'] = ext.get('name')
        impl = [i.get('name') for i in c.findall('implements')]
        if impl:
            ent['i'] = impl
        ms = [m.get('name') for m in c.findall('method')]
        if ms:
            ent['m'] = ms
            n_m += len(ms)
        fs = [f.get('name') for f in c.findall('field')]
        if fs:
            ent['f'] = fs
            n_f += len(fs)
        classes[name] = ent
    db = {'meta': {'source': os.path.basename(os.path.dirname(os.path.dirname(src))) + '/api-versions.xml',
                   'classes': len(classes), 'methods': n_m, 'fields': n_f},
          'classes': classes}
    raw = json.dumps(db, separators=(',', ':'), ensure_ascii=False)
    with open(out, 'w') as f:
        f.write(raw)
    comp = zlib.compress(raw.encode(), 9)
    with open(out + '.z', 'wb') as f:
        f.write(comp)
    print(f'classes={len(classes)} methods={n_m} fields={n_f}')
    print(f'json={len(raw)/1e6:.2f}MB  zlib={len(comp)/1e6:.2f}MB  -> {out}')

if __name__ == '__main__':
    main()
