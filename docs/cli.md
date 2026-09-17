# CLI reference

[English] | [简体中文](zh-CN/cli.md)

Everything `ddc --help` tells you, in more detail: invocation modes,
every option's semantics, every subcommand's output format and behavior.
The binary's help is the quick card; this is the manual.

Two invocation modes:

```
ddc [OPTIONS] <INPUT>... [OUTPUT]      # full decompile
ddc <SUBCOMMAND> [ARGS...]             # progressive analysis (query)
```

## Language

Messages (help, errors, summaries, table headers) localize automatically:
`DDC_LANG` (explicit `zh`/`en`) overrides `LC_ALL` > `LC_MESSAGES` > `LANG`;
any `zh*` value selects Chinese, everything else falls back to English.

```bash
DDC_LANG=zh ddc --help    # 中文帮助
LANG=zh_CN.UTF-8 ddc -V   # also Chinese
DDC_LANG=en ddc -V        # forced English even under a zh locale
```

## Full decompile

`ddc [OPTIONS] <INPUT>... [OUTPUT]`

**Inputs** (multiple merge into one class pool; duplicate classes are
deduplicated, first definition wins):

- `.dex` — versions 035–041
- `.apk` / `.jar` / `.zip` — every `classes.dex`, `classes2.dex`, … entry,
  merged in numeric order
- `.xapk` / `.apks` / `.apkm` — a zip of APKs: every inner APK's dexes
  merge, base first; labels are three-level (`container!base.apk!
  classes.dex`)
- a directory — scanned recursively for all of the above

**Output** — the last positional argument or `-o`:

- `<dir>` — output root, package structure preserved; default
  `<input-stem>-out/` next to the input
- `<file.java>` — a single class only (single-class input or `-c`)
- `-` — stdout, classes separated by `// ===== class =====` lines, in pool
  order (forces one thread)

Positional-argument disambiguation: with no `-o` and two or more
positionals, a **last** argument that isn't input-shaped (no dex-bearing
extension, not an existing file, not a directory containing dex files) is
the output — so `ddc app.apk out/` writes into the pre-created `out/`,
while `ddc a.dex dump/` treats a real dex directory as an input.

| Option | Semantics |
|---|---|
| `-o, --output <path>` | output location: dir / `file.java` / `-` |
| `-c, --class FQCN` | decompile only this class (dotted or slashed; nested/anonymous/local classes of it come along) |
| `-l, --list` | list class names and exit |
| `-t, --threads <n>` | worker count (default: CPU count; stdout forces one for pool order) |
| `--no-comments` | omit the provenance header |
| `-v, --verbose` | per-dex stats and slow classes on stderr |
| `-h, --help` / `-V, --version` | help / name+version+homepage |

`--opt=value` and `-o=path` forms both work. Bare `ddc help` / `ddc
version` do the same as `-h` / `-V`.

**Provenance header** (unless `--no-comments`):

```java
// Decompiled by https://github.com/ejfkdev/ddc 1.2.3
// From: app!classes3.dex (DEX 038)
// Source file: Foo.java
```

`From:` names the input file, the dex image, and the DEX version — the
fastest clue for which image a class lives in (jadx's `loaded from:`
pattern). Headers carry no timestamps, so two runs diff cleanly; a few
variable IDs may still differ between runs (std HashMap seed), with
identical semantics.

**Exit codes**: `0` success; `1` some classes failed (e.g. a
pathological-CFG timeout); `2` usage error (the error, then the full
help). A one-line summary goes to stderr when a run finishes: `ddc:
wrote 98348 file(s) to out/, 1 failed in 6.13s`.

## Progressive-analysis subcommands

All of them accept `-d/--dex NAME` (repeatable; entry-name substring —
the filter runs before parsing, so `getclass --dex classes20` parses
exactly one image) and most accept `-o FILE` to write the result.
Queries never enter the lift/structure/render pipeline; stdout stays
clean (timing prints only with `-o`).

### Get oriented

- **`ddc info <input>`** — one row per dex image: version, class,
  method, field, string counts, plus a total row.
- **`ddc listclasses <input> [pattern]`** — class names (internal
  `com/foo/Bar` form); pattern is a case-insensitive substring.
- **`ddc manifest <apk> [--component C] [-o FILE]`** — decodes the
  binary AndroidManifest.xml to text XML. `--component` filters to one
  element kind: `launcher` (the MAIN/LAUNCHER activity), `activity`,
  `service`, `receiver`, `provider`, `permission`, `activity-alias`,
  `application`. Raw `.axml` files are accepted directly. In XAPK/APKS
  containers the base APK's manifest is used.
- **`ddc mainactivity <apk>`** — package, custom Application class (if
  any), and the launcher activity, resolved through relative-name rules
  (`.MainActivity` → package-prefixed; bare word → package + word) and
  activity-alias `targetActivity`; then verified against the dex images
  (the defining image is reported).
- **`ddc res <apk> [entry] [-o FILE]`** — without an entry: every archive
  entry (method, compressed size; XAPK inner APKs flattened into
  `apk!name` labels). With an entry: dumps it — binary XML (first chunk
  `0x0003`) decodes through the AXML decoder, text prints as-is, binary
  content is saved via `-o` (or the error tells you to). Entry matching:
  exact name first, then a unique substring.

### Find things

- **`ddc strings <input> [-f TEXT] [--with-locations]`** — the string
  table (one row per string). `-f` filters by substring;
  `--with-locations` walks every method's const-string sites and adds a
  `used-by` column mapping each hit to its owner methods.
- **`ddc findrefs <input> <string|type|method|field> <query> [--class
  FQCN] [--fuzzy-class] [-o FILE]`** — every reference to a string
  literal / type / method call site / field access. Output is columnar
  with a header (`dex kind class method refs`), **one row per method**:
  multiple hits aggregate into `refs` (`; `-separated, deduped); `kind`
  is the first hit's instruction. Match semantics: queries are
  case-insensitive substrings; `--class` defaults to exact (dots,
  slashes and `L…;` descriptor forms all normalize) and `--fuzzy-class`
  widens it to substring.
- **`ddc callers <input> NAME [FQCN]`** — who invokes method NAME (the
  findrefs method machinery, scoped to one class optionally).
- **`ddc members <input> [NAME] [--class FQCN] [--fuzzy-class]
  [--method|--field]`** — method/field name search over the method and
  field id tables; `--method` / `--field` restrict the kind.

### Understand structure

- **`ddc hierarchy <input> FQCN`** — the class's lineage: `class` /
  `extends` / `implements` forward, `sub` / `impl` for every class that
  extends or implements it. Works across images (name-matched when the
  parent lives in another dex).
- **`ddc largest <input> [-n N]`** — top-N methods by instruction count
  (find the monsters; default 20).
- **`ddc disasm <input> FQCN[.method]`** — raw bytecode of a class or
  one method: one line per instruction (`pc opcode mnemonic`). The
  target resolves as a whole-string class first, then splits at the last
  dot — so both `org.foo.Cells.t1` (a class) and `Greeter.greet` (a
  method) work.

### Decompile surgically

- **`ddc getclass <input> FQCN [-o FILE] [--dex NAME]`** — one class
  with its nested/anonymous/local classes, through the full pipeline.
  Ambiguous names (defined in several images) get a warning listing the
  images; the defining image is registered first so the pool resolves
  from it.
- **`ddc getmethod <input> FQCN[.method] [-o FILE]`** — one method,
  sliced out of the decompiled class: provenance header + package line +
  every matching overload, dedented. A miss lists the class's method
  names. A bare class name falls back to the whole class.
- **`ddc pkg <input> PACKAGE [-o DIR] [-t N] [--app]`** — decompile a
  whole package subtree through the full pipeline (default output:
  `<package-with-underscores>-pkg/` next to the input). `""` or `.`
  means the root (default package included). `--app` takes the package
  from the manifest — and when that package has no classes (Telegram:
  manifest says `org.telegram.messenger.web`, code lives in
  `org.telegram.messenger`) it retries with the launcher class's
  package, which is where an app's own code clusters.

## Exit codes for subcommands

Usage errors (missing arguments, unknown options, bad `--dex`) print the
error plus the full help and exit `2`. Query misses (class/method/entry
not found) are also `2` but carry the specific miss in the error —
`getmethod` lists the available methods, `--dex` the available images.
