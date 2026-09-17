//! ddc — DEX decompiler CLI.
//!
//! Usage:
//!   ddc [OPTIONS] <INPUT>... [OUTPUT]
//! INPUT is a .dex image, an .apk/.jar/.zip containing classes*.dex, or a
//! directory scanned recursively for those. Multiple inputs merge into one
//! class pool. OUTPUT (or -o) is a directory, a single .java file (single
//! class only), or `-` for stdout; default: `<input-stem>-out/` sibling.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{bail, Context, Result};

mod axml;
mod findrefs;
mod inputs;

use inputs::{collect_images, dir_has_dex_files, expand_inputs, is_dex_ext, parse_images};

// Expr-tree-heavy workloads do billions of small allocations; the system
// allocator serializes cross-thread frees. mimalloc's per-thread heaps
// unlock the flat thread-scaling curve.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
use ddc_dec::{top_level_classes, ClassOptions, DexPool};

fn print_help() {
    println!("ddc {} — DEX decompiler (Dalvik → Java)", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Decompiles DEX images (versions 035-041, multi-dex APKs, invoke-custom)");
    println!("back into readable Java source.");
    println!();
    println!("Usage: ddc [OPTIONS] <INPUT>... [OUTPUT]");
    println!("       ddc <help|version>");
    println!();
    println!("INPUT is a .dex file, an .apk/.jar/.zip archive containing");
    println!("classes.dex / classes2.dex..., or a directory (scanned recursively).");
    println!("Multiple inputs merge into one class pool (duplicates skipped).");
    println!();
    println!("OUTPUT, given either as the last positional argument or -o:");
    println!("  <dir>       output root, package structure preserved");
    println!("  <file.java> one class only (single-class input or -c)");
    println!("  -           stdout (`// ===== class =====` separators)");
    println!("  Default: <input-stem>-out/ next to the input.");
    println!();
    println!("Options:");
    println!("  -o, --output <path>   output location (see OUTPUT above)");
    println!("  -c, --class FQCN      decompile only this class (dotted/slashed)");
    println!("  -l, --list            list class names and exit");
    println!("  --no-comments         omit the provenance header");
    println!("  -t, --threads <n>     parallel workers (default: CPU count)");
    println!("  -v, --verbose         stats per dex and slow classes on stderr");
    println!("  -h, --help            print this help");
    println!("  -V, --version         print version");
    println!();
    println!("Progressive analysis (query the artifact as a database — no full");
    println!("decompile; metadata loads take well under a second):");
    println!("  ddc manifest <apk>                 # AndroidManifest.xml → text XML");
    println!("  ddc info <input>                   # per-dex class/method/field/string counts");
    println!("  ddc listclasses <input> [pattern]  # class names, optional fuzzy filter");
    println!("  ddc getclass <input> <FQCN> [-o f] # decompile one class (+nested)");
    println!("  ddc findrefs <input> string TEXT   # refs to string literals");
    println!("  ddc findrefs <input> type com.example.Foo");
    println!("  ddc findrefs <input> method init --class com.example.Foo [--fuzzy-class]");
    println!("  ddc findrefs <input> field CREATOR --class com.example --fuzzy-class");
    println!("                                      # refs only — class/method names are");
    println!("                                      # fuzzy (substring); --class defaults exact");
    println!();
    println!("Exit status: 0 ok; 1 some classes failed; 2 usage error.");
    println!();
    println!("Examples:");
    println!("  ddc app.apk                       # app-out/ next to the apk");
    println!("  ddc app.apk src/                  # dae-style positional output");
    println!("  ddc classes.dex -o out/           # explicit output root");
    println!("  ddc app.apk -o -                  # dump everything to stdout");
    println!("  ddc app.apk -c com.example.Foo    # one class to stdout");
    println!("  ddc app.apk -c com.example.Foo -o Foo.java");
    println!("  ddc base.apk patch.dex -o merged/ # split inputs, one pool");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Leading subcommand word (unless an actual path shadows it) routes
    // to the metadata fast paths: query the artifact as a database
    // instead of decompiling everything.
    if let Some(cmd) = args.first() {
        if is_subcommand(cmd) && !Path::new(cmd).exists() {
            if let Err(e) = run_subcommand(cmd, &args[1..]) {
                eprintln!("ddc: {e:?}");
                eprintln!();
                print_help();
                std::process::exit(2);
            }
            return;
        }
    }
    if let Err(e) = run() {
        // Invalid invocation: show what went wrong, then the full help so
        // the user does not have to re-run with -h.
        eprintln!("ddc: {e:?}");
        eprintln!();
        print_help();
        std::process::exit(2);
    }
}

fn is_subcommand(word: &str) -> bool {
    matches!(
        word,
        "getclass" | "listclasses" | "findrefs" | "manifest" | "info"
    )
}

/// Progressive-analysis commands (ASC-style "query, don't decompile"):
/// each loads only the metadata it needs.
fn run_subcommand(cmd: &str, args: &[String]) -> Result<()> {
    let t0 = std::time::Instant::now();
    match cmd {
        "manifest" => cmd_manifest(args, t0),
        "info" => cmd_info(args, t0),
        "listclasses" => cmd_listclasses(args, t0),
        "getclass" => cmd_getclass(args, t0),
        "findrefs" => cmd_findrefs(args, t0),
        _ => bail!("unknown subcommand: {cmd}"),
    }
}

/// Shared: first positional argument of a subcommand (the input).
fn sub_input(args: &[String], cmd: &str) -> Result<PathBuf> {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .with_context(|| format!("{cmd} needs an input file"))
}

// ---- manifest ---------------------------------------------------------------

fn cmd_manifest(args: &[String], t0: std::time::Instant) -> Result<()> {
    let mut input = sub_input(args, "manifest")?;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                out = Some(PathBuf::from(
                    args.get(i + 1).context("-o needs a value")?,
                ));
                i += 1;
            }
            a if a.starts_with('-') => bail!("manifest: unknown option {a}"),
            _ => {}
        }
        i += 1;
    }
    // A ZIP/APK contributes its AndroidManifest.xml entry; a raw file is
    // itself a binary XML (`.axml`) — no dex parse either way.
    let xml = {
        let bytes = std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
        if bytes.len() >= 4 && &bytes[..2] == b"PK" {
            let entries = zip_entries(&bytes)?;
            let (name, data, method) = entries
                .into_iter()
                .find(|(n, _, _)| n == "AndroidManifest.xml")
                .with_context(|| format!("{}: no AndroidManifest.xml entry", input.display()))?;
            let raw = match method {
                ZipMethod::Stored => data,
                ZipMethod::Deflate => inflate(&data)?,
            };
            input = PathBuf::from(name);
            raw
        } else {
            bytes
        }
    };
    let text = axml::axml_to_xml(&xml)
        .map_err(|e| anyhow::anyhow!("{}: {}", input.display(), e))?;
    match out {
        Some(f) => {
            if let Some(parent) = f.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&f, &text)?;
            eprintln!("ddc: wrote manifest to {} in {}", f.display(), fmt_secs(t0.elapsed()));
        }
        None => {
            print!("{text}");
            eprintln!("ddc: manifest in {}", fmt_secs(t0.elapsed()));
        }
    }
    Ok(())
}

// ---- info -------------------------------------------------------------------

fn cmd_info(args: &[String], t0: std::time::Instant) -> Result<()> {
    let input = sub_input(args, "info")?;
    let files = expand_inputs(&[input])?;
    let parsed = parse_images(collect_images(&files)?)?;
    let mut total_classes = 0usize;
    println!("{:>10}  {:>8}  {:>10}  {:>10}  {:>9}  {:>10}", "image", "dex", "classes", "methods", "fields", "strings");
    for (label, dex) in &parsed {
        let classes = dex.class_defs.len();
        total_classes += classes;
        println!(
            "{:>10}  {:>8}  {:>10}  {:>10}  {:>9}  {:>10}",
            label,
            dex.version,
            classes,
            dex.method_count(),
            dex.field_count(),
            dex.string_count(),
        );
    }
    println!("total: {} image(s), {} classes", parsed.len(), total_classes);
    eprintln!("ddc: info in {}", fmt_secs(t0.elapsed()));
    Ok(())
}

// ---- listclasses ------------------------------------------------------------

fn cmd_listclasses(args: &[String], t0: std::time::Instant) -> Result<()> {
    let input = sub_input(args, "listclasses")?;
    let mut pattern: Option<String> = None;
    let mut i = 0;
    let mut seen_input = false;
    while i < args.len() {
        match args[i].as_str() {
            a if a.starts_with('-') => bail!("listclasses: unknown option {a}"),
            a => {
                if seen_input {
                    pattern = Some(a.to_string());
                } else {
                    seen_input = true;
                }
            }
        }
        i += 1;
    }
    let files = expand_inputs(&[input])?;
    let parsed = parse_images(collect_images(&files)?)?;
    let mut pool = DexPool::new();
    for (label, dex) in parsed {
        let idx = pool.add_dex(dex);
        pool.set_dex_label(idx, label);
    }
    let all: Vec<&str> = pool.class_names().collect();
    let shown: Vec<&str> = match &pattern {
        Some(p) => {
            let lp = p.to_ascii_lowercase();
            all.into_iter()
                .filter(|n| n.to_ascii_lowercase().contains(&lp))
                .collect()
        }
        None => all,
    };
    for name in &shown {
        println!("{}", name.replace('/', "."));
    }
    match pattern {
        Some(p) => eprintln!(
            "ddc: listed {} of {} classes matching {:?} in {}",
            shown.len(),
            pool.len(),
            p,
            fmt_secs(t0.elapsed())
        ),
        None => eprintln!(
            "ddc: listed {} classes in {}",
            shown.len(),
            fmt_secs(t0.elapsed())
        ),
    }
    Ok(())
}

// ---- getclass ---------------------------------------------------------------

fn cmd_getclass(args: &[String], t0: std::time::Instant) -> Result<()> {
    let mut fqcn: Option<String> = None;
    let mut input: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                out = Some(PathBuf::from(args.get(i + 1).context("-o needs a value")?));
                i += 1;
            }
            a if a.starts_with('-') => bail!("getclass: unknown option {a}"),
            a => {
                if input.is_none() {
                    input = Some(PathBuf::from(a));
                } else if fqcn.is_none() {
                    fqcn = Some(a.to_string());
                } else {
                    bail!("getclass: too many arguments (one input and one class)");
                }
            }
        }
        i += 1;
    }
    let input = input.context("getclass needs an input file")?;
    let fqcn = fqcn.context("getclass needs a class name (com.example.Foo)")?;
    let files = expand_inputs(&[input])?;
    let parsed = parse_images(collect_images(&files)?)?;
    let mut pool = DexPool::new();
    for (label, dex) in parsed {
        let idx = pool.add_dex(dex);
        pool.set_dex_label(idx, label);
    }
    let pool = std::sync::Arc::new(pool);
    let internal = fqcn.replace('.', "/");
    let pc = pool.get(&internal).with_context(|| {
        format!("class {fqcn} not found (try `ddc listclasses <input> <pattern>`)")
    })?;

    let pending: std::sync::Mutex<
        Vec<(
            std::sync::mpsc::Receiver<Result<String, String>>,
            String,
            std::time::Instant,
        )>,
    > = std::sync::Mutex::new(Vec::new());
    let opts = ClassOptions::default();
    let result = ddc_dec::classdec::decompile_class(&pool, pc, &opts, &pending)
        .map_err(|e| anyhow::anyhow!("{:#}", e));
    let mut text = match result {
        Ok(t) => t,
        Err(e) => {
            if format!("{e:#}").contains("deferred to monitored thread") {
                let (rx, name, deadline) = pending.into_inner().unwrap().remove(0);
                let now = std::time::Instant::now();
                let remaining = deadline.saturating_duration_since(now);
                rx.recv_timeout(remaining)
                    .map_err(|_| anyhow::anyhow!("{name}: decompile timed out"))?
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            } else {
                return Err(e);
            }
        }
    };
    text.push('\n');
    match out {
        Some(f) => {
            if let Some(parent) = f.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&f, &text)?;
            eprintln!("ddc: wrote {} in {}", f.display(), fmt_secs(t0.elapsed()));
        }
        None => {
            print!("{text}");
            eprintln!("ddc: getclass {fqcn} in {}", fmt_secs(t0.elapsed()));
        }
    }
    Ok(())
}

// ---- findrefs ---------------------------------------------------------------

fn cmd_findrefs(args: &[String], t0: std::time::Instant) -> Result<()> {
    let mut positionals: Vec<String> = Vec::new();
    let mut class: Option<String> = None;
    let mut fuzzy_class = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--class" | "-C" => {
                class = Some(args.get(i + 1).context("--class needs a value")?.to_string());
                i += 1;
            }
            "--fuzzy-class" => fuzzy_class = true,
            a if a.starts_with('-') => bail!("findrefs: unknown option {a}"),
            a => positionals.push(a.to_string()),
        }
        i += 1;
    }
    if positionals.len() < 3 {
        bail!(
            "findrefs needs: <input> <string|type|method|field> <query> \\
             (method/field also take --class X, --fuzzy-class)"
        );
    }
    let input = PathBuf::from(&positionals[0]);
    let kind = positionals[1].clone();
    let value = positionals[2].clone();
    let query = match kind.as_str() {
        "string" => findrefs::FindQuery::String(value),
        "type" => findrefs::FindQuery::Type(value),
        "method" => findrefs::FindQuery::Method { class, name: value, fuzzy_class },
        "field" => findrefs::FindQuery::Field { class, name: value, fuzzy_class },
        other => bail!("findrefs: unknown kind {other:?} (string|type|method|field)"),
    };

    let files = expand_inputs(&[input])?;
    let parsed = parse_images(collect_images(&files)?)?;
    // One scan thread per dex image (weibo: 20 images → 20 threads).
    let mut handles = Vec::new();
    for (label, dex) in parsed {
        let query = query.clone();
        handles.push(std::thread::spawn(move || findrefs::scan_dex(&label, &dex, &query)));
    }
    let mut hits = Vec::new();
    for h in handles {
        let one = h
            .join()
            .map_err(|_| anyhow::anyhow!("scan thread panicked"))??;
        hits.extend(one);
    }
    hits.sort_by(|a, b| a.class.cmp(&b.class).then(a.method.cmp(&b.method)));

    for h in &hits {
        println!(
            "{}.{}  ->  {} {}",
            h.class.replace('/', "."),
            h.method,
            h.insn,
            h.target
        );
    }
    eprintln!(
        "ddc: findrefs {} → {} hit(s) in {}",
        query.kind(),
        hits.len(),
        fmt_secs(t0.elapsed())
    );
    Ok(())
}

/// Where the decompiled source goes.
#[derive(Debug, Clone)]
enum Sink {
    /// Print to stdout with `// ===== class =====` separators.
    Stdout,
    /// Root directory; each class at its package-relative path.
    Dir(PathBuf),
    /// One explicit .java file (single emitted class only).
    File(PathBuf),
}

fn run() -> Result<()> {
    let t_start = std::time::Instant::now();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut positionals: Vec<PathBuf> = Vec::new();
    let mut out: Option<String> = None;
    let mut only: Option<String> = None;
    let mut list = false;
    let mut comments = true;
    let mut workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut verbose = false;

    let mut i = 0;
    while i < args.len() {
        // Bare commands (only when they cannot be an input yet).
        if positionals.is_empty() && !args[i].starts_with('-') {
            match args[i].as_str() {
                "help" => {
                    print_help();
                    return Ok(());
                }
                "version" => {
                    println!("ddc {}", env!("CARGO_PKG_VERSION"));
                    return Ok(());
                }
                _ => {}
            }
        }
        // Split `--opt=value` / `-o=path` into name + inline value.
        let (name, inline_val) = match args[i].split_once('=') {
            Some((n, v)) if n.starts_with('-') => (n.to_string(), Some(v.to_string())),
            _ => (args[i].clone(), None),
        };
        macro_rules! take_value {
            () => {{
                match inline_val.clone() {
                    Some(v) => v,
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .with_context(|| format!("{} needs a value", name))?
                    }
                }
            }};
        }
        match name.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "-V" | "--version" => {
                println!("ddc {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-o" | "--output" => out = Some(take_value!()),
            "-c" | "--class" => only = Some(take_value!()),
            "-l" | "--list" => list = true,
            "--no-comments" => comments = false,
            "-t" | "--threads" => {
                workers = take_value!().parse().unwrap_or(4);
            }
            "-v" | "--verbose" => verbose = true,
            other => {
                if other.starts_with('-') {
                    bail!("unknown option {} (try --help)", other);
                }
                positionals.push(PathBuf::from(other));
            }
        }
        i += 1;
    }
    if positionals.is_empty() {
        bail!("no input given (try --help)");
    }
    // dae/pycdc-style positional output: with no -o and TWO OR MORE
    // positionals, a LAST argument is the OUTPUT unless it looks like an
    // input (`ddc base.apk patch.dex merged/`). "Looks like an input":
    // has a dex-bearing extension, is a file, or is a directory that
    // actually CONTAINS dex-bearing files. A directory without any
    // (e.g. a pre-created output dir, or last run's output) is the
    // OUTPUT — treating it as an input made `ddc apk weibo` with an
    // existing empty `weibo/` silently fall back to the default
    // sibling dir.
    if out.is_none() && positionals.len() >= 2 {
        let last = positionals[positionals.len() - 1].clone();
        let looks_input = is_dex_ext(&last)
            || (last.exists() && !last.is_dir())
            || (last.is_dir() && dir_has_dex_files(&last));
        if !looks_input {
            positionals.pop();
            out = Some(last.display().to_string());
        }
    }
    let inputs = positionals;

    let files = expand_inputs(&inputs)?;
    let t_wall = std::time::Instant::now();
    let t_read = t_wall.elapsed();
    let parsed = parse_images(collect_images(&files)?)?;
    let t_inflate = t_wall.elapsed();

    let mut pool = DexPool::new();
    for (label, dex) in parsed {
        let before = pool.len();
        let ver = dex.version.clone();
        let idx = pool.add_dex(dex);
        pool.set_dex_label(idx, label.clone());
        if verbose {
            eprintln!("[+] {} ({} classes, DEX {})", label, pool.len() - before, ver);
        }
    }
    let dex_count = pool.dex_count();
    if std::env::var("DDC_WALL").is_ok() {
        eprintln!(
            "[wall] read={:?} zip-scan={:?} parse+pool={:?} total={:?}",
            t_read,
            t_inflate - t_read,
            t_wall.elapsed() - t_inflate,
            t_wall.elapsed()
        );
    }

    if verbose {
        eprintln!(
            "[i] {} dex file(s), {} classes",
            dex_count,
            pool.len()
        );
    }

    if list {
        for name in pool.class_names() {
            println!("{}", name.replace('/', "."));
        }
        eprintln!(
            "ddc: listed {} classes in {}",
            pool.len(),
            fmt_secs(t_start.elapsed())
        );
        return Ok(());
    }

    let pool = std::sync::Arc::new(pool);
    if std::env::var("DDC_PHASES").is_ok() {
        ddc_dec::method::phases_enable();
        ddc_dec::method::dom_counters_enable();
    }
    let opts = ClassOptions { provenance: comments };
    let targets: Vec<String> = match &only {
        Some(one) => {
            let internal = one.replace('.', "/");
            if pool.get(&internal).is_none() {
                bail!("class not found: {} (try --list)", one);
            }
            vec![internal]
        }
        None => top_level_classes(&pool),
    };

    // ---- resolve the output sink ----
    let sink = resolve_sink(&inputs, out.as_deref(), &targets)?;
    if let Sink::Dir(d) = &sink {
        std::fs::create_dir_all(d)?;
    }
    // Stdout must be deterministic: pool order, one worker.
    let stdout_mode = matches!(sink, Sink::Stdout);
    if stdout_mode && workers > 1 && targets.len() > 1 {
        workers = 1;
    }

    // Detached monitored threads for pathological classes:
    // (receiver, class name, deadline Instant). Deadlines arm at SPAWN
    // time, so draining at the end costs at most one deadline total.
    let pending: std::sync::Mutex<
        Vec<(
            std::sync::mpsc::Receiver<Result<String, String>>,
            String,
            std::time::Instant,
        )>,
    > = std::sync::Mutex::new(Vec::new());
    let pending_ref = &pending;

    let failed = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let total = targets.len();
    let pool_ref = &pool;
    let opts_ref = &opts;
    let sink_ref = &sink;
    let failed_ref = &failed;
    let done_ref = &done;
    let nowrite = std::env::var("DDC_NOWRITE").is_ok();
    let class_time = std::env::var("DDC_CLASSTIME").is_ok();

    // Writer pool: decompile workers hand finished sources to dedicated
    // writer threads through a bounded MPMC queue (std mpsc has no
    // multi-consumer). Measured on weibo: inline fs::write stalled
    // workers ~64s of wall (APFS metadata + page-cache flushing under 12
    // concurrent writers) while user CPU was only ~146s — workers sat
    // blocked-in-kernel at "100% busy". The bound (256) keeps memory
    // flat; writers keep per-thread mkdir caches (create_dir_all is
    // idempotent, no shared lock).
    struct WriteQueue {
        q: std::sync::Mutex<std::collections::VecDeque<(std::path::PathBuf, String)>>,
        not_empty: std::sync::Condvar,
        not_full: std::sync::Condvar,
        cap: usize,
    }
    impl WriteQueue {
        fn push(&self, item: (std::path::PathBuf, String)) {
            let mut q = self.q.lock().unwrap();
            while q.len() >= self.cap {
                q = self.not_full.wait(q).unwrap();
            }
            q.push_back(item);
            self.not_empty.notify_one();
        }
        fn close(&self) {
            let mut q = self.q.lock().unwrap();
            // Sentinel-free shutdown: writers exit on the CLOSED marker.
            q.push_back((std::path::PathBuf::new(), String::new()));
            self.not_empty.notify_all();
        }
        fn pop(&self) -> Option<(std::path::PathBuf, String)> {
            let mut q = self.q.lock().unwrap();
            loop {
                if let Some(item) = q.pop_front() {
                    self.not_full.notify_one();
                    if item.0.as_os_str().is_empty() && item.1.is_empty() {
                        // Shutdown marker consumed: restore it for the
                        // other writers, then exit.
                        q.push_back(item);
                        self.not_empty.notify_one();
                        return None;
                    }
                    return Some(item);
                }
                q = self.not_empty.wait(q).unwrap();
            }
        }
    }
    let wq = std::sync::Arc::new(WriteQueue {
        q: std::sync::Mutex::new(std::collections::VecDeque::new()),
        not_empty: std::sync::Condvar::new(),
        not_full: std::sync::Condvar::new(),
        // Effectively unbounded: the 992MB of weibo output fits the page
        // cache, and blocking the decompile workers on APFS metadata (the
        // measured 64s stall) costs far more than a transient memory bump.
        cap: 1 << 20,
    });
    let n_writers = workers.clamp(2, 4);
    let uses_writers = matches!(sink, Sink::Dir(_)) && !nowrite;
    let writer_handles: Vec<std::thread::JoinHandle<()>> = if uses_writers {
        (0..n_writers)
            .map(|_| {
                let wq = wq.clone();
                std::thread::spawn(move || {
                    let mut dirs: std::collections::HashSet<std::path::PathBuf> =
                        std::collections::HashSet::new();
                    while let Some((path, text)) = wq.pop() {
                        if let Some(parent) = path.parent() {
                            if dirs.insert(parent.to_path_buf()) {
                                let _ = std::fs::create_dir_all(parent);
                            }
                        }
                        let _ = std::fs::write(&path, text);
                    }
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    // Dynamic work queue: small slices pulled via an atomic cursor —
    // slow (efficiency) cores naturally take less, so static-chunk
    // stragglers disappear.
    const CHUNK: usize = 32;
    static BUSY_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static WORKER_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let queue: Vec<Vec<String>> = if stdout_mode || targets.len() <= 1 {
        // One ordered chunk: stdout emits in pool order (single worker
        // forced above); a lone class has nothing to split.
        vec![targets.clone()]
    } else {
        targets.chunks(CHUNK).map(|c| c.to_vec()).collect()
    };
    let cursor = AtomicUsize::new(0);
    let queue_ref = &queue;
    let cursor_ref = &cursor;
    std::thread::scope(|scope| {
        let wq_ref = &wq;
        let mut handles = Vec::new();
        for _ in 0..workers.min(queue.len()).max(1) {
            handles.push(
                std::thread::Builder::new()
                    .stack_size(64 * 1024 * 1024)
                    .spawn_scoped(scope, move || -> usize {
                let mut local_failed = 0usize;
                let worker_start = std::time::Instant::now();
                let mut busy = std::time::Duration::ZERO;
                let mut iter_start = std::time::Instant::now();
                loop {
                    let qi = cursor_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(chunk) = queue_ref.get(qi) else { break };
                    // (includes the fetch itself — negligible next to a
                    // chunk of 32 classes)
                    busy += iter_start.elapsed();
                    iter_start = std::time::Instant::now();
                    for name in chunk {
                    let ct0 = std::time::Instant::now();
                    let Some(pc) = pool_ref.get(&name) else { continue };
                    // A panic in one class must not take down the worker
                    // (the whole chunk would be lost); pathological CFGs run
                    // on a detached monitored thread (decompile_class
                    // decides) whose handle is awaited with its deadline at
                    // the END — the worker never blocks on it.
                    let out = std::panic::catch_unwind(
                        std::panic::AssertUnwindSafe(|| {
                            ddc_dec::classdec::decompile_class(
                                pool_ref,
                                pc,
                                opts_ref,
                                pending_ref,
                            )
                        }),
                    );
                    match out {
                        Ok(Ok(text)) => {
                            match sink_ref {
                                Sink::Stdout => {
                                    if total > 1 {
                                        println!("\n// ===== {} =====", name.replace('/', "."));
                                    }
                                    println!("{}", text);
                                }
                                Sink::File(f) => {
                                    if !nowrite {
                                        if let Some(parent) = f.parent() {
                                            let _ = std::fs::create_dir_all(parent);
                                        }
                                        let _ = std::fs::write(f, text);
                                    }
                                }
                                Sink::Dir(d) => {
                                    if !nowrite {
                                        // Hand off to the writer pool; the bounded
                                        // queue blocks only when writers fall
                                        // behind (backpressure, not a stall).
                                        wq_ref.push((source_path(d, &name), text));
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            if format!("{:#}", e).contains("deferred to monitored thread") {
                                // Result arrives via the pending registry
                                // (awaited after the chunk phase).
                                continue;
                            }
                            local_failed += 1;
                            eprintln!("[!] {}: {:#}", name.replace('/', "."), e);
                        }
                        Err(e) => {
                            local_failed += 1;
                            let msg = e
                                .downcast_ref::<String>()
                                .cloned()
                                .or_else(|| e.downcast_ref::<&str>().map(|m| m.to_string()))
                                .unwrap_or_else(|| "panic".into());
                            eprintln!("[!] {}: {}", name.replace('/', "."), msg);
                        }
                    }
                        let n = done_ref.fetch_add(1, Ordering::Relaxed) + 1;
                        if class_time && ct0.elapsed().as_millis() >= 50 {
                            eprintln!("[ctime] {:>6}ms {}", ct0.elapsed().as_millis(), name);
                        }
                        if verbose && n % 500 == 0 {
                            eprintln!("[i] {}/{} classes", n, total);
                        }
                    }
                }
                WORKER_MICROS.fetch_add(worker_start.elapsed().as_micros() as u64, Ordering::Relaxed);
                BUSY_MICROS.fetch_add(busy.as_micros() as u64, Ordering::Relaxed);
                local_failed
                    })
                    .map(|h| h),
            );
        }
        for h in handles.into_iter().flatten() {
            failed_ref.fetch_add(h.join().unwrap_or(0), Ordering::Relaxed);
        }
    });
    let t_work = t_wall.elapsed();

    // Drain the detached pathological-class threads: deadlines armed at
    // spawn, so the total tail is bounded by one deadline.
    let mut pending: Vec<_> = pending.into_inner().unwrap();
    if std::env::var("DDC_WALL").is_ok() {
        eprintln!("[wall] deferred-to-monitored: {} classes", pending.len());
    }
    pending.sort_by_key(|(_, _, dl)| *dl);
    for (rx, name, deadline) in pending {
        let now = std::time::Instant::now();
        let remaining = if deadline > now {
            deadline - now
        } else {
            std::time::Duration::ZERO
        };
        match rx.recv_timeout(remaining) {
            Ok(Ok(text)) => {
                match &sink {
                    Sink::Stdout => {
                        if total > 1 {
                            println!("\n// ===== {} =====", name.replace('/', "."));
                        }
                        println!("{}", text);
                    }
                    Sink::File(f) => {
                        if !nowrite {
                            if let Some(parent) = f.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                            let _ = std::fs::write(f, text);
                        }
                    }
                    Sink::Dir(d) => {
                        if !nowrite {
                            wq.push((source_path(d, &name), text));
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[!] {}: {}", name.replace('/', "."), e);
            }
            Err(_) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[!] {}: decompile timed out (pathological CFG)", name.replace('/', "."));
            }
        }
    }

    // All producers done: release the writers and join them (flush the
    // remaining queue before exiting).
    wq.close();
    for h in writer_handles {
        let _ = h.join();
    }
    let t_flush = t_wall.elapsed();

    if std::env::var("DDC_WALL").is_ok() {
        let busy = BUSY_MICROS.load(Ordering::Relaxed) as f64 / 1e6;
        let worker = WORKER_MICROS.load(Ordering::Relaxed) as f64 / 1e6;
        eprintln!(
            "[wall] work={:?} drain={:?} flush={:?} busy={:.1}s worker={:.1}s util={:.0}%",
            t_work - t_read,
            t_flush - t_work,
            t_wall.elapsed() - t_flush,
            busy,
            worker,
            100.0 * busy / worker.max(0.001)
        );
        let (dc, db) = ddc_dec::method::dom_counters();
        eprintln!("[dom] {} compute_dominators calls, {} total blocks scanned", dc, db);
    }

    if std::env::var("DDC_PHASES").is_ok() {
        let ph = ddc_dec::method::phases_dump();
        let labels = ["fixpoint", "structure+convert", "passes", "print"];
        for (i, l) in labels.iter().enumerate() {
            eprintln!("[phase] {:>18}: {:8.1}s", l, ph[i] as f64 / 1e6);
        }
        let pb = ddc_dec::method::phases_bucket_dump();
        let blabels = ["<=1 blk", "2-5 blk", "6-20 blk", "21-100 blk", ">100 blk"];
        eprintln!("[phase x bucket] (cumulative from fixpoint start)");
        for (i, l) in labels.iter().enumerate().take(3) {
            let cells: Vec<String> = (0..5)
                .map(|b| format!("{:6.1}s", pb[i][b] as f64 / 1e6))
                .collect();
            eprintln!("  {:>16}: {}", l, cells.join(" "));
        }
        eprintln!("  buckets           : {}", blabels.join("  "));
    }
    if std::env::var("DDC_BUCKETS").is_ok() {
        let (b, i) = ddc_dec::method::dump_builds();
        eprintln!("[builds] {} block-lifts, {} insns lifted", b, i);
        let (ch, ci) = ddc_dec::method::dump_caps();
        eprintln!("[caps] {} methods hit visit cap, {} (insns*1000+blocks sum)", ch, ci);
        let b = ddc_dec::method::dump_buckets();
        let labels = ["<=1 blk", "2-5 blk", "6-20 blk", "21-100 blk", ">100 blk"];
        eprintln!("[buckets]");
        for (i, (n, us)) in b.iter().enumerate() {
            if *n > 0 {
                eprintln!(
                    "  {:>10}: {:6} methods {:8.1}s total {:7.1}us avg",
                    labels[i],
                    n,
                    *us as f64 / 1e6,
                    *us as f64 / *n as f64
                );
            }
        }
    }
    // Summary + exit status (0 all ok, 1 some classes failed).
    let failed_n = failed.load(Ordering::Relaxed);
    let elapsed = fmt_secs(t_start.elapsed());
    let failed_part = if failed_n > 0 {
        format!(", {failed_n} failed")
    } else {
        String::new()
    };
    match &sink {
        Sink::Dir(d) => eprintln!(
            "ddc: wrote {} file(s) to {}{} in {}",
            total - failed_n,
            d.display(),
            failed_part,
            elapsed
        ),
        Sink::File(f) => eprintln!(
            "ddc: wrote {} file to {}{} in {}",
            total - failed_n,
            f.display(),
            failed_part,
            elapsed
        ),
        Sink::Stdout => {
            if !verbose {
                eprintln!(
                    "ddc: printed {} class(es) to stdout{} in {}",
                    total - failed_n,
                    failed_part,
                    elapsed
                );
            }
        }
    }
    if failed_n > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// `0.004s` under a second, `0.24s` under ten, `5.6s` above (precision
/// where it reads).
fn fmt_secs(d: std::time::Duration) -> String {
    let s = d.as_secs_f64();
    if s < 1.0 {
        format!("{s:.3}s")
    } else if s < 10.0 {
        format!("{s:.2}s")
    } else {
        format!("{s:.1}s")
    }
}

/// Decide where the decompiled source goes. `-o`/positional-output
/// semantics: `-` forces stdout; a `.java` suffix (or an existing
/// non-directory) is a single output file (single emitted class only —
/// with `-c` or a one-class pool); anything else is an output root
/// directory. With no output given, every input writes to a sibling
/// `<stem>-out/` directory (single .dex inputs included: a dex always
/// carries many classes, unlike jcdc's single .class).
fn resolve_sink(
    inputs: &[PathBuf],
    out: Option<&str>,
    targets: &[String],
) -> Result<Sink> {
    let single_class = targets.len() == 1;
    match out {
        Some("-") => Ok(Sink::Stdout),
        Some(o) => {
            let p = PathBuf::from(o);
            let is_file = p.extension().and_then(|e| e.to_str()) == Some("java")
                || (p.exists() && p.is_file());
            if is_file {
                if !single_class {
                    bail!(
                        "-o {} names a file but {} class(es) would be written \
                         (use a directory, `-c`, or `-`)",
                        o,
                        targets.len()
                    );
                }
                return Ok(Sink::File(p));
            }
            Ok(Sink::Dir(p))
        }
        None => {
            // A single emitted class (-c, or a one-class dex) prints to
            // stdout like jcdc's single .class; everything else needs a
            // directory.
            if single_class {
                return Ok(Sink::Stdout);
            }
            let input = inputs
                .first()
                .context("no input to derive an output path from")?;
            let stem = input
                .file_stem()
                .or_else(|| input.file_name())
                .and_then(|s| s.to_str())
                .context("input has no usable name")?;
            let dir = input
                .parent()
                .unwrap_or(Path::new("."))
                .join(format!("{}-out", stem));
            eprintln!(
                "ddc: no output given; writing to {} (pass -o or a positional OUTPUT to override, -o - for stdout)",
                dir.display()
            );
            Ok(Sink::Dir(dir))
        }
    }
}




/// `com/foo/Bar$Inner` → `<out>/com/foo/Bar$Inner.java`.
fn source_path(out: &Path, internal: &str) -> PathBuf {
    let mut p = out.to_path_buf();
    for seg in internal.split('/') {
        p.push(seg);
    }
    p.set_extension("java");
    p
}

// ---------------------------------------------------------------------------
// Minimal ZIP reader (stored + deflate), enough for APK/JAR class extraction.
// ---------------------------------------------------------------------------

pub(crate) enum ZipMethod {
    Stored,
    Deflate,
}

pub(crate) fn zip_entries(data: &[u8]) -> Result<Vec<(String, Vec<u8>, ZipMethod)>> {
    // Find EOCD (22 bytes + optional comment).
    let eocd = find_eocd(data).context("zip: EOCD not found")?;
    let cd_size = u32le(data, eocd + 12) as usize;
    let cd_off = u32le(data, eocd + 16) as usize;
    let n = u32le(data, eocd + 10) as usize;
    let mut out = Vec::with_capacity(n);
    let mut p = cd_off;
    for _ in 0..n {
        if p + 46 > data.len() || u32le(data, p) != 0x0201_4b50 {
            break;
        }
        let method = u16le(data, p + 10);
        let csize = u32le(data, p + 20) as usize;
        let name_len = u16le(data, p + 28) as usize;
        let extra_len = u16le(data, p + 30) as usize;
        let comm_len = u16le(data, p + 32) as usize;
        let lho = u32le(data, p + 42) as usize;
        let name = String::from_utf8_lossy(&data[p + 46..p + 46 + name_len]).into_owned();
        // Local header: fixed 30 bytes + name + extra (name length from the
        // local header may differ from the central one).
        if lho + 30 <= data.len() {
            let l_name_len = u16le(data, lho + 26) as usize;
            let l_extra_len = u16le(data, lho + 28) as usize;
            let start = lho + 30 + l_name_len + l_extra_len;
            let end = (start + csize).min(data.len());
            let comp = data[start..end].to_vec();
            let m = match method {
                0 => ZipMethod::Stored,
                8 => ZipMethod::Deflate,
                _ => {
                    p += 46 + name_len + extra_len + comm_len;
                    continue;
                }
            };
            out.push((name, comp, m));
        }
        p += 46 + name_len + extra_len + comm_len;
    }
    let _ = cd_size;
    Ok(out)
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let start = data.len().saturating_sub(22 + 0xffff);
    let mut i = data.len() - 22;
    loop {
        if u32le(data, i) == 0x0605_4b50 {
            return Some(i);
        }
        if i == start {
            return None;
        }
        i -= 1;
    }
}

fn u16le(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn u32le(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

pub(crate) fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec = flate2::read::DeflateDecoder::new(data);
    dec.read_to_end(&mut out)?;
    Ok(out)
}
