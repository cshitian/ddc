//! ddc-dec — DEX → Java decompiler front-end over `jdc-core`.
//!
//! Pipeline per method: DEX code units → CFG → per-block register→IR
//! lifting → `jdc-core` structuring/conversion → refinement passes →
//! emission. Class-level rendering mirrors jcdc's `classdec` but reads
//! DEX metadata (no signatures, no generics).

pub mod cfg;
pub mod classdec;

pub use classdec::ClassOptions;
pub mod ctx;
pub mod lift;
pub mod method;
pub mod passes;
pub mod platform;

use jdc_core::FxHashMap as HashMap;

use ddc_dex::annotations::{self, EncodedValue};

/// A resolved static-field initializer.
#[derive(Debug, Clone)]
pub enum StaticValue {
    Int(i64),
    Float(f32),
    Double(f64),
    Str(String),
    Type(String),
    Boolean(bool),
    Null,
    /// (declaring class, field name) — enum constants.
    Field(String, String),
    Other,
}
use ddc_dex::{ClassDef, DexFile};
use jdc_core::types::{
    parse_field_descriptor, parse_method_descriptor, JavaType, MethodDescriptor,
};

// ---------------------------------------------------------------------------
// Access flags (Dalvik numbering, JVM-compatible subset).
// ---------------------------------------------------------------------------
pub mod access {
    pub const ACC_PUBLIC: u32 = 0x1;
    pub const ACC_PRIVATE: u32 = 0x2;
    pub const ACC_PROTECTED: u32 = 0x4;
    pub const ACC_STATIC: u32 = 0x8;
    pub const ACC_FINAL: u32 = 0x10;
    pub const ACC_SYNCHRONIZED: u32 = 0x20;
    pub const ACC_BRIDGE: u32 = 0x40;
    pub const ACC_VARARGS: u32 = 0x80;
    pub const ACC_NATIVE: u32 = 0x100;
    pub const ACC_INTERFACE: u32 = 0x200;
    pub const ACC_ABSTRACT: u32 = 0x400;
    pub const ACC_STRICT: u32 = 0x800;
    pub const ACC_SYNTHETIC: u32 = 0x1000;
    pub const ACC_ANNOTATION: u32 = 0x2000;
    pub const ACC_ENUM: u32 = 0x4000;
    pub const ACC_CONSTRUCTOR: u32 = 0x1_0000;
    pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x2_0000;
}

/// One field of a pooled class.
#[derive(Debug, Clone)]
pub struct PoolField {
    pub name: String,
    /// Field descriptor (`I`, `Ljava/lang/String;`, ...).
    pub desc: String,
    pub access: u32,
    pub is_static: bool,
}

/// One method of a pooled class.
#[derive(Debug, Clone)]
pub struct PoolMethod {
    /// Shared with the dex string table (the idx IS the dedup key).
    pub name: std::sync::Arc<str>,
    /// Method descriptor, shared per proto (a dex's proto table is the
    /// descriptor dedup layer — 1.9M methods on lark share ~1 proto
    /// table's worth of unique descriptors).
    pub desc: std::sync::Arc<str>,
    pub access: u32,
    pub code_off: u32,
    pub debug_info_off: u32,
    /// Which DEX image the body lives in.
    pub dex_idx: usize,
}

impl PoolMethod {
    pub fn parsed_desc(&self) -> Option<MethodDescriptor> {
        parse_method_descriptor(&self.desc)
    }
    pub fn is_static(&self) -> bool {
        self.access & access::ACC_STATIC != 0
    }
    pub fn is_abstract_or_native(&self) -> bool {
        self.access & (access::ACC_ABSTRACT | access::ACC_NATIVE) != 0
    }
}

/// One pool entry: either already built, or name-registered with its
/// (dex index, class_def index) locator for on-demand construction.
enum ClassEntry {
    Eager(PoolClass),
    Lazy {
        at: (usize, usize),
        pc: std::sync::OnceLock<PoolClass>,
    },
}

/// A class materialized from one `class_def_item` (with ids resolved to
/// names and the class data expanded).
#[derive(Debug, Clone)]
pub struct PoolClass {
    pub name: String,
    pub access: u32,
    /// `None` for `java/lang/Object` roots.
    pub super_name: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    pub static_fields: Vec<PoolField>,
    pub instance_fields: Vec<PoolField>,
    pub direct_methods: Vec<PoolMethod>,
    pub virtual_methods: Vec<PoolMethod>,
    /// Static initial values aligned with the head of `static_fields`.
    pub static_values: Vec<StaticValue>,
    /// Nesting evidence with annotation ids resolved to names.
    pub nesting: ResolvedNesting,
    /// Which DEX image the class body lives in (provenance header).
    pub dex_idx: usize,
}

/// Nesting evidence, names resolved at pooling time.
#[derive(Debug, Clone, Default)]
pub struct ResolvedNesting {
    pub enclosing_class: Option<String>,
    /// (class internal name, method name) of the enclosing method.
    pub enclosing_method: Option<(String, String)>,
    pub member_classes: Vec<String>,
}

impl PoolClass {
    pub fn is_interface(&self) -> bool {
        self.access & access::ACC_INTERFACE != 0
    }

    pub fn is_enum(&self) -> bool {
        self.access & access::ACC_ENUM != 0
    }

    pub fn is_synthetic(&self) -> bool {
        self.access & access::ACC_SYNTHETIC != 0
    }

    pub fn is_static_nested(&self) -> bool {
        self.access & access::ACC_STATIC != 0
    }

    /// All methods in declaration order.
    pub fn all_methods(&self) -> impl Iterator<Item = &PoolMethod> {
        self.direct_methods
            .iter()
            .chain(self.virtual_methods.iter())
    }

    /// Find a method by name + descriptor.
    pub fn find_method(&self, name: &str, desc: &str) -> Option<&PoolMethod> {
        self.all_methods()
            .find(|m| &*m.name == name && &*m.desc == desc)
    }

    /// Constructors `<init>` matching `arity` descriptor arguments.
    pub fn ctors_by_arity(&self, arity: usize) -> Vec<&PoolMethod> {
        self.all_methods()
            .filter(|m| &*m.name == "<init>")
            .filter(|m| {
                m.parsed_desc()
                    .map(|d| d.args.len() == arity)
                    .unwrap_or(false)
            })
            .collect()
    }

    pub fn field_flags_of(&self, name: &str) -> Option<u32> {
        self.static_fields
            .iter()
            .chain(self.instance_fields.iter())
            .find(|f| f.name == name)
            .map(|f| f.access)
    }
}

/// Multi-DEX class pool: classes from all images, first definition wins.
pub struct DexPool {
    /// Images as Arcs: `dex()` hands out snapshots whose borrows stay
    /// valid for the Arc's lifetime (decompile workers hold them), while
    /// `release_images` empties the image data through exclusive access
    /// when all of an image's classes are done (full-decompile driver
    /// only — progressive callers keep images whole).
    dexes: Vec<std::sync::Arc<DexFile>>,
    /// Human label per image ("weibo!classes.dex") for the provenance
    /// header; defaults to "dex N" until the CLI names the inputs.
    pub dex_labels: Vec<String>,
    /// Name → class entry. Eager pools materialize everything at add
    /// time (full decompile, tests); lazy pools register names only and
    /// materialize on first `get` (progressive `getclass` — one class's
    /// PoolClass costs annotation reads, 145k of them cost ~0.2s).
    classes: HashMap<String, ClassEntry>,
    /// Class names in insertion order (stable for output).
    pub order: Vec<String>,
    /// Per-image remaining class count once `arm_retirement` fires.
    retire_counts: std::sync::Mutex<Vec<u64>>,
    retire_armed: std::sync::atomic::AtomicBool,
    /// name → outer (computed once; `$` heuristic + dalvik annotations).
    outers: std::sync::OnceLock<HashMap<String, Option<String>>>,
    /// outer → direct children (computed once).
    children: std::sync::OnceLock<HashMap<String, Vec<String>>>,
    /// Per-image hot-reference interning (parallel to `dexes`).
    ref_caches: Vec<DexRefCache>,
}

/// Lazily-filled, thread-shared reference interning for one image.
///
/// The lifter used to rebuild class names, field/method names and WHOLE
/// method descriptors per INSTRUCTION (`method_ref` alone: N param
/// Strings → `format!` descriptor → re-parse — 6-10 allocations per
/// invoke). Every entry here is built at most once per (image, table
/// index); lifts and the endless IR clones downstream are refcount
/// bumps. Slots are `OnceLock` so worker threads fill them race-free
/// without a lock on the hot path.
pub(crate) struct DexRefCache {
    proto_descs: Box<[std::sync::OnceLock<std::sync::Arc<jdc_core::types::MethodDescriptor>>]>,
    type_names: Box<[std::sync::OnceLock<std::sync::Arc<str>>]>,
    type_javas: Box<[std::sync::OnceLock<std::sync::Arc<jdc_core::types::JavaType>>]>,
}

impl DexRefCache {
    fn new(protos: usize, types: usize) -> Self {
        DexRefCache {
            proto_descs: (0..protos).map(|_| std::sync::OnceLock::new()).collect(),
            type_names: (0..types).map(|_| std::sync::OnceLock::new()).collect(),
            type_javas: (0..types).map(|_| std::sync::OnceLock::new()).collect(),
        }
    }
}

impl DexPool {
    pub fn new() -> Self {
        DexPool {
            dexes: Vec::new(),
            retire_armed: std::sync::atomic::AtomicBool::new(false),
            dex_labels: Vec::new(),
            classes: HashMap::default(),
            order: Vec::new(),
            retire_counts: std::sync::Mutex::new(Vec::new()),
            outers: std::sync::OnceLock::new(),
            children: std::sync::OnceLock::new(),
            ref_caches: Vec::new(),
        }
    }

    /// Shared `MethodDescriptor` of a proto (one parse per image).
    pub fn proto_desc_parsed(
        &self,
        di: usize,
        proto_idx: u32,
    ) -> std::sync::Arc<jdc_core::types::MethodDescriptor> {
        let Some(dex) = self.dexes.get(di) else {
            return std::sync::Arc::new(jdc_core::types::MethodDescriptor {
                args: Vec::new(),
                ret: jdc_core::types::JavaType::Void,
            });
        };
        let build = || {
            std::sync::Arc::new(parse_proto_desc(dex, proto_idx))
        };
        match self
            .ref_caches
            .get(di)
            .and_then(|c| c.proto_descs.get(proto_idx as usize))
        {
            Some(slot) => slot.get_or_init(build).clone(),
            None => build(),
        }
    }

    /// Shared internal class name of a type id (one strip+alloc per image).
    pub fn type_name_arc(&self, di: usize, type_idx: u32) -> std::sync::Arc<str> {
        let Some(dex) = self.dexes.get(di) else {
            return std::sync::Arc::from("");
        };
        let build = || std::sync::Arc::from(dex.class_name(type_idx).as_str());
        match self
            .ref_caches
            .get(di)
            .and_then(|c| c.type_names.get(type_idx as usize))
        {
            Some(slot) => slot.get_or_init(build).clone(),
            None => build(),
        }
    }

    /// Shared parsed type of a type id.
    pub fn type_java(&self, di: usize, type_idx: u32) -> std::sync::Arc<jdc_core::types::JavaType> {
        let Some(dex) = self.dexes.get(di) else {
            return std::sync::Arc::new(jdc_core::types::JavaType::Object(
                std::sync::Arc::from("java/lang/Object"),
            ));
        };
        let build = || std::sync::Arc::new(desc_type(dex.type_name(type_idx)));
        match self
            .ref_caches
            .get(di)
            .and_then(|c| c.type_javas.get(type_idx as usize))
        {
            Some(slot) => slot.get_or_init(build).clone(),
            None => build(),
        }
    }

    /// name → outer map, computed lazily once.
    fn outer_map(&self) -> &HashMap<String, Option<String>> {
        self.outers.get_or_init(|| {
            self.order
                .iter()
                .map(|n| (n.clone(), find_outer_name(self, n)))
                .collect()
        })
    }

    /// The outer class of `name`, from the cached map (borrowed).
    pub fn outer_of(&self, name: &str) -> Option<&str> {
        self.outer_map().get(name).and_then(|o| o.as_deref())
    }

    /// Direct nested children of `internal` (any `$` depth 1), cached.
    /// (Perf: returns a borrowed slice — the owned-Vec clone ran once per
    /// class on 98k-class runs.)
    pub fn children_of(&self, internal: &str) -> &[String] {
        if self.children.get().is_none() {
            // Build FIRST, set ONCE: the previous shape set an empty map
            // to claim the OnceLock and then silently failed to store the
            // real index (`let _ = set(...)` on an initialized lock) —
            // children_of returned [] forever, so member nested classes
            // were neither inlined nor emitted as files (Guard$Report
            // vanished whole; every corpus run since the borrow refactor
            // dropped them, invisible to the syntax-only gate).
            let mut idx: HashMap<String, Vec<String>> = HashMap::default();
            for name in &self.order {
                if let Some(outer) = self.outer_of(name).map(str::to_string) {
                    idx.entry(outer).or_default().push(name.clone());
                }
            }
            // A racing thread may have set an identical map first — the
            // index is a pure function of `order`, so either copy is right.
            let _ = self.children.set(idx);
        }
        self.children
            .get()
            .and_then(|m| m.get(internal))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Adds one image; duplicate class names keep their first definition.
    /// Returns the image's index — call `set_dex_label` with it to give the
    /// provenance header a real origin instead of the default "dex N".
    pub fn add_dex(&mut self, dex: DexFile) -> usize {
        let dex_idx = self.dexes.len();
        // Pre-size the name map: 240k-entry growth rehashed repeatedly
        // (reserve_rehash showed up in corpus profiles).
        self.classes.reserve(dex.class_defs.len());
        // The annotation reader borrows the image; pool classes are built
        // before ownership moves into `self.dexes` (no full-image copy).
        for cd in &dex.class_defs {
            let name = dex.class_name(cd.class_idx);
            if self.classes.contains_key(&name) {
                continue;
            }
            let pc = pool_class_of(&dex, dex.raw(), cd, dex_idx);
            self.classes.insert(name.clone(), ClassEntry::Eager(pc));
            self.order.push(name);
        }
        self.ref_caches
            .push(DexRefCache::new(dex.proto_count(), dex.type_count()));
        self.dexes.push(std::sync::Arc::new(dex));
        self.retire_counts.lock().unwrap().push(0);
        self.dex_labels.push(format!("dex {}", dex_idx));
        dex_idx
    }

    /// Registers class NAMES only; the PoolClass (annotation reads
    /// included) is materialized on first `get`. Duplicate class names
    /// keep their first definition, matching `add_dex`.
    pub fn add_dex_lazy(&mut self, dex: DexFile) -> usize {
        let dex_idx = self.dexes.len();
        self.classes.reserve(dex.class_defs.len());
        for (ci, cd) in dex.class_defs.iter().enumerate() {
            let name = dex.class_name(cd.class_idx);
            if self.classes.contains_key(&name) {
                continue;
            }
            self.classes.insert(
                name.clone(),
                ClassEntry::Lazy {
                    at: (dex_idx, ci),
                    pc: std::sync::OnceLock::new(),
                },
            );
            self.order.push(name);
        }
        self.ref_caches
            .push(DexRefCache::new(dex.proto_count(), dex.type_count()));
        self.dexes.push(std::sync::Arc::new(dex));
        self.retire_counts.lock().unwrap().push(0);
        self.dex_labels.push(format!("dex {}", dex_idx));
        dex_idx
    }

    /// Label the image at `idx` (see `add_dex`).
    pub fn set_dex_label(&mut self, idx: usize, label: impl Into<String>) {
        if let Some(slot) = self.dex_labels.get_mut(idx) {
            *slot = label.into();
        }
    }

    pub fn len(&self) -> usize {
        self.classes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    pub fn get(&self, internal: &str) -> Option<&PoolClass> {
        self.get_inner(internal, None)
    }

    /// `get` with optional pre-taken raw-image snapshots (one per
    /// image). `materialize_all` hoists the `DexFile::raw()` lock out of
    /// the per-class loop — the parallel materialize used to take the
    /// same per-image lock once PER CLASS across all threads.
    fn get_inner(&self, internal: &str, raws: Option<&[&[u8]]>) -> Option<&PoolClass> {
        match self.classes.get(internal)? {
            ClassEntry::Eager(pc) => Some(pc),
            ClassEntry::Lazy { at, pc } => {
                if let Some(built) = pc.get() {
                    return Some(built);
                }
                let (di, ci) = *at;
                let dex = self.dexes.get(di)?;
                let cd = dex.class_defs.get(ci)?;
                let raw = match raws {
                    Some(r) => r.get(di).copied().unwrap_or(&[]),
                    None => dex.raw(),
                };
                let built = pool_class_of(dex, raw, cd, di);
                Some(pc.get_or_init(move || built))
            }
        }
    }

    /// Materialize every lazy entry (parallel across the given chunk
    /// count). After this the pool is observationally identical to an
    /// eagerly-built one — including the annotation-aware outer-map —
    /// while the annotation reads ran on worker threads instead of the
    /// serial pool build (~0.2s on weibo).
    pub fn materialize_all(&self, threads: usize) {
        let keys: Vec<String> = self
            .classes
            .iter()
            .filter(|(_, e)| matches!(e, ClassEntry::Lazy { .. }))
            .map(|(k, _)| k.clone())
            .collect();
        if keys.is_empty() {
            return;
        }
        // One raw() snapshot per image for the whole sweep (see
        // get_inner). Safe window: materialize_all completes before
        // retirement is armed, so no image releases while these slices
        // are alive.
        let raws: Vec<&[u8]> = self.dexes.iter().map(|d| d.raw()).collect();
        let threads = threads.max(1);
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(k) = keys.get(i) else { break };
                    let _ = self.get_inner(k, Some(&raws));
                });
            }
        });
    }

    /// `get` without materializing: None for not-yet-built lazy entries.
    fn get_if_materialized(&self, internal: &str) -> Option<&PoolClass> {
        match self.classes.get(internal)? {
            ClassEntry::Eager(pc) => Some(pc),
            ClassEntry::Lazy { pc, .. } => pc.get(),
        }
    }

    /// Name registered (no materialization).
    pub fn has_name(&self, internal: &str) -> bool {
        self.classes.contains_key(internal)
    }

    /// One image as an Arc snapshot (borrows of the snapshot live as
    /// long as the caller holds the Arc).
    pub fn dex(&self, idx: usize) -> Option<std::sync::Arc<DexFile>> {
        self.dexes.get(idx).cloned()
    }

    pub fn dex_count(&self) -> usize {
        self.dexes.len()
    }

    pub fn class_names(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(|s| s.as_str())
    }

    /// True when `sub` is assignable to `sup` (internal names), walking the
    /// pool's hierarchy. Unknown classes are never assignable (conservative).
    pub fn is_subtype(&self, sub: &str, sup: &str) -> bool {
        if sub == sup {
            return true;
        }
        // Arrays: covariance by element type when both are arrays.
        if let (Some(sub_elem), Some(sup_elem)) = (array_elem(sub), array_elem(sup)) {
            if sub_elem.starts_with('L')
                && sup_elem.starts_with('L')
                && sub_elem.ends_with(';')
                && sup_elem.ends_with(';')
            {
                return self.is_subtype(
                    &sub_elem[1..sub_elem.len() - 1],
                    &sup_elem[1..sup_elem.len() - 1],
                );
            }
            return sub_elem == sup_elem;
        }
        let mut cur = self.get(sub);
        let mut hops = 0;
        while let Some(c) = cur {
            hops += 1;
            if hops > 64 {
                return false;
            }
            for i in &c.interfaces {
                if i == sup || self.is_subtype(i, sup) {
                    return true;
                }
            }
            match &c.super_name {
                Some(s) if s == sup => return true,
                Some(s) if s != "java/lang/Object" => {
                    cur = self.get(s);
                }
                _ => return false,
            }
        }
        false
    }
}

impl Default for DexPool {
    fn default() -> Self {
        Self::new()
    }
}

fn array_elem(desc: &str) -> Option<&str> {
    desc.strip_prefix('[')
}

fn resolve_static_value(v: &EncodedValue, dex: &DexFile) -> StaticValue {
    match v {
        EncodedValue::Byte(x) => StaticValue::Int(*x as i64),
        EncodedValue::Short(x) => StaticValue::Int(*x as i64),
        EncodedValue::Char(x) => StaticValue::Int(*x as i64),
        EncodedValue::Int(x) => StaticValue::Int(*x as i64),
        EncodedValue::Long(x) => StaticValue::Int(*x),
        EncodedValue::Float(x) => StaticValue::Float(*x),
        EncodedValue::Double(x) => StaticValue::Double(*x),
        EncodedValue::String(i) => StaticValue::Str(dex.string(*i).to_string()),
        EncodedValue::Type(i) => StaticValue::Type(dex.class_name(*i)),
        EncodedValue::Boolean(b) => StaticValue::Boolean(*b),
        EncodedValue::Null => StaticValue::Null,
        EncodedValue::Enum(i) | EncodedValue::Field(i) => {
            let f = dex.field(*i);
            StaticValue::Field(
                dex.class_name(f.class_idx),
                dex.string(f.name_idx).to_string(),
            )
        }
        _ => StaticValue::Other,
    }
}

fn pool_class_of(dex: &DexFile, raw: &[u8], cd: &ClassDef, dex_idx: usize) -> PoolClass {
    let name = dex.class_name(cd.class_idx);
    let super_name = if cd.superclass_idx == ddc_dex::NO_INDEX {
        None
    } else {
        let s = dex.class_name(cd.superclass_idx);
        if s.is_empty() || s == "java/lang/Object" {
            None
        } else {
            Some(s)
        }
    };
    let interfaces = dex
        .interfaces_of(cd)
        .into_iter()
        .map(|t| dex.class_name(t))
        .collect();
    let source_file = if cd.source_file_idx == ddc_dex::NO_INDEX {
        None
    } else {
        Some(dex.string(cd.source_file_idx).to_string())
    };

    let data = dex.class_data(cd);
    let mk_field = |ef: &ddc_dex::EncodedField, is_static: bool| {
        let f = dex.field(ef.field_idx);
        PoolField {
            name: dex.string(f.name_idx).to_string(),
            desc: dex.type_name(f.type_idx).to_string(),
            access: ef.access_flags,
            is_static,
        }
    };
    let static_fields: Vec<PoolField> = data
        .static_fields
        .iter()
        .map(|f| mk_field(f, true))
        .collect();
    let instance_fields: Vec<PoolField> = data
        .instance_fields
        .iter()
        .map(|f| mk_field(f, false))
        .collect();
    let mk_method = |em: &ddc_dex::EncodedMethod| {
        let m = dex.method(em.method_idx);
        let (code_off, debug_info_off) = match dex.debug_info_off_at(em.code_off) {
            Some(d) => (em.code_off, d),
            None => (0, 0),
        };
        PoolMethod {
            name: dex.string_arc(m.name_idx),
            desc: dex.proto_desc(m.proto_idx),
            access: em.access_flags,
            code_off,
            debug_info_off,
            dex_idx,
        }
    };
    let direct_methods: Vec<PoolMethod> = data.direct_methods.iter().map(&mk_method).collect();
    let virtual_methods: Vec<PoolMethod> = data.virtual_methods.iter().map(&mk_method).collect();

    let static_values: Vec<StaticValue> = dex
        .static_values(cd.static_values_off)
        .into_iter()
        .map(|v| resolve_static_value(&v, dex))
        .collect();
    let anns = if cd.annotations_off != 0 {
        annotations::read_class_annotations(raw, cd.annotations_off)
    } else {
        Vec::new()
    };
    let raw = annotations::nesting_from(&anns, &|t: u32| dex.type_name(t).to_string());
    let nesting = ResolvedNesting {
        enclosing_class: raw.enclosing_class.map(|t| dex.class_name(t)),
        enclosing_method: raw.enclosing_method.map(|m| {
            let mid = dex.method(m);
            (
                dex.class_name(mid.class_idx),
                dex.string(mid.name_idx).to_string(),
            )
        }),
        member_classes: raw
            .member_classes
            .into_iter()
            .map(|t| dex.class_name(t))
            .collect(),
    };

    PoolClass {
        name,
        access: cd.access_flags,
        super_name,
        interfaces,
        source_file,
        static_fields,
        instance_fields,
        direct_methods,
        virtual_methods,
        static_values,
        nesting,
        dex_idx,
    }
}

/// JavaType for a field/method descriptor segment.
/// Parse a proto's descriptor into a MethodDescriptor straight from the
/// tables (no string round-trip).
fn parse_proto_desc(
    dex: &ddc_dex::DexFile,
    proto_idx: u32,
) -> jdc_core::types::MethodDescriptor {
    let proto = dex.proto(proto_idx);
    let args = dex
        .proto_params(proto_idx)
        .iter()
        .map(|&t| desc_type(dex.type_name(t)))
        .collect();
    jdc_core::types::MethodDescriptor {
        args,
        ret: desc_type(dex.type_name(proto.return_type_idx)),
    }
}

pub fn desc_type(desc: &str) -> JavaType {
    parse_field_descriptor(desc).unwrap_or(JavaType::Object("java/lang/Object".into()))
}

/// Nesting evidence for `internal`: dalvik annotations first, then the
/// `$`-name heuristic against the pool.
pub fn find_outer_name(pool: &DexPool, internal: &str) -> Option<String> {
    // Annotation refinement only for ALREADY-MATERIALIZED classes: eager
    // pools (full decompile) behave exactly as before; lazy pools
    // (progressive getclass) fall straight to the `$` chain without
    // materializing the world.
    if let Some(pc) = pool.get_if_materialized(internal) {
        if let Some(enc) = &pc.nesting.enclosing_class {
            return Some(enc.clone());
        }
    }
    let mut rest = internal;
    while let Some(d) = rest.rfind('$') {
        let cand = &rest[..d];
        if pool.has_name(cand) {
            return Some(cand.to_string());
        }
        rest = cand;
    }
    None
}

/// True when the `$` tail names a plain member class (not anonymous/local/
/// lambda), i.e. the class renders inside its outer's compilation unit.
fn clean_member_tail(rest: &str) -> bool {
    if rest.starts_with('-') {
        return false;
    }
    let tail = rest.rsplit('$').next().unwrap_or(rest);
    if tail.is_empty() || tail.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    true
}

/// Classes to emit as their own compilation units: top-level classes plus
/// anonymous/local/lambda-shaped ones (clean members render inline).
impl DexPool {
    /// Arm image retirement (full-decompile driver only): count one
    /// pending class per image by pool ownership.
    pub fn arm_retirement(&self) {
        self.retire_armed
            .store(true, std::sync::atomic::Ordering::Release);
        let mut counts = self.retire_counts.lock().unwrap();
        for c in counts.iter_mut() {
            *c = 0;
        }
        for entry in self.classes.values() {
            let di = match entry {
                ClassEntry::Eager(pc) => pc.dex_idx,
                ClassEntry::Lazy { at, .. } => at.0,
            };
            if let Some(c) = counts.get_mut(di) {
                *c += 1;
            }
        }
    }

    /// Report one class finished; Some(image) when it was the image's
    /// last class (driver batches these into release_images).
    pub fn report_class_done(&self, class_name: &str) -> Option<usize> {
        if !self.retire_armed.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        let entry = self.classes.get(class_name)?;
        let di = match entry {
            ClassEntry::Eager(pc) => pc.dex_idx,
            ClassEntry::Lazy { at, .. } => at.0,
        };
        let mut counts = self.retire_counts.lock().unwrap();
        match counts.get_mut(di) {
            Some(c) => {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    Some(di)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Release the images' inflated bytes. Safe: the driver calls this
    /// only when every class of each image is emitted or failed; new
    /// `dex()` snapshots still work (tables valid, code accessors empty).
    pub fn release_images(&self, indexes: &[usize]) {
        let mut counts = self.retire_counts.lock().unwrap();
        for &i in indexes {
            if let Some(dex) = self.dexes.get(i) {
                // Mark the shared image: code accessors go empty
                // immediately; the bytes drop when the last snapshot
                // drops (workers hold snapshots only mid-class).
                dex.mark_released();
            }
            if let Some(c) = counts.get_mut(i) {
                *c = u64::MAX; // released marker
            }
        }
    }
}

pub fn top_level_classes(pool: &DexPool) -> Vec<String> {
    pool.class_names()
        .filter(|name| match pool.outer_of(name) {
            None => true,
            Some(outer) => {
                if pool.get(outer).is_none() {
                    return true;
                }
                // The outer can come from an ANNOTATION (EnclosingClass)
                // with no naming relationship to this class — obfuscated
                // apps pair a 1-char name with a long enclosing descriptor
                // (weixin), which made the old blind slice panic. Only a
                // real `outer$tail` prefix yields a member tail; anything
                // else is a standalone unit.
                let rest = name
                    .strip_prefix(outer)
                    .and_then(|t| t.strip_prefix('$'))
                    .unwrap_or("");
                !clean_member_tail(rest)
            }
        })
        .map(|n| n.to_string())
        .collect()
}

/// Deterministic case-collision renames over the FILE-emission set:
/// classes whose internal names differ only in letter case cannot share
/// one case-insensitive directory; the first (sorted) member of each
/// group keeps its name, the others gain `_2`, `_3`, … on the simple
/// segment. The map carries identity entries for unrenamed file-level
/// classes (they anchor nested prefix walks in apply_class_rename).
pub fn case_rename_map(pool: &DexPool) -> HashMap<String, String> {
    use std::collections::HashMap;
    let mut groups: HashMap<String, Vec<String>> = HashMap::default();
    for t in top_level_classes(pool) {
        groups.entry(t.to_lowercase()).or_default().push(t);
    }
    let folds: std::collections::HashSet<String> = groups.keys().cloned().collect();
    let mut map = HashMap::default();
    for (_, mut members) in groups {
        members.sort();
        for (i, m) in members.iter().enumerate() {
            if i == 0 {
                map.insert(m.clone(), m.clone());
                continue;
            }
            // Suffix the simple segment; keep incrementing if the fold
            // of the suffixed name is already taken by a real class.
            let cut = m.rfind('/').map(|x| x + 1).unwrap_or(0);
            let mut n = i + 1;
            loop {
                let cand = format!("{}{}_{}", &m[..cut], &m[cut..], n);
                let fold = cand.to_lowercase();
                if !folds.contains(&fold) {
                    map.insert(m.clone(), cand);
                    break;
                }
                n += 1;
            }
        }
    }
    map
}

/// Display-level renames for two nested-class shapes that render
/// uncompilable or inconsistent output:
///
/// 1. A member class whose simple tail equals its rendered parent's
///    tail (`x0$a$a` inside `x0$a`): javac rejects a member class with
///    the same simple name as its immediately enclosing class ("已在类
///    x0中定义了类 x0.a") — a shape Kotlin lambda families hit by the
///    thousand (lark alone: 22k). Bump the tail: `a` → `a2`, `a3`, …
/// 2. An orphaned intermediate (`x0$a$b` with `x0$a` absent from the
///    pool): the member DECLARES as `b` inside `x0` but references
///    printed `x0.a$b` — a type that exists nowhere. Flatten the
///    display name to `x0$b` so every site agrees.
///
/// Both are pure display renames keyed by internal name; declarations,
/// ctor names, file names and every type reference funnel through
/// apply_class_rename, so one map keeps all sites consistent. Children
/// Display-level renames for nested member classes that render
/// uncompilable or inconsistent output:
///
/// 1. A member whose simple tail equals ANY enclosing class's simple
///    name in its nesting chain. javac rejects more than the immediate
///    parent (`class a { static class a2 { static class a {} } }` —
///    member `a` two levels under `a` — is "已在类 X中定义了类 X.a");
///    Kotlin lambda families (`x0$a$a` inside `x0$a`) hit it by the
///    thousand (lark alone: 22k). Bump the tail until it clears every
///    ancestor name: `a` → `a3`.
/// 2. An orphaned intermediate (`x0$a$b` with `x0$a` absent): the
///    member DECLARES as `b` inside `x0` but references printed
///    `x0.a$b` — a type that exists nowhere. Flatten the display to
///    `x0$b` so every site agrees.
///
/// Candidates build on the parent's DISPLAY name (ancestors are
/// renamed first — ascending `$`-depth order), so declarations,
/// constructor names, file names and every type reference stay
/// consistent through apply_class_rename. All are pure display
/// renames keyed by internal name.
fn nested_collision_renames(pool: &DexPool, map: &mut HashMap<String, String>) {
    // Ancestors before descendants: a parent's rename must be in the
    // map when its children compute their display chain.
    let mut names: Vec<&String> = pool.order.iter().collect();
    names.sort_by_key(|n| n.matches('$').count());
    let mut assigned: jdc_core::FxHashSet<String> = jdc_core::FxHashSet::default();
    for name in names {
        if !name.contains('$') || map.contains_key(name) {
            continue;
        }
        let Some(parent) = find_outer_name(pool, name) else {
            continue;
        };
        // Only a REAL `parent$rest` name renders as an inline member;
        // anonymous/local/lambda tails keep their flat own-file names.
        let Some(rest) = name
            .strip_prefix(parent.as_str())
            .and_then(|t| t.strip_prefix('$'))
        else {
            continue;
        };
        if !clean_member_tail(rest) {
            continue;
        }
        // Display simple names of every enclosing level, bottom-up.
        let mut chain: Vec<String> = Vec::new();
        let mut cur = parent.clone();
        loop {
            let disp = map.get(&cur).cloned().unwrap_or_else(|| cur.clone());
            let simple = disp.rsplit('/').next().unwrap_or(&disp);
            chain.push(simple.rsplit('$').next().unwrap_or(simple).to_string());
            match find_outer_name(pool, &cur) {
                Some(o) if o != cur => cur = o,
                _ => break,
            }
        }
        let disp_parent = map
            .get(&parent)
            .cloned()
            .unwrap_or_else(|| parent.clone());
        let tail = rest.rsplit('$').next().unwrap_or(rest);
        let orphan = rest.contains('$');
        let clash = chain.iter().any(|c| c == tail);
        if !orphan && !clash {
            continue;
        }
        let mut k = 0u32;
        loop {
            k += 1;
            let cand_tail = if k == 1 {
                tail.to_string()
            } else {
                format!("{tail}{k}")
            };
            // The candidate must clear every ancestor display name,
            // not just the immediate parent (javac checks the whole
            // chain — see the shape list above).
            if chain.contains(&cand_tail) {
                continue;
            }
            let cand = format!("{disp_parent}${cand_tail}");
            if pool.has_name(&cand) || assigned.contains(&cand) {
                continue;
            }
            assigned.insert(cand.clone());
            map.insert(name.clone(), cand);
            break;
        }
    }
}

/// Compute and install the registry (call before worker threads spawn).
pub fn install_case_renames(pool: &DexPool) {
    let mut map = case_rename_map(pool);
    nested_collision_renames(pool, &mut map);
    jdc_core::rename::set_class_renames(map);
}

pub use jdc_core::rename::apply_class_rename;
