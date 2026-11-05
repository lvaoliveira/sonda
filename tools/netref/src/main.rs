//! Summarizes the public declarations of .NET reference assemblies for
//! sonda's C# type inference (ADR-0022).
//!
//! Usage: `sonda-netref OUT LABEL DIR [LABEL DIR]...`, where each DIR holds
//! a reference pack's `ref/<tfm>/*.dll` and LABEL names it ("Microsoft.NETCore.App.Ref 8.0.11").
//! OUT is written as deflated JSON, the format `sonda-core` embeds. A LABEL
//! starting with `baseline:` adds no types: members of the other packs it
//! also declares, with the same signature, are tagged "ns20" (.NET
//! Standard 2.0, which every target has).
//!
//! Type names are keys like the project index's (`semantic/cs_index.rs`):
//! namespace, enclosing types without their arity, then the type with its
//! own (`System.Collections.Generic.List`1`, `System.Environment.SpecialFolder`).
//! Type references in signatures add arguments in angle brackets, `[]` for
//! arrays, and `!0` / `!!0` for type and method parameters.

use cildec::tables::{
    CustomAttributeRow, EventRow, FieldRow, InterfaceImplRow, MemberRefRow, MethodDefRow,
    MethodSemanticsRow, ParamRow, PropertyRow, TypeDefRow, TypeRefRow, TypeSpecRow,
};
use cildec::{
    FieldSig, Metadata, MethodSig, PeImage, PropertySig, Rid, TableId, Token, Type, TypeSpecSig,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::error::Error;
use std::io::Write;
use std::path::Path;

type Res<T> = Result<T, Box<dyn Error>>;

#[derive(Serialize)]
struct Summary {
    /// The reference packs this was extracted from.
    packs: Vec<String>,
    types: Vec<TypeEntry>,
}

#[derive(Serialize)]
struct TypeEntry {
    /// The key: `System.IO.FileStream`.
    n: String,
    /// "class", "struct", "interface", "enum" or "delegate".
    k: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    b: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    i: Vec<String>,
    /// "abstract", "sealed", "static", "Flags", "Obsolete".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    a: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    m: Vec<Member>,
}

#[derive(Serialize)]
struct Member {
    /// "method", "constructor", "operator", "property", "field", "event".
    k: &'static str,
    n: String,
    /// The return, property, field or event type.
    #[serde(skip_serializing_if = "String::is_empty")]
    t: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    p: Vec<ParamEntry>,
    /// A method's own type parameters.
    #[serde(skip_serializing_if = "is_zero")]
    g: u32,
    /// "static", "protected", "virtual", "abstract", "get", "set", "init",
    /// "Pure", "Obsolete", "Extension", "Localizable".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    a: Vec<&'static str>,
    /// A constant field's value, as `constant` writes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    v: Option<String>,
}

#[derive(Serialize)]
struct ParamEntry {
    t: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    n: String,
    /// "ref", "out", "in", "params", "optional", "Localizable", "caller"
    /// (a caller-information attribute), and `StringSyntax` values such as
    /// "syntax:Regex".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    a: Vec<String>,
    /// An optional parameter's default value, as `constant` writes it. Left
    /// out when .NET Standard 2.0 declares the member without it, as it does
    /// the constructors of `StreamReader`: leaving the argument out would
    /// not compile on older targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 || args.len().is_multiple_of(2) {
        return Err("usage: sonda-netref OUT LABEL DIR [LABEL DIR]...".into());
    }
    let (packs, mut types, baseline) = read_packs(&args[1..])?;
    tag_baseline(&mut types, &baseline);
    let summary = Summary {
        packs,
        types: types.into_values().collect(),
    };
    write_summary(&args[0], &summary)
}

/// Types by name.
type Types = BTreeMap<String, TypeEntry>;

/// The packs' labels, their types, and the baseline's (a label starting
/// with `baseline:`).
fn read_packs(pairs: &[String]) -> Res<(Vec<String>, Types, Types)> {
    let mut types = Types::new();
    let mut baseline = Types::new();
    let mut packs = Vec::new();
    for pair in pairs.chunks(2) {
        packs.push(pair[0].clone());
        let into = if pair[0].starts_with("baseline:") {
            &mut baseline
        } else {
            &mut types
        };
        let mut dlls: Vec<_> = std::fs::read_dir(&pair[1])?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "dll"))
            .collect();
        dlls.sort();
        for dll in dlls {
            extract(&dll, into).map_err(|e| format!("{}: {e}", dll.display()))?;
        }
    }
    Ok((packs, types, baseline))
}

/// A member's identity across packs: its type, kind, name, arity and
/// parameter types.
fn signature(t: &TypeEntry, m: &Member) -> String {
    let params: Vec<&str> = m.p.iter().map(|p| p.t.as_str()).collect();
    format!("{}|{}|{}|{}|{}", t.n, m.k, m.n, m.g, params.join(","))
}

/// Tags "ns20" the members the baseline also declares, and keeps only the
/// parameter defaults it agrees on.
fn tag_baseline(types: &mut Types, baseline: &Types) {
    let common: std::collections::HashSet<String> = baseline
        .values()
        .flat_map(|t| t.m.iter().map(move |m| signature(t, m)))
        .collect();
    let baseline_defaults: std::collections::HashMap<String, Vec<Option<String>>> = baseline
        .values()
        .flat_map(|t| {
            t.m.iter()
                .map(move |m| (signature(t, m), m.p.iter().map(|p| p.d.clone()).collect()))
        })
        .collect();
    for t in types.values_mut() {
        let signatures: Vec<String> = t.m.iter().map(|m| signature(t, m)).collect();
        for (m, sig) in t.m.iter_mut().zip(signatures) {
            if common.contains(&sig) {
                m.a.push("ns20");
            }
            if let Some(older) = baseline_defaults.get(&sig) {
                drop_changed_defaults(m, older);
            }
        }
    }
}

/// Drops the default values that differ from the baseline's for the same member.
fn drop_changed_defaults(m: &mut Member, older: &[Option<String>]) {
    for (p, d) in m.p.iter_mut().zip(older) {
        if *d != p.d {
            p.d = None;
        }
    }
}

/// Writes the summary as deflated JSON.
fn write_summary(out_path: &str, summary: &Summary) -> Res<()> {
    let json = serde_json::to_vec(summary)?;
    let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(&json)?;
    let out = z.finish()?;
    std::fs::write(out_path, &out)?;
    eprintln!(
        "{} types, {} members: {} bytes of JSON, {} deflated",
        summary.types.len(),
        summary.types.iter().map(|t| t.m.len()).sum::<usize>(),
        json.len(),
        out.len()
    );
    Ok(())
}

struct Reader<'m, 'a> {
    md: &'m Metadata<'a>,
}

impl Reader<'_, '_> {
    fn str(&self, i: cildec::StringIndex) -> String {
        self.md.strings().str_opt(i).unwrap_or_default().to_string()
    }

    /// A TypeDef's key, through its enclosing types.
    fn type_def_name(&self, rid: u32) -> Res<String> {
        let t = self.md.tables();
        let row: TypeDefRow = t.type_def(rid)?;
        let mut name = self.str(row.type_name);
        let mut current = Rid::new(rid);
        let mut namespace = self.str(row.type_namespace);
        for _ in 0..16 {
            let Some(outer) = t.enclosing_type(current)? else {
                break;
            };
            let outer_row: TypeDefRow = t.type_def(outer.get())?;
            name = format!("{}.{name}", strip_arity(&self.str(outer_row.type_name)));
            namespace = self.str(outer_row.type_namespace);
            current = outer;
        }
        Ok(qualify(&namespace, &name))
    }

    fn type_ref_name(&self, rid: u32) -> Res<String> {
        let row: TypeRefRow = self.md.tables().type_ref(rid)?;
        let name = self.str(row.type_name);
        let scope = row.resolution_scope;
        if scope.table() == Some(TableId::TypeRef) && !scope.is_null() {
            let outer = self.type_ref_name(scope.rid())?;
            // The outer type's arity goes, as in a TypeDef's key.
            let (ns_and_outer, last) = outer.rsplit_once('.').unwrap_or(("", &outer));
            let outer = qualify(ns_and_outer, strip_arity(last));
            return Ok(format!("{outer}.{name}"));
        }
        Ok(qualify(&self.str(row.type_namespace), &name))
    }

    /// The name a TypeDefOrRef(OrSpec) token stands for.
    fn token_name(&self, token: Token) -> Res<String> {
        Ok(match token.table() {
            Some(TableId::TypeDef) => self.type_def_name(token.rid())?,
            Some(TableId::TypeRef) => self.type_ref_name(token.rid())?,
            Some(TableId::TypeSpec) => {
                let row: TypeSpecRow = self.md.tables().type_spec(token.rid())?;
                let sig = TypeSpecSig::parse(self.md.blobs().get(row.signature)?)?;
                self.type_name(&sig.type_)?
            }
            _ => String::new(),
        })
    }

    fn type_name(&self, t: &Type) -> Res<String> {
        let primitive = |n: &str| Ok(format!("System.{n}"));
        match t {
            Type::Void => primitive("Void"),
            Type::Boolean => primitive("Boolean"),
            Type::Char => primitive("Char"),
            Type::I1 => primitive("SByte"),
            Type::U1 => primitive("Byte"),
            Type::I2 => primitive("Int16"),
            Type::U2 => primitive("UInt16"),
            Type::I4 => primitive("Int32"),
            Type::U4 => primitive("UInt32"),
            Type::I8 => primitive("Int64"),
            Type::U8 => primitive("UInt64"),
            Type::R4 => primitive("Single"),
            Type::R8 => primitive("Double"),
            Type::String => primitive("String"),
            Type::Object => primitive("Object"),
            Type::TypedByRef => primitive("TypedReference"),
            Type::IntPtr => primitive("IntPtr"),
            Type::UIntPtr => primitive("UIntPtr"),
            Type::Ptr(_, inner) => Ok(format!("{}*", self.type_name(inner)?)),
            Type::ByRef(inner) | Type::Modified(_, inner) | Type::Pinned(inner) => {
                self.type_name(inner)
            }
            Type::ValueType(token) | Type::Class(token) => self.token_name(*token),
            Type::Var(n) => Ok(format!("!{n}")),
            Type::MVar(n) => Ok(format!("!!{n}")),
            Type::SzArray(_, inner) => Ok(format!("{}[]", self.type_name(inner)?)),
            Type::Array(inner, shape) => Ok(format!(
                "{}[{}]",
                self.type_name(inner)?,
                ",".repeat((shape.rank as usize).saturating_sub(1))
            )),
            Type::GenericInst { def, args, .. } => {
                let args: Vec<String> =
                    args.iter().map(|a| self.type_name(a)).collect::<Res<_>>()?;
                Ok(format!("{}<{}>", self.token_name(*def)?, args.join(",")))
            }
            _ => Ok(String::new()),
        }
    }

    /// The type of an attribute: its constructor's declaring type.
    fn attribute_type(&self, row: &CustomAttributeRow) -> Res<String> {
        let ctor = row.constructor;
        match ctor.table() {
            Some(TableId::MethodDef) => {
                match self.md.tables().type_of_method(Rid::new(ctor.rid()))? {
                    Some(t) => self.type_def_name(t.get()),
                    None => Ok(String::new()),
                }
            }
            Some(TableId::MemberRef) => {
                let m: MemberRefRow = self.md.tables().member_ref(ctor.rid())?;
                self.token_name(m.class)
            }
            _ => Ok(String::new()),
        }
    }

    /// The attributes on a metadata item that rules read, with the first
    /// argument of those that take one.
    fn attributes(&self, parent: Token) -> Res<Vec<(String, Vec<u8>)>> {
        let t = self.md.tables();
        let mut out = Vec::new();
        for rid in t.custom_attributes(parent)? {
            let row: CustomAttributeRow = t.custom_attribute(rid)?;
            let name = self.attribute_type(&row)?;
            if ATTRIBUTES.iter().any(|(full, _)| *full == name) {
                out.push((name, self.md.blobs().get(row.value)?.to_vec()));
            }
        }
        Ok(out)
    }

    fn tags(&self, parent: Token) -> Res<Vec<&'static str>> {
        Ok(self
            .attributes(parent)?
            .into_iter()
            .filter_map(|(name, blob)| {
                let (_, tag) = ATTRIBUTES.iter().find(|(full, _)| *full == name)?;
                // `[Localizable(false)]` says the opposite.
                (*tag != "Localizable" || blob.get(2) == Some(&1)).then_some(*tag)
            })
            .collect())
    }
}

/// Attributes rules read, and the tag each becomes.
const ATTRIBUTES: &[(&str, &str)] = &[
    ("System.FlagsAttribute", "Flags"),
    ("System.ObsoleteAttribute", "Obsolete"),
    ("System.Diagnostics.Contracts.PureAttribute", "Pure"),
    (
        "System.Runtime.CompilerServices.ExtensionAttribute",
        "Extension",
    ),
    ("System.ParamArrayAttribute", "params"),
    ("System.ComponentModel.LocalizableAttribute", "Localizable"),
    (
        "System.Diagnostics.CodeAnalysis.StringSyntaxAttribute",
        "syntax",
    ),
    (
        "System.Runtime.CompilerServices.CallerMemberNameAttribute",
        "caller",
    ),
    (
        "System.Runtime.CompilerServices.CallerFilePathAttribute",
        "caller",
    ),
    (
        "System.Runtime.CompilerServices.CallerLineNumberAttribute",
        "caller",
    ),
    (
        "System.Runtime.CompilerServices.CallerArgumentExpressionAttribute",
        "caller",
    ),
];

fn strip_arity(name: &str) -> &str {
    name.split('`').next().unwrap_or(name)
}

fn qualify(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

/// Visible from another assembly: public, or protected in a public type.
fn type_visible(flags: u32) -> bool {
    matches!(flags & 7, 1 | 2 | 4 | 7)
}

/// A member's access: (visible from another assembly, only to derived types).
fn member_access(flags: u16) -> (bool, bool) {
    match flags & 7 {
        6 => (true, false),
        4 | 5 => (true, true),
        _ => (false, false),
    }
}

fn extract(path: &Path, types: &mut BTreeMap<String, TypeEntry>) -> Res<()> {
    let bytes = std::fs::read(path)?;
    let image = PeImage::parse(&bytes)?;
    let md = image.metadata()?;
    let r = Reader { md: &md };
    let t = md.tables();
    for (rid, row) in t.iter::<TypeDefRow>() {
        let row = row?;
        if !type_visible(row.flags) || !outer_visible(&r, rid)? {
            continue;
        }
        let name = r.type_def_name(rid)?;
        if name == "<Module>" || types.contains_key(&name) {
            continue;
        }
        let base = if row.extends.is_null() {
            None
        } else {
            Some(r.token_name(row.extends)?)
        };
        let kind = type_kind(&row, base.as_deref(), &name);
        let mut a = type_modifiers(&row, kind);
        a.extend(r.tags(Token::new(TableId::TypeDef, rid))?);
        let interfaces = interfaces_of(&r, rid)?;
        let members = members(&r, rid)?;
        types.insert(
            name.clone(),
            TypeEntry {
                n: name,
                k: kind,
                b: base,
                i: interfaces,
                a,
                m: members,
            },
        );
    }
    Ok(())
}

/// "interface", "enum", "struct", "delegate" or "class".
fn type_kind(row: &TypeDefRow, base: Option<&str>, name: &str) -> &'static str {
    if row.is_interface() {
        return "interface";
    }
    match base {
        Some("System.Enum") => "enum",
        Some("System.ValueType") if name != "System.Enum" => "struct",
        Some("System.MulticastDelegate") => "delegate",
        _ => "class",
    }
}

/// "static" (abstract and sealed), "abstract", or "sealed" for a class.
fn type_modifiers(row: &TypeDefRow, kind: &str) -> Vec<&'static str> {
    let mut a = Vec::new();
    if row.is_interface() {
        return a;
    }
    let (abstract_, sealed) = (row.flags & 0x80 != 0, row.flags & 0x100 != 0);
    match (abstract_, sealed) {
        (true, true) => a.push("static"),
        (true, false) => a.push("abstract"),
        (false, true) if kind == "class" => a.push("sealed"),
        _ => {}
    }
    a
}

/// The interfaces a type implements, by name.
fn interfaces_of(r: &Reader, rid: u32) -> Res<Vec<String>> {
    let t = r.md.tables();
    let mut interfaces = Vec::new();
    for i in t.interface_impls(Rid::new(rid))? {
        let ii: InterfaceImplRow = t.interface_impl(i)?;
        interfaces.push(r.token_name(ii.interface)?);
    }
    Ok(interfaces)
}

fn outer_visible(r: &Reader, rid: u32) -> Res<bool> {
    let t = r.md.tables();
    let mut current = Rid::new(rid);
    for _ in 0..16 {
        let Some(outer) = t.enclosing_type(current)? else {
            return Ok(true);
        };
        let row: TypeDefRow = t.type_def(outer.get())?;
        if !type_visible(row.flags) {
            return Ok(false);
        }
        current = outer;
    }
    Ok(true)
}

fn members(r: &Reader, type_rid: u32) -> Res<Vec<Member>> {
    let mut out = Vec::new();
    method_members(r, type_rid, &mut out)?;
    property_members(r, type_rid, &mut out)?;
    field_members(r, type_rid, &mut out)?;
    event_members(r, type_rid, &mut out)?;
    Ok(out)
}

/// The visible methods, constructors and operators.
fn method_members(r: &Reader, type_rid: u32, out: &mut Vec<Member>) -> Res<()> {
    let t = r.md.tables();
    for rid in t.method_range(Rid::new(type_rid))? {
        let m: MethodDefRow = t.method_def(rid)?;
        let (visible, protected) = member_access(m.flags);
        let name = r.str(m.name);
        let special = m.flags & 0x800 != 0;
        let kind = match name.as_str() {
            ".ctor" => "constructor",
            n if special && n.starts_with("op_") => "operator",
            _ if special => continue,
            _ => "method",
        };
        if !visible {
            continue;
        }
        let sig = MethodSig::parse(r.md.blobs().get(m.signature)?)?;
        let mut a = method_flags(m.flags, protected);
        a.extend(r.tags(Token::new(TableId::MethodDef, rid))?);
        out.push(Member {
            k: kind,
            v: None,
            n: if kind == "constructor" {
                String::new()
            } else {
                name
            },
            t: if kind == "constructor" {
                String::new()
            } else {
                r.type_name(&sig.return_type.type_)?
            },
            p: params(r, rid, &sig)?,
            g: sig.calling_convention.generic_param_count(),
            a,
        });
    }
    Ok(())
}

/// The properties with a visible accessor.
fn property_members(r: &Reader, type_rid: u32, out: &mut Vec<Member>) -> Res<()> {
    let t = r.md.tables();
    if let Some(map) = t.property_map_of(Rid::new(type_rid))? {
        for rid in t.property_range(map)? {
            let p: PropertyRow = t.property(rid)?;
            let sig = PropertySig::parse(r.md.blobs().get(p.type_signature)?)?;
            let token = Token::new(TableId::Property, rid);
            let Some((a, flags)) = property_accessors(r, token)? else {
                continue;
            };
            let (_, protected) = member_access(flags);
            let mut all = method_flags(flags, protected);
            all.extend(a);
            all.extend(r.tags(token)?);
            out.push(Member {
                k: "property",
                n: r.str(p.name),
                t: r.type_name(&sig.return_type.type_)?,
                p: sig
                    .params
                    .iter()
                    .map(|x| {
                        Ok(ParamEntry {
                            t: r.type_name(&x.type_)?,
                            n: String::new(),
                            a: Vec::new(),
                            d: None,
                        })
                    })
                    .collect::<Res<_>>()?,
                g: 0,
                a: all,
                v: None,
            });
        }
    }
    Ok(())
}

/// A property's visible accessors ("get", "set", "init") and the last
/// one's flags; None when none is visible.
fn property_accessors(r: &Reader, token: Token) -> Res<Option<(Vec<&'static str>, u16)>> {
    let t = r.md.tables();
    let mut a: Vec<&'static str> = Vec::new();
    let mut visible = false;
    let mut flags = 0u16;
    for s in t.semantics_for(token)? {
        let sem: MethodSemanticsRow = t.method_semantics(s)?;
        let acc: MethodDefRow = t.method_def(sem.method.get())?;
        let (v, _) = member_access(acc.flags);
        if !v {
            continue;
        }
        visible = true;
        flags = acc.flags;
        match sem.semantics {
            0x2 => a.push("get"),
            0x1 if is_init(r, acc)? => a.push("init"),
            0x1 => a.push("set"),
            _ => {}
        }
    }
    Ok(visible.then_some((a, flags)))
}

/// The visible fields, other than an enum's storage.
fn field_members(r: &Reader, type_rid: u32, out: &mut Vec<Member>) -> Res<()> {
    let t = r.md.tables();
    for rid in t.field_range(Rid::new(type_rid))? {
        let f: FieldRow = t.field(rid)?;
        let (visible, protected) = member_access(f.flags);
        // `value__`, an enum's storage, is RTSpecialName.
        if !visible || f.flags & 0x400 != 0 {
            continue;
        }
        let sig = FieldSig::parse(r.md.blobs().get(f.signature)?)?;
        let mut a = Vec::new();
        if f.is_static() {
            a.push("static");
        }
        if protected {
            a.push("protected");
        }
        if f.is_literal() {
            a.push("const");
        } else if f.flags & 0x20 != 0 {
            a.push("readonly");
        }
        a.extend(r.tags(Token::new(TableId::Field, rid))?);
        let v = if f.is_literal() {
            t.constant_of(Token::new(TableId::Field, rid))?
                .and_then(|c| constant(r, c))
        } else {
            None
        };
        out.push(Member {
            k: "field",
            n: r.str(f.name),
            t: r.type_name(&sig.type_)?,
            p: Vec::new(),
            g: 0,
            a,
            v,
        });
    }
    Ok(())
}

/// The events with a visible `add` accessor.
fn event_members(r: &Reader, type_rid: u32, out: &mut Vec<Member>) -> Res<()> {
    let t = r.md.tables();
    if let Some(map) = t.event_map_of(Rid::new(type_rid))? {
        for rid in t.event_range(map)? {
            let e: EventRow = t.event(rid)?;
            let token = Token::new(TableId::Event, rid);
            let accessor = t
                .semantics_for(token)?
                .into_iter()
                .map(|s| t.method_semantics(s))
                .collect::<Result<Vec<MethodSemanticsRow>, _>>()?
                .into_iter()
                .find(|s| s.semantics == 0x8);
            let Some(add) = accessor else { continue };
            let acc: MethodDefRow = t.method_def(add.method.get())?;
            let (visible, protected) = member_access(acc.flags);
            if !visible {
                continue;
            }
            out.push(Member {
                k: "event",
                n: r.str(e.name),
                t: r.token_name(e.event_type)?,
                p: Vec::new(),
                g: 0,
                a: method_flags(acc.flags, protected),
                v: None,
            });
        }
    }
    Ok(())
}

fn method_flags(flags: u16, protected: bool) -> Vec<&'static str> {
    let mut a = Vec::new();
    if flags & 0x10 != 0 {
        a.push("static");
    }
    if protected {
        a.push("protected");
    }
    if flags & 0x400 != 0 {
        a.push("abstract");
    } else if flags & 0x40 != 0 && flags & 0x20 == 0 {
        a.push("virtual");
    }
    a
}

/// A setter whose return type is marked `modreq(IsExternalInit)`.
fn is_init(r: &Reader, acc: MethodDefRow) -> Res<bool> {
    let sig = MethodSig::parse(r.md.blobs().get(acc.signature)?)?;
    for m in &sig.return_type.custom_mods {
        if r.token_name(m.type_token)? == "System.Runtime.CompilerServices.IsExternalInit" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn params(r: &Reader, method: u32, sig: &MethodSig) -> Res<Vec<ParamEntry>> {
    let t = r.md.tables();
    let mut out: Vec<ParamEntry> = sig
        .params
        .iter()
        .map(|p| {
            Ok(ParamEntry {
                t: r.type_name(&p.type_)?,
                n: String::new(),
                a: if p.by_ref {
                    vec!["ref".to_string()]
                } else {
                    Vec::new()
                },
                d: None,
            })
        })
        .collect::<Res<_>>()?;
    for rid in t.param_range(Rid::new(method))? {
        let p: ParamRow = t.param(rid)?;
        if let Some(entry) = (p.sequence as usize)
            .checked_sub(1)
            .and_then(|i| out.get_mut(i))
        {
            apply_param_row(r, rid, &p, entry)?;
        }
    }
    Ok(out)
}

/// What a Param row adds to its parameter: its name, `out` or `in` for a
/// by-ref one, "optional" and its default, and its attributes' tags.
fn apply_param_row(r: &Reader, rid: u32, p: &ParamRow, entry: &mut ParamEntry) -> Res<()> {
    let t = r.md.tables();
    entry.n = r.str(p.name);
    if entry.a.first().is_some_and(|x| x == "ref") {
        if p.flags & 0x2 != 0 {
            entry.a[0] = "out".to_string();
        } else if p.flags & 0x1 != 0 {
            entry.a[0] = "in".to_string();
        }
    }
    if p.flags & 0x1010 != 0 {
        entry.a.push("optional".to_string());
    }
    if p.flags & 0x1000 != 0 {
        entry.d = t
            .constant_of(Token::new(TableId::Param, rid))?
            .and_then(|c| constant(r, c));
    }
    for (name, blob) in r.attributes(Token::new(TableId::Param, rid))? {
        entry.a.extend(param_attribute_tag(&name, &blob));
    }
    Ok(())
}

/// The tag a parameter attribute gives: `params`, `Localizable(true)`, a
/// caller-information attribute, or a `StringSyntax`.
fn param_attribute_tag(name: &str, blob: &[u8]) -> Option<String> {
    match name {
        "System.ParamArrayAttribute" => Some("params".to_string()),
        "System.ComponentModel.LocalizableAttribute" if blob.get(2) == Some(&1) => {
            Some("Localizable".to_string())
        }
        "System.Runtime.CompilerServices.CallerMemberNameAttribute"
        | "System.Runtime.CompilerServices.CallerFilePathAttribute"
        | "System.Runtime.CompilerServices.CallerLineNumberAttribute"
        | "System.Runtime.CompilerServices.CallerArgumentExpressionAttribute" => {
            Some("caller".to_string())
        }
        "System.Diagnostics.CodeAnalysis.StringSyntaxAttribute" => {
            ser_string(&blob[2.min(blob.len())..]).map(|s| format!("syntax:{s}"))
        }
        _ => None,
    }
}

/// A constant's value (ECMA-335 II.22.9): "true" or "false", an integer,
/// a float with a decimal point or exponent, `'c` for a char, `"text` for
/// a string, or "null" (also a struct's `default`). None for an encoding
/// it can't read.
fn constant(r: &Reader, c: cildec::tables::ConstantRow) -> Option<String> {
    let b = r.md.blobs().get(c.value).ok()?;
    let bytes = |n: usize| -> Option<[u8; 8]> {
        let mut a = [0u8; 8];
        a.get_mut(..n)?.copy_from_slice(b.get(..n)?);
        Some(a)
    };
    let i16_at = || Some(i16::from_le_bytes(b.get(..2)?.try_into().ok()?));
    let u16_at = || Some(u16::from_le_bytes(b.get(..2)?.try_into().ok()?));
    let i32_at = || Some(i32::from_le_bytes(b.get(..4)?.try_into().ok()?));
    let u32_at = || Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?));
    Some(match c.element_type() {
        0x02 => (*b.first()? != 0).to_string(),
        0x03 => format!("'{}", char::from_u32(u32::from(u16_at()?))?),
        0x04 => (*b.first()? as i8).to_string(),
        0x05 => b.first()?.to_string(),
        0x06 => i16_at()?.to_string(),
        0x07 => u16_at()?.to_string(),
        0x08 => i32_at()?.to_string(),
        0x09 => u32_at()?.to_string(),
        0x0a => i64::from_le_bytes(bytes(8)?).to_string(),
        0x0b => u64::from_le_bytes(bytes(8)?).to_string(),
        0x0c => format!("{:?}", f64::from(f32::from_bits(u32_at()?))),
        0x0d => format!("{:?}", f64::from_le_bytes(bytes(8)?)),
        0x0e => {
            let units: Vec<u16> = b
                .as_chunks::<2>()
                .0
                .iter()
                .map(|u| u16::from_le_bytes(*u))
                .collect();
            format!("\"{}", String::from_utf16(&units).ok()?)
        }
        0x12 => "null".to_string(),
        _ => return None,
    })
}

/// A custom attribute blob's first string argument (ECMA-335 II.23.3).
fn ser_string(b: &[u8]) -> Option<String> {
    let (len, used) = match *b.first()? {
        x if x & 0x80 == 0 => (x as usize, 1),
        x if x & 0xC0 == 0x80 => ((((x & 0x3F) as usize) << 8) | *b.get(1)? as usize, 2),
        _ => return None,
    };
    let s = b.get(used..used + len)?;
    String::from_utf8(s.to_vec()).ok()
}
