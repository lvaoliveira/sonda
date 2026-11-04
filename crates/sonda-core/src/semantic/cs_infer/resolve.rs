//! Overload resolution (ADR-0022, step 3): the method a call binds to,
//! chosen among the overloads its name finds by its arguments' types as C#
//! chooses, and the parameter each argument goes to. When an argument's
//! type, a parameter's, or overloads a type's unresolved bases may add
//! leave the choice open, there is none: rules then report nothing.
//!
//! Calls through a type's members, a local function, an extension method
//! or a platform constructor resolve; explicit type arguments (`M<int>()`),
//! `base.` calls and a local type's constructors don't.

use super::{Conversion, Found, Infer, STRING, Ty, settled, simple, unify, widens_to};
use crate::semantic::DeclKind;
use tree_sitter::Node;

/// A compile-time constant: a literal, a constant field, `default`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Constant {
    /// `null`, and the `default` of a struct other than a number.
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Char(char),
    Str(String),
}

impl Constant {
    /// A value in the platform summary's form (`dotnet.rs`).
    fn read(text: &str) -> Option<Constant> {
        Some(match text {
            "null" => Constant::Null,
            "true" => Constant::Bool(true),
            "false" => Constant::Bool(false),
            _ if text.starts_with('"') => Constant::Str(text[1..].to_string()),
            _ if text.starts_with('\'') => Constant::Char(text[1..].chars().next()?),
            _ => match text.parse::<i128>() {
                Ok(n) => Constant::Int(n),
                Err(_) => Constant::Float(text.parse().ok()?),
            },
        })
    }

    /// Whether two constants are the same value, numbers by value: `5`
    /// passed for a `double` whose default is 5.0.
    pub(crate) fn same(&self, other: &Constant) -> bool {
        match (self, other) {
            (Constant::Int(a), Constant::Float(b)) | (Constant::Float(b), Constant::Int(a)) => {
                *a as f64 == *b
            }
            _ => self == other,
        }
    }
}

/// A parameter of a method a call may bind to.
pub(crate) struct Param<'m> {
    pub(crate) name: &'m str,
    /// With the declaring type's arguments substituted; None when it
    /// doesn't resolve.
    pub(crate) ty: Option<Ty>,
    /// "ref", "out", "in" or "this".
    pub(crate) modifier: Option<&'m str>,
    pub(crate) optional: bool,
    /// A `params` array.
    pub(crate) params: bool,
    /// An optional parameter's default, when known.
    pub(crate) default: Option<Constant>,
    /// Whether an attribute may supply its value: a caller-information
    /// attribute of the platform's, any attribute of the file's.
    pub(crate) attributed: bool,
}

/// An argument as written.
#[derive(Clone, Copy)]
pub(crate) struct Arg<'t> {
    /// The `argument` node.
    pub(crate) node: Node<'t>,
    pub(crate) value: Node<'t>,
    /// The parameter it names, `name: value`.
    pub(crate) name: Option<Node<'t>>,
    /// "ref", "out" or "in".
    pub(crate) modifier: Option<&'static str>,
}

/// The arguments of an invocation or object creation.
pub(crate) fn arguments(call: Node) -> Vec<Arg> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    list.named_children(&mut list.walk())
        .filter(|a| a.kind() == "argument")
        .filter_map(|a| {
            let name = a.child_by_field_name("name");
            let value = a.named_child(a.named_child_count().checked_sub(1)? as u32)?;
            let modifier = a.children(&mut a.walk()).find_map(|c| match c.kind() {
                "ref" => Some("ref"),
                "out" => Some("out"),
                "in" => Some("in"),
                _ => None,
            });
            (name.map(|n| n.id()) != Some(value.id())).then_some(Arg {
                node: a,
                value,
                name,
                modifier,
            })
        })
        .collect()
}

/// The method a call binds to.
pub(crate) struct Bound<'m, 't> {
    pub(crate) method: Found<'m, 't>,
    pub(crate) params: Vec<Param<'m>>,
    /// The parameter each argument goes to, by index into `params`. An
    /// extension method's receiver is its first parameter, not an argument.
    pub(crate) targets: Vec<usize>,
    pub(crate) extension: bool,
    /// How many other candidates without a `params` array also apply to
    /// the arguments, which the chosen method wins over.
    pub(crate) rivals: usize,
}

/// A method a call's name finds.
struct Candidate<'m, 't> {
    found: Found<'m, 't>,
    params: Vec<Param<'m>>,
    /// Its distance from the receiver's type, counting from the type that
    /// introduces it: C# drops the methods of a base type when a derived
    /// one has an applicable method.
    depth: usize,
    generic: bool,
    /// Whether it overrides a method, so belongs to a base type.
    overrides: bool,
    /// 1 for an extension method's receiver.
    skip: usize,
}

/// A call's candidates, whether they are all, and its receiver.
type Candidates<'m, 't> = (Vec<Candidate<'m, 't>>, bool, Option<Ty>);

/// A method's parameter types and modifiers, to tell an override.
type Signature = Vec<(Option<Ty>, Option<String>)>;

/// A method a type declares: whether it's generic, and whether it overrides.
type FoundMethod<'m, 't> = (Found<'m, 't>, bool, bool);

/// Whether a candidate applies to the arguments.
enum Fit {
    No,
    /// An argument's type or a parameter's leaves it open; the parameter
    /// each argument would go to.
    Unknown(Vec<usize>),
    Yes {
        targets: Vec<usize>,
        /// The type each argument converts to.
        types: Vec<Ty>,
        expanded: bool,
        /// Whether each parameter has an argument.
        all: bool,
    },
}

/// How two parameter types compare for an argument (C# 12.6.4.5).
#[derive(PartialEq)]
enum Better {
    First,
    Second,
    Same,
    Neither,
}

const SIGNED_BEFORE_UNSIGNED: &[(&str, &[&str])] = &[
    (
        "System.SByte",
        &[
            "System.Byte",
            "System.UInt16",
            "System.UInt32",
            "System.UInt64",
        ],
    ),
    (
        "System.Int16",
        &["System.UInt16", "System.UInt32", "System.UInt64"],
    ),
    ("System.Int32", &["System.UInt32", "System.UInt64"]),
    ("System.Int64", &["System.UInt64"]),
];

const INTEGRAL_RANGES: &[(&str, i128, i128)] = &[
    ("System.SByte", i8::MIN as i128, i8::MAX as i128),
    ("System.Byte", 0, u8::MAX as i128),
    ("System.Int16", i16::MIN as i128, i16::MAX as i128),
    ("System.UInt16", 0, u16::MAX as i128),
    ("System.Int32", i32::MIN as i128, i32::MAX as i128),
    ("System.UInt32", 0, u32::MAX as i128),
    ("System.Int64", i64::MIN as i128, i64::MAX as i128),
    ("System.UInt64", 0, u64::MAX as i128),
];

impl<'m, 't> Infer<'m, 't> {
    /// A method's parameters.
    pub(crate) fn params(&self, found: &Found<'m, 't>) -> Option<Vec<Param<'m>>> {
        match found {
            Found::Platform { member, vars, .. } => {
                // The method's own type parameters stay, for a call to bind.
                let own: Vec<Ty> = (0..member.generic).map(Ty::MVar).collect();
                Some(
                    member
                        .params
                        .iter()
                        .map(|p| {
                            let has = |tag: &str| p.tags.iter().any(|t| t == tag);
                            Param {
                                name: &p.name,
                                ty: Ty::parse(&p.ty).map(|t| t.substitute(vars, &own)),
                                modifier: ["ref", "out", "in"].into_iter().find(|m| has(m)),
                                optional: has("optional"),
                                params: has("params"),
                                default: p.default.as_deref().and_then(Constant::read),
                                attributed: has("caller"),
                            }
                        })
                        .collect(),
                )
            }
            Found::Local(d) => {
                let declarator = d.declarator?;
                let Some(list) = declarator.child_by_field_name("parameters") else {
                    return Some(Vec::new());
                };
                let mut out: Vec<Param<'m>> = list
                    .named_children(&mut list.walk())
                    .filter(|p| p.kind() == "parameter")
                    .map(|p| {
                        let name = p.child_by_field_name("name");
                        let ty = p.child_by_field_name("type").and_then(|t| self.written(t));
                        let mut c = p.walk();
                        let children: Vec<Node> = p.named_children(&mut c).collect();
                        // The default value follows the name.
                        let value = name.and_then(|n| {
                            children
                                .iter()
                                .skip_while(|c| c.id() != n.id())
                                .nth(1)
                                .copied()
                        });
                        Param {
                            name: name.map_or("", |n| self.text(n)),
                            default: value.and_then(|v| self.constant(v, ty.as_ref())),
                            ty,
                            modifier: children
                                .iter()
                                .find(|c| c.kind() == "modifier")
                                .map(|c| self.text(*c)),
                            optional: value.is_some(),
                            params: false,
                            attributed: children.iter().any(|c| c.kind() == "attribute_list"),
                        }
                    })
                    .collect();
                // `params T[] name` is written on the list itself.
                if let Some(name) = list.child_by_field_name("name") {
                    out.push(Param {
                        name: self.text(name),
                        ty: list
                            .child_by_field_name("type")
                            .and_then(|t| self.written(t)),
                        modifier: None,
                        optional: false,
                        params: true,
                        default: None,
                        attributed: false,
                    });
                }
                Some(out)
            }
        }
    }

    /// The methods a call taking `n` arguments may bind to by its name and
    /// arity, before its arguments' types are looked at; whether no
    /// unresolved base type could add more; and the receiver of an instance
    /// call, for extension methods.
    fn candidates(&self, call: Node, n: usize) -> Option<Candidates<'m, 't>> {
        Some(match call.kind() {
            "invocation_expression" => {
                let function = call.child_by_field_name("function")?;
                match function.kind() {
                    "member_access_expression" => {
                        let name = function.child_by_field_name("name")?;
                        if name.kind() != "identifier" {
                            return None;
                        }
                        let expr = function.child_by_field_name("expression")?;
                        let instance = self.type_of(expr).is_some();
                        let receiver = self.receiver(expr, 0)?;
                        let (c, complete) =
                            self.chain_methods(&receiver, self.text(name), n, Some(instance));
                        (c, complete, instance.then_some(receiver))
                    }
                    "identifier" => {
                        let name = self.text(function);
                        if let Some(d) = self
                            .m
                            .decl_of(function)
                            .filter(|d| d.kind == DeclKind::Function)
                        {
                            let found = Found::Local(d);
                            let params = self.params(&found)?;
                            let candidate = Candidate {
                                found,
                                params,
                                depth: 0,
                                generic: false,
                                overrides: false,
                                skip: 0,
                            };
                            (vec![candidate], true, None)
                        } else {
                            let owner = self.enclosing_type(call)?;
                            let (c, complete) = self.chain_methods(&owner, name, n, None);
                            (c, complete, None)
                        }
                    }
                    _ => return None,
                }
            }
            "object_creation_expression" => {
                let ty = self.written(call.child_by_field_name("type")?)?;
                let p = self.platform.get(ty.key()?)?;
                let c = p
                    .members
                    .iter()
                    .filter(|m| m.kind == "constructor")
                    .filter_map(|member| {
                        let found = Found::Platform {
                            declaring: p,
                            member,
                            vars: ty.args().to_vec(),
                        };
                        Some(Candidate {
                            params: self.params(&found)?,
                            found,
                            depth: 0,
                            generic: false,
                            overrides: false,
                            skip: 0,
                        })
                    })
                    .collect();
                (c, true, None)
            }
            _ => return None,
        })
    }

    /// The parameters of each method a call may bind to by its name and
    /// arity, extension methods when no other may: a cheap test before
    /// `resolve_with` of what a rule needs.
    pub(crate) fn candidate_params(&self, call: Node, n: usize) -> Vec<Vec<Param<'m>>> {
        let Some((candidates, _, receiver)) = self.candidates(call, n) else {
            return Vec::new();
        };
        if candidates.is_empty()
            && let (Some(receiver), Some(name)) = (
                receiver,
                call.child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("name")),
            )
        {
            return self
                .extension_candidates(&receiver, self.text(name), n, call.start_byte())
                .into_iter()
                .map(|c| c.params)
                .collect();
        }
        candidates.into_iter().map(|c| c.params).collect()
    }

    /// The method an invocation or object creation binds to with its own
    /// arguments (`arguments`).
    pub(crate) fn resolve_with<'n>(
        &self,
        call: Node<'n>,
        args: &[Arg<'n>],
    ) -> Option<Bound<'m, 't>> {
        self.resolve_args(call, args, true)
    }

    /// The method a call would bind to with `args` for arguments, them
    /// without one, say: since such a call may not compile, a candidate an
    /// argument's type leaves open never counts as the one.
    pub(crate) fn resolve_instead<'n>(
        &self,
        call: Node<'n>,
        args: &[Arg<'n>],
    ) -> Option<Bound<'m, 't>> {
        self.resolve_args(call, args, false)
    }

    /// `resolve_with`, assuming the call compiles when `compiles`.
    fn resolve_args<'n>(
        &self,
        call: Node<'n>,
        args: &[Arg<'n>],
        compiles: bool,
    ) -> Option<Bound<'m, 't>> {
        let n = args.len();
        let (candidates, complete, receiver) = self.candidates(call, n)?;
        let fits: Vec<Fit> = candidates.iter().map(|c| self.fit(c, args)).collect();
        if fits.iter().any(|f| matches!(f, Fit::Unknown(_))) {
            // Should it not apply, an extension method may.
            let extensions = match (&receiver, call.child_by_field_name("function")) {
                (Some(r), Some(f)) => {
                    f.child_by_field_name("name")
                        .and_then(simple)
                        .is_some_and(|name| {
                            !self
                                .extension_candidates(r, self.text(name), n, call.start_byte())
                                .is_empty()
                        })
                }
                _ => false,
            };
            return self.only_one(candidates, fits, compiles && complete && !extensions);
        }
        let mut applicable: Vec<(Candidate, Fit)> = candidates
            .into_iter()
            .zip(fits)
            .filter(|(_, f)| matches!(f, Fit::Yes { .. }))
            .collect();
        if applicable.is_empty() {
            // Extension methods, when no instance method applies.
            let receiver = receiver.filter(|_| complete)?;
            let function = call.child_by_field_name("function")?;
            let name = self.text(simple(function.child_by_field_name("name")?)?);
            let extensions = self.extension_candidates(&receiver, name, n, call.start_byte());
            let fits: Vec<Fit> = extensions.iter().map(|c| self.fit(c, args)).collect();
            if fits.iter().any(|f| matches!(f, Fit::Unknown(_))) {
                return self.only_one(extensions, fits, compiles && complete);
            }
            applicable = extensions
                .into_iter()
                .zip(fits)
                .filter(|(_, f)| matches!(f, Fit::Yes { .. }))
                .collect();
        } else if !complete && applicable.iter().any(|(c, _)| c.overrides) {
            // The overridden method's type declares overloads unseen.
            return None;
        }
        // Methods of a derived type hide a base type's.
        let nearest = applicable.iter().map(|(c, _)| c.depth).min()?;
        applicable.retain(|(c, _)| c.depth == nearest);
        let best = (0..applicable.len()).find(|&i| {
            (0..applicable.len())
                .all(|j| i == j || self.better(&applicable[i], &applicable[j], args))
        })?;
        let (c, fit) = applicable.swap_remove(best);
        let rivals = applicable
            .iter()
            .filter(|(o, _)| !o.params.last().is_some_and(|p| p.params))
            .count();
        let Fit::Yes { targets, .. } = fit else {
            return None;
        };
        Some(Bound {
            extension: c.skip == 1,
            method: c.found,
            params: c.params,
            targets,
            rivals,
        })
    }

    /// The one candidate an argument's type leaves open when every other is
    /// ruled out: a call that compiles binds to it. None when a base type
    /// that doesn't resolve may declare others.
    fn only_one(
        &self,
        candidates: Vec<Candidate<'m, 't>>,
        fits: Vec<Fit>,
        complete: bool,
    ) -> Option<Bound<'m, 't>> {
        let mut open = candidates
            .into_iter()
            .zip(fits)
            .filter(|(_, f)| !matches!(f, Fit::No));
        let (c, Fit::Unknown(targets)) = open.next()? else {
            return None;
        };
        (complete && open.next().is_none()).then_some(Bound {
            extension: c.skip == 1,
            method: c.found,
            params: c.params,
            targets,
            rivals: 0,
        })
    }

    /// The methods named `name` that `ty` and its base types declare, the
    /// nearest first, an override counted with the method it overrides;
    /// static ones only, or instance ones only, when `instance` says.
    /// Whether no base type left unresolved could declare more.
    fn chain_methods(
        &self,
        ty: &Ty,
        name: &str,
        arguments: usize,
        instance: Option<bool>,
    ) -> (Vec<Candidate<'m, 't>>, bool) {
        let interface = self.interface(ty) == Some(true);
        let chain: Vec<Ty> = self
            .supertypes(ty)
            .into_iter()
            .filter(|t| interface || self.interface(t) != Some(true))
            .collect();
        let mut complete = if interface {
            self.complete(ty)
        } else {
            self.base_classes_known(ty)
        };
        let mut out: Vec<Candidate> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();
        for (depth, t) in chain.iter().enumerate() {
            let found = match t {
                Ty::Named {
                    key,
                    args,
                    local: false,
                } => self.platform_methods(key, args, name, instance),
                Ty::Named {
                    key, local: true, ..
                } => self.local_methods(key, name, instance, &mut complete),
                _ => None,
            };
            let Some(found) = found else {
                continue;
            };
            for (f, generic, overrides) in found {
                let Some(params) = self.params(&f) else {
                    complete = false;
                    continue;
                };
                if !fits_count(&params, arguments) {
                    continue;
                }
                let signature: Signature = params
                    .iter()
                    .map(|p| (p.ty.clone(), p.modifier.map(str::to_string)))
                    .collect();
                // The same signature in a base type: this one overrides it.
                if let Some(i) = signatures.iter().position(|s| *s == signature) {
                    out[i].depth = depth;
                    out[i].overrides = false;
                    continue;
                }
                signatures.push(signature);
                out.push(Candidate {
                    found: f,
                    params,
                    depth,
                    generic,
                    overrides,
                    skip: 0,
                });
            }
        }
        (out, complete)
    }

    /// The methods named `name` the platform type `key` declares, static
    /// ones only or instance ones only when `instance` says: (method,
    /// generic, overrides). None when it's not a platform type.
    fn platform_methods(
        &self,
        key: &str,
        args: &[Ty],
        name: &str,
        instance: Option<bool>,
    ) -> Option<Vec<FoundMethod<'m, 't>>> {
        let p = self.platform.get(key)?;
        Some(
            p.members
                .iter()
                .filter(|m| m.kind == "method" && m.name == name)
                .filter(|member| !instance.is_some_and(|i| i == member.has("static")))
                .map(|member| {
                    let method = Found::Platform {
                        declaring: p,
                        member,
                        vars: args.to_vec(),
                    };
                    (method, member.generic > 0, false)
                })
                .collect(),
        )
    }

    /// The methods named `name` the file's type `key` declares, as
    /// `platform_methods`; a partial type leaves `complete` false, since
    /// other parts may declare more.
    fn local_methods(
        &self,
        key: &str,
        name: &str,
        instance: Option<bool>,
        complete: &mut bool,
    ) -> Option<Vec<FoundMethod<'m, 't>>> {
        let local = self.locals.get(key).copied().flatten()?;
        let modifiers = |n: Node| -> Vec<&str> {
            n.children(&mut n.walk())
                .filter(|c| c.kind() == "modifier")
                .map(|c| self.text(c))
                .collect()
        };
        if modifiers(local.node).contains(&"partial") {
            *complete = false;
        }
        let scope = local.members?;
        let mut found = Vec::new();
        for &d in self.m.decls_named(scope, name) {
            let d = &self.m.decls[d];
            let Some(method) = d.declarator.filter(|_| d.kind == DeclKind::Method) else {
                continue;
            };
            let mods = modifiers(method);
            if instance.is_some_and(|i| i == mods.contains(&"static")) {
                continue;
            }
            let generic = method.child_by_field_name("type_parameters").is_some();
            found.push((Found::Local(d), generic, mods.contains(&"override")));
        }
        Some(found)
    }

    /// Extension methods `receiver.name(...)` may call, with the receiver's
    /// type arguments bound.
    fn extension_candidates(
        &self,
        receiver: &Ty,
        name: &str,
        arguments: usize,
        byte: usize,
    ) -> Vec<Candidate<'m, 't>> {
        self.extensions(receiver, name, arguments, byte)
            .into_iter()
            .filter_map(|(found, bound)| {
                let Found::Platform { member, .. } = &found else {
                    return None;
                };
                let generic = member.generic > 0;
                let mut params = self.params(&found)?;
                for p in &mut params {
                    p.ty = p.ty.take().map(|t| t.substitute(&[], &bound));
                }
                Some(Candidate {
                    found,
                    params,
                    depth: 0,
                    generic,
                    overrides: false,
                    skip: 1,
                })
            })
            .collect()
    }

    /// Whether a candidate applies to the arguments, in its normal form or
    /// else its expanded one.
    fn fit(&self, c: &Candidate, args: &[Arg]) -> Fit {
        match self.fit_form(c, args, false) {
            Fit::No if c.params.last().is_some_and(|p| p.params) => self.fit_form(c, args, true),
            other => other,
        }
    }

    fn fit_form(&self, c: &Candidate, args: &[Arg], expanded: bool) -> Fit {
        let params = &c.params[c.skip..];
        let Some((targets, all)) = self.argument_targets(params, args, expanded) else {
            return Fit::No;
        };
        let bound = self.bind_method_type_params(c, params, args, &targets, expanded);
        let Some((types, open)) = self.argument_types(params, args, &targets, &bound, expanded)
        else {
            return Fit::No;
        };
        let targets: Vec<usize> = targets.into_iter().map(|j| j + c.skip).collect();
        if open {
            return Fit::Unknown(targets);
        }
        Fit::Yes {
            targets,
            types,
            expanded,
            all,
        }
    }

    /// The parameter each argument goes to, and whether each parameter has
    /// one; None when the arguments don't fit the parameters: a name none
    /// has, a positional argument after one out of position, a parameter
    /// filled twice, or a required one left empty.
    fn argument_targets(
        &self,
        params: &[Param],
        args: &[Arg],
        expanded: bool,
    ) -> Option<(Vec<usize>, bool)> {
        let last = params.len().wrapping_sub(1);
        let mut filled = vec![false; params.len()];
        let mut targets = Vec::new();
        let mut out_of_position = false;
        for (position, a) in args.iter().enumerate() {
            let j = self.argument_target(a, position, params, expanded, &mut out_of_position)?;
            if j >= params.len() || filled[j] && !(expanded && j == last) {
                return None;
            }
            filled[j] = true;
            targets.push(j);
        }
        let all = filled.iter().all(|f| *f);
        if params
            .iter()
            .zip(&filled)
            .any(|(p, f)| !f && !p.optional && !(p.params && expanded))
        {
            return None;
        }
        Some((targets, all))
    }

    /// The parameter the argument at `position` goes to: the one it names,
    /// or its position's; a positional argument after a named one out of
    /// position fits none.
    fn argument_target(
        &self,
        a: &Arg,
        position: usize,
        params: &[Param],
        expanded: bool,
        out_of_position: &mut bool,
    ) -> Option<usize> {
        let last = params.len().wrapping_sub(1);
        match a.name {
            Some(name) => {
                let name = self.text(name);
                let j = params.iter().position(|p| p.name == name)?;
                if expanded && j == last {
                    return None;
                }
                *out_of_position |= j != position;
                Some(j)
            }
            None if *out_of_position => None,
            None if expanded && position >= last => Some(last),
            None => Some(position),
        }
    }

    /// The method's own type parameters, bound from the arguments.
    fn bind_method_type_params(
        &self,
        c: &Candidate,
        params: &[Param],
        args: &[Arg],
        targets: &[usize],
        expanded: bool,
    ) -> Vec<Ty> {
        let Found::Platform { member, .. } = &c.found else {
            return Vec::new();
        };
        let last = params.len().wrapping_sub(1);
        let mut bound = vec![Ty::Unknown; member.generic as usize];
        for (a, &j) in args.iter().zip(targets) {
            let (Some(pattern), Some(actual)) = (params[j].ty.as_ref(), self.type_of(a.value))
            else {
                continue;
            };
            let pattern = match pattern {
                Ty::Array(e) if expanded && j == last => e,
                p => p,
            };
            let direct = unify(pattern, &actual, &mut bound);
            if !direct && let Some(key) = pattern.key() {
                for s in self.supertypes(&actual) {
                    if s.key() == Some(key) && unify(pattern, &s, &mut bound) {
                        break;
                    }
                }
            }
        }
        bound
    }

    /// The type each argument converts to, and whether one stays open; None
    /// when one doesn't convert.
    fn argument_types(
        &self,
        params: &[Param],
        args: &[Arg],
        targets: &[usize],
        bound: &[Ty],
        expanded: bool,
    ) -> Option<(Vec<Ty>, bool)> {
        let last = params.len().wrapping_sub(1);
        let mut types = Vec::new();
        let mut open = false;
        for (a, &j) in args.iter().zip(targets) {
            let p = &params[j];
            let Some(ty) = p.ty.as_ref().map(|t| t.substitute(&[], bound)) else {
                open = true;
                continue;
            };
            let ty = match ty {
                Ty::Array(e) if expanded && j == last => *e,
                t => t,
            };
            match self.converts(a, p.modifier, &ty) {
                Some(true) => types.push(ty),
                Some(false) => return None,
                None => open = true,
            }
        }
        Some((types, open))
    }

    /// Whether an argument converts implicitly to a parameter's type; None
    /// when its type or the parameter's leaves it open.
    fn converts(&self, a: &Arg, modifier: Option<&str>, to: &Ty) -> Option<bool> {
        let value = a.value;
        let modifier = modifier.filter(|m| *m != "this");
        match (a.modifier, modifier) {
            (None, None | Some("in")) => {}
            (Some(x), Some(y)) if x == y => return self.ref_out_conversion(x, value, to),
            _ => return Some(false),
        }
        // A lambda needs a delegate taking as many parameters, whatever its
        // type arguments.
        if matches!(
            value.kind(),
            "lambda_expression" | "anonymous_method_expression"
        ) && let (Some(n), Some(m)) = (lambda_arity(value), self.invoke_arity(to))
            && n != m
        {
            return Some(false);
        }
        if !settled(to) {
            return None;
        }
        if let Some(converts) = self.literal_conversion(value, to) {
            return converts;
        }
        if self.constant_fits(value, to) {
            return Some(true);
        }
        match self.type_of(value) {
            Some(from) => self.implicitly(&from, to),
            // Any value converts to object, whatever its type.
            None => to.is("System.Object").then_some(true),
        }
    }

    /// A `ref`, `out` or `in` argument to a parameter with the same
    /// modifier: the types must be the same; `out var x` and `out _` take
    /// any type.
    fn ref_out_conversion(&self, modifier: &str, value: Node, to: &Ty) -> Option<bool> {
        if modifier == "out"
            && (value.kind() == "declaration_expression"
                && value
                    .child_by_field_name("type")
                    .is_some_and(|t| t.kind() == "implicit_type")
                || self.text(value) == "_")
        {
            return Some(true);
        }
        let from = match value.kind() {
            "declaration_expression" => self.written(value.child_by_field_name("type")?),
            _ => self.type_of(value),
        }?;
        settled(&from).then(|| from == *to)
    }

    /// The conversions of values with no type of their own: `null`,
    /// `default`, a lambda (whose natural type converts to Delegate and
    /// object) and an interpolated string. None when `value` is none of
    /// those, or the rule doesn't decide it.
    fn literal_conversion(&self, value: Node, to: &Ty) -> Option<Option<bool>> {
        match value.kind() {
            "null_literal" => Some(
                self.value_type(to)
                    .map(|v| to.is("System.Nullable`1") || !v)
                    .or_else(|| to.is("System.Nullable`1").then_some(true)),
            ),
            "default_expression" if value.named_child_count() == 0 => Some(Some(true)),
            "lambda_expression" | "anonymous_method_expression" => {
                let open = self.delegate(to)
                    || [
                        "System.Linq.Expressions.Expression`1",
                        "System.Delegate",
                        "System.MulticastDelegate",
                        "System.Object",
                    ]
                    .iter()
                    .any(|k| to.is(k));
                Some(if open {
                    None
                } else {
                    self.kind(to).map(|_| false)
                })
            }
            "interpolated_string_expression" => {
                if to.is(STRING)
                    || to.is("System.IFormattable")
                    || to.is("System.FormattableString")
                    || to.is("System.Object")
                {
                    return Some(Some(true));
                }
                to.key()
                    .is_some_and(|k| k.ends_with("InterpolatedStringHandler"))
                    .then_some(None)
            }
            _ => None,
        }
    }

    /// A constant integer converts to any integral type that holds it, and
    /// 0 to any enum.
    fn constant_fits(&self, value: Node, to: &Ty) -> bool {
        let Some(Constant::Int(n)) = self
            .type_of(value)
            .filter(|t| t.is("System.Int32"))
            .and_then(|_| self.constant(value, None))
        else {
            return false;
        };
        INTEGRAL_RANGES
            .iter()
            .find(|(k, _, _)| to.is(k))
            .is_some_and(|(_, lo, hi)| (*lo..=*hi).contains(&n))
            || (n == 0 && self.kind(to) == Some("enum"))
    }

    /// How many parameters a delegate type's Invoke takes, or an
    /// `Expression<D>`'s D.
    fn invoke_arity(&self, ty: &Ty) -> Option<usize> {
        if ty.is("System.Linq.Expressions.Expression`1") {
            return self.invoke_arity(ty.args().first()?);
        }
        match ty {
            Ty::Named {
                key, local: false, ..
            } => {
                let p = self.platform.get(key).filter(|p| p.kind == "delegate")?;
                p.members
                    .iter()
                    .find(|m| m.kind == "method" && m.name == "Invoke")
                    .map(|m| m.params.len())
            }
            Ty::Named {
                key, local: true, ..
            } => {
                let l = self.locals.get(key).copied().flatten()?;
                let list = l
                    .node
                    .child_by_field_name("parameters")
                    .filter(|_| l.node.kind() == "delegate_declaration")?;
                Some(
                    list.named_children(&mut list.walk())
                        .filter(|p| p.kind() == "parameter")
                        .count(),
                )
            }
            _ => None,
        }
    }

    /// Whether a value of `from` converts implicitly to `to`; None when the
    /// declarations don't tell.
    fn implicitly(&self, from: &Ty, to: &Ty) -> Option<bool> {
        if !settled(from) || !settled(to) {
            return None;
        }
        match self.conversion(from, to) {
            Some(Conversion::Identity | Conversion::Implicit) => Some(true),
            Some(Conversion::Explicit) => Some(false),
            Some(Conversion::UserDefined) => Some(self.user_conversion(from, to, true)),
            None => {
                // None is definite once both types and their bases resolve,
                // and they aren't arrays or generic types related by
                // variance, which conversions don't classify.
                let known = self.complete(from) && self.complete(to);
                let arrays = matches!((from, to), (Ty::Array(_), Ty::Array(_)));
                let variance = (self.interface(to) != Some(false) || self.delegate(to))
                    && self
                        .supertypes(from)
                        .iter()
                        .any(|s| s.key().is_some() && s.key() == to.key());
                let nullable = from.is("System.Nullable`1") || to.is("System.Nullable`1");
                (known && !arrays && !variance && !nullable).then_some(false)
            }
        }
    }

    /// Whether candidate `a` is better than `b` for the arguments (C#
    /// 12.6.4.3).
    fn better(&self, a: &(Candidate, Fit), b: &(Candidate, Fit), args: &[Arg]) -> bool {
        let (
            (
                ca,
                Fit::Yes {
                    types: ta,
                    expanded: ea,
                    all: alla,
                    ..
                },
            ),
            (
                cb,
                Fit::Yes {
                    types: tb,
                    expanded: eb,
                    all: allb,
                    ..
                },
            ),
        ) = (a, b)
        else {
            return false;
        };
        let mut first = false;
        let mut all_same = true;
        for ((x, y), arg) in ta.iter().zip(tb).zip(args) {
            match self.better_target(arg, x, y) {
                Better::First => {
                    first = true;
                    all_same = false;
                }
                Better::Second => return false,
                Better::Neither => all_same = false,
                Better::Same => {}
            }
        }
        if first {
            return true;
        }
        if !all_same {
            return false;
        }
        // Tie-breakers for the same parameter types.
        (!ca.generic && cb.generic) || (!ea && *eb) || (*alla && !allb)
    }

    /// Which of two parameter types an argument converts to better.
    fn better_target(&self, arg: &Arg, t1: &Ty, t2: &Ty) -> Better {
        if t1 == t2 {
            return Better::Same;
        }
        let from = match arg.value.kind() {
            "null_literal" | "default_expression" => None,
            _ => self.type_of(arg.value),
        };
        if let Some(s) = &from {
            if s == t1 {
                return Better::First;
            }
            if s == t2 {
                return Better::Second;
            }
        }
        let to_second = self.implicitly(t1, t2) == Some(true);
        let to_first = self.implicitly(t2, t1) == Some(true);
        match (to_second, to_first) {
            (true, false) => return Better::First,
            (false, true) => return Better::Second,
            _ => {}
        }
        for (signed, unsigned) in SIGNED_BEFORE_UNSIGNED {
            if t1.is(signed) && unsigned.iter().any(|u| t2.is(u)) {
                return Better::First;
            }
            if t2.is(signed) && unsigned.iter().any(|u| t1.is(u)) {
                return Better::Second;
            }
        }
        Better::Neither
    }

    /// The methods with the same name that the type declaring a method
    /// declares, itself included.
    pub(crate) fn overloads(&self, found: &Found<'m, 't>) -> Vec<Found<'m, 't>> {
        match found {
            Found::Platform {
                declaring,
                member,
                vars,
            } => declaring
                .members
                .iter()
                .filter(|m| m.kind == member.kind && m.name == member.name)
                .map(|m| Found::Platform {
                    declaring,
                    member: m,
                    vars: vars.clone(),
                })
                .collect(),
            Found::Local(d) => self
                .m
                .decls_named(d.scope, &d.name)
                .iter()
                .map(|&i| &self.m.decls[i])
                .filter(|o| o.kind == d.kind)
                .map(Found::Local)
                .collect(),
        }
    }

    /// Whether a method is static.
    pub(crate) fn is_static(&self, found: &Found) -> bool {
        match found {
            Found::Platform { member, .. } => member.has("static"),
            Found::Local(d) => d.declarator.is_some_and(|m| {
                m.children(&mut m.walk())
                    .any(|c| c.kind() == "modifier" && self.text(c) == "static")
            }),
        }
    }

    // ------------------------------------------------ constants

    /// The constant an expression is, `ty` giving `default`'s type when
    /// the expression doesn't.
    pub(crate) fn constant(&self, expr: Node, ty: Option<&Ty>) -> Option<Constant> {
        self.constant_at(expr, ty, 0)
    }

    fn constant_at(&self, expr: Node, ty: Option<&Ty>, depth: u8) -> Option<Constant> {
        if depth > 8 {
            return None;
        }
        let text = self.text(expr);
        match expr.kind() {
            "parenthesized_expression" => self.constant_at(expr.named_child(0)?, ty, depth + 1),
            "null_literal" => Some(Constant::Null),
            "boolean_literal" => Some(Constant::Bool(text == "true")),
            "integer_literal" => integer(text).map(Constant::Int),
            "real_literal" => {
                let t = text.replace('_', "").to_ascii_lowercase();
                let t = t.trim_end_matches(['f', 'd', 'm']);
                t.parse().ok().map(Constant::Float)
            }
            "character_literal" => {
                let inner = text.strip_prefix('\'')?.strip_suffix('\'')?;
                let value = unescape(inner)?;
                let mut chars = value.chars();
                let c = chars.next()?;
                chars.next().is_none().then_some(Constant::Char(c))
            }
            "string_literal" if !text.ends_with("u8") => {
                unescape(text.strip_prefix('"')?.strip_suffix('"')?).map(Constant::Str)
            }
            "verbatim_string_literal" if !text.ends_with("u8") => Some(Constant::Str(
                text.strip_prefix("@\"")?
                    .strip_suffix('"')?
                    .replace("\"\"", "\""),
            )),
            "prefix_unary_expression" => {
                let operand = self.constant_at(expr.named_child(0)?, ty, depth + 1)?;
                match (text.trim_start().chars().next()?, operand) {
                    ('-', Constant::Int(n)) => Some(Constant::Int(-n)),
                    ('-', Constant::Float(f)) => Some(Constant::Float(-f)),
                    ('+', c @ (Constant::Int(_) | Constant::Float(_))) => Some(c),
                    ('!', Constant::Bool(b)) => Some(Constant::Bool(!b)),
                    _ => None,
                }
            }
            "default_expression" => {
                let t = match expr.child_by_field_name("type") {
                    Some(t) => self.written(t)?,
                    None => ty?.clone(),
                };
                self.default_of(&t)
            }
            "member_access_expression" => {
                let owner = expr.child_by_field_name("expression")?;
                // A type's constant, not an instance's member.
                if self.type_of(owner).is_some() {
                    return None;
                }
                let ty = self.written(owner).or_else(|| self.receiver(owner, 0))?;
                self.field_constant(&ty, self.text(expr.child_by_field_name("name")?), depth)
            }
            "identifier" => {
                let d = self.m.decl_of(expr)?;
                let declarator = d.declarator.filter(|v| v.kind() == "variable_declarator")?;
                let declaration = declarator.parent()?.parent()?;
                let constant = declaration
                    .children(&mut declaration.walk())
                    .any(|c| c.kind() == "modifier" && self.text(c) == "const");
                if !constant {
                    return None;
                }
                let value =
                    declarator.named_child(declarator.named_child_count().checked_sub(1)? as u32)?;
                if value.id() == d.node.id() {
                    return None;
                }
                let ty = d.ty.and_then(|t| self.written(t));
                self.constant_at(value, ty.as_ref(), depth + 1)
            }
            _ => None,
        }
    }

    /// A constant field of a type: a platform constant or enum member, or
    /// a member of an enum the file declares.
    fn field_constant(&self, ty: &Ty, name: &str, depth: u8) -> Option<Constant> {
        match ty {
            Ty::Named {
                key, local: false, ..
            } => {
                let p = self.platform.get(key)?;
                let field = p
                    .members
                    .iter()
                    .find(|m| m.kind == "field" && m.name == name && m.has("const"))?;
                Constant::read(field.value.as_deref()?)
            }
            Ty::Named {
                key, local: true, ..
            } => {
                let local = self.locals.get(key).copied().flatten()?;
                if local.node.kind() != "enum_declaration" {
                    return None;
                }
                let body = local.node.child_by_field_name("body")?;
                let mut next = 0i128;
                for member in body.named_children(&mut body.walk()) {
                    if member.kind() != "enum_member_declaration" {
                        continue;
                    }
                    if let Some(v) = member.child_by_field_name("value") {
                        let Some(Constant::Int(n)) = self.constant_at(v, None, depth + 1) else {
                            return None;
                        };
                        next = n;
                    }
                    if self.text(member.child_by_field_name("name")?) == name {
                        return Some(Constant::Int(next));
                    }
                    next += 1;
                }
                None
            }
            _ => None,
        }
    }

    /// `default(T)`.
    fn default_of(&self, ty: &Ty) -> Option<Constant> {
        if ty.is("System.Boolean") {
            return Some(Constant::Bool(false));
        }
        if ty.is("System.Char") {
            return Some(Constant::Char('\0'));
        }
        if let Some(key) = ty.key()
            && widens_to(key).is_some()
        {
            return Some(
                if matches!(key, "System.Single" | "System.Double" | "System.Decimal") {
                    Constant::Float(0.0)
                } else {
                    Constant::Int(0)
                },
            );
        }
        if let Ty::Array(_) = ty {
            return Some(Constant::Null);
        }
        match self.kind(ty)? {
            "enum" => Some(Constant::Int(0)),
            _ => Some(Constant::Null),
        }
    }
}

/// How many parameters a lambda or anonymous method declares; None for
/// `delegate { }`, which fits any.
fn lambda_arity(lambda: Node) -> Option<usize> {
    let params = lambda.child_by_field_name("parameters").or_else(|| {
        lambda
            .named_children(&mut lambda.walk())
            .find(|c| c.kind() == "parameter_list")
    })?;
    Some(match params.kind() {
        "implicit_parameter" | "identifier" => 1,
        _ => params
            .named_children(&mut params.walk())
            .filter(|p| matches!(p.kind(), "parameter" | "implicit_parameter"))
            .count(),
    })
}

/// Whether a method takes `n` arguments, as many as its parameters but
/// optional ones and a `params` array.
fn fits_count(params: &[Param], n: usize) -> bool {
    let variadic = params.last().is_some_and(|p| p.params);
    let required = params.iter().filter(|p| !p.optional && !p.params).count();
    n >= required && (variadic || n <= params.len())
}

/// An integer literal's value.
fn integer(text: &str) -> Option<i128> {
    let t = text.replace('_', "").to_ascii_lowercase();
    let t = t.trim_end_matches(['u', 'l']);
    if let Some(hex) = t.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = t.strip_prefix("0b") {
        i128::from_str_radix(bin, 2).ok()
    } else {
        t.parse().ok()
    }
}

/// A regular string or character literal's content with its escapes
/// replaced; None for one it doesn't know.
fn unescape(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next()? {
            '\'' => '\'',
            '"' => '"',
            '\\' => '\\',
            '0' => '\0',
            'a' => '\u{7}',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{b}',
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?
            }
            _ => return None,
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{render, with_infer};
    use super::*;

    /// What each call in the source binds to, in order: the method's name
    /// and parameter types, `System.` left out, or None.
    fn bound(src: &str) -> Vec<Option<String>> {
        let mut out = Vec::new();
        with_infer(src, |infer, root| {
            let mut stack = vec![root];
            let mut calls = Vec::new();
            while let Some(n) = stack.pop() {
                if matches!(
                    n.kind(),
                    "invocation_expression" | "object_creation_expression"
                ) {
                    calls.push(n);
                }
                stack.extend(n.named_children(&mut n.walk()));
            }
            calls.sort_by_key(|n| n.start_byte());
            for call in calls {
                out.push(infer.resolve_with(call, &arguments(call)).map(|b| {
                    let name = match &b.method {
                        Found::Platform { member, .. } if member.kind == "constructor" => ".ctor",
                        Found::Platform { member, .. } => member.name.as_str(),
                        Found::Local(d) => d.name.as_str(),
                    };
                    let params: Vec<String> = b
                        .params
                        .iter()
                        .map(|p| {
                            p.ty.as_ref()
                                .map_or("?".to_string(), render)
                                .replace("System.", "")
                        })
                        .collect();
                    format!("{name}({})", params.join(","))
                }));
            }
        });
        out
    }

    fn some(s: &[&str]) -> Vec<Option<String>> {
        s.iter().map(|x| Some(x.to_string())).collect()
    }

    #[test]
    fn picks_the_overload_the_arguments_fit_best() {
        let src = "using System;\nclass A { void F(string s, object o, int i, long l) {\n\
            Console.WriteLine(s); Console.WriteLine(i); Console.WriteLine(l); Console.WriteLine(o);\n\
            Console.WriteLine(\"{0}\", i); Console.WriteLine(\"{0} {1} {2} {3}\", i, i, i, i);\n\
            s.StartsWith(\"x\"); s.StartsWith('x'); s.Equals(o); s.Equals(s); string.Compare(s, s);\n\
            s.IndexOf(\"x\", 3); int.Parse(s); Console.WriteLine(3); } }";
        assert_eq!(
            bound(src),
            some(&[
                "WriteLine(String)",
                "WriteLine(Int32)",
                "WriteLine(Int64)",
                "WriteLine(Object)",
                "WriteLine(String,Object)",
                "WriteLine(String,Object[])",
                "StartsWith(String)",
                "StartsWith(Char)",
                "Equals(Object)",
                "Equals(String)",
                "Compare(String,String)",
                "IndexOf(String,Int32)",
                "Parse(String)",
                "WriteLine(Int32)",
            ])
        );
    }

    #[test]
    fn local_methods_named_arguments_and_defaults() {
        let src = "class A {\n void M(int x, int y = 5) { }\n void M(string s) { }\n\
            void N(int a, params int[] rest) { }\n\
            static void S(long v) { }\n\
            void F() { M(1); M(1, y: 2); M(\"s\"); N(1); N(1, 2, 3); S(1); M(y: 1, x: 2); } }";
        assert_eq!(
            bound(src),
            some(&[
                "M(Int32,Int32)",
                "M(Int32,Int32)",
                "M(String)",
                "N(Int32,Int32[])",
                "N(Int32,Int32[])",
                "S(Int64)",
                "M(Int32,Int32)",
            ])
        );
    }

    #[test]
    fn extensions_constructors_and_what_stays_open() {
        let src = "using System;\nusing System.IO;\nusing System.Linq;\nusing System.Collections.Generic;\n\
            using System.Threading.Tasks;\n\
            class A { void F(List<string> names, Unknown u, string path) {\n\
            names.First(); new StreamReader(path); names.Select(n => n); u.Go(1); Go(names); Task.Run(() => 1); } }";
        assert_eq!(
            bound(src),
            vec![
                Some("First(Collections.Generic.IEnumerable`1<String>)".to_string()),
                Some(".ctor(String)".to_string()),
                // The lambda's one parameter rules out the overload taking an
                // index too; what it returns stays open.
                Some(
                    "Select(Collections.Generic.IEnumerable`1<String>,Func`2<String,Unknown>)"
                        .to_string()
                ),
                None,
                None,
                // Overloads taking lambdas without parameters: which one takes
                // what the lambda returns.
                None,
            ]
        );
    }

    #[test]
    fn constants() {
        let src = "class A { const int K = 3; enum E { P, Q = 5, R }\n\
            void F() { _ = 0x1F; _ = 1_000L; _ = -2; _ = 2.5f; _ = 'c'; _ = '\\n'; _ = \"a\\tb\"; _ = @\"x\"\"y\";\n\
            _ = null; _ = true; _ = K; _ = E.R; _ = System.StringSplitOptions.RemoveEmptyEntries; _ = int.MaxValue;\n\
            _ = default(int); _ = default(string); _ = (1); } }";
        let mut out = Vec::new();
        with_infer(src, |infer, root| {
            let mut stack = vec![root];
            let mut found = Vec::new();
            while let Some(n) = stack.pop() {
                if n.kind() == "assignment_expression" {
                    found.push(n.child_by_field_name("right").unwrap());
                }
                stack.extend(n.named_children(&mut n.walk()));
            }
            found.sort_by_key(|n| n.start_byte());
            out = found.into_iter().map(|n| infer.constant(n, None)).collect();
        });
        use Constant::*;
        assert_eq!(
            out,
            [
                Int(31),
                Int(1000),
                Int(-2),
                Float(2.5),
                Char('c'),
                Char('\n'),
                Str("a\tb".into()),
                Str("x\"y".into()),
                Null,
                Bool(true),
                Int(3),
                Int(6),
                Int(1),
                Int(i32::MAX as i128),
                Int(0),
                Null,
                Int(1),
            ]
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>()
        );
        assert!(Int(5).same(&Float(5.0)));
        assert!(!Int(5).same(&Str("5".into())));
    }
}
