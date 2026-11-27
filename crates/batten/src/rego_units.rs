//! [`crate::facts::Fact::Units`] for Rego: each module's functions and the `:=`
//! bindings whose right side can be undefined by its shape, as D4 nodes,
//! through regorus's own parse (CLOUD-1008, CLOUD-2777).
//!
//! Pointers, never the AST: a `function` node says whether the helper is
//! TOTAL (it has a `default` or an `else` body, so a call to it always yields a
//! value), and a `binding` node says that a `:=` in some body binds a call of a
//! named function (`name`), a lookup (`counts.lookup`), or `_`
//! (`counts.wildcard`). Those facts are what a preset needs to refuse a `:=`
//! regorus's RVM binds as Undefined where the interpreter fails the body
//! (CLOUD-2777), and nothing here decides it: the `rego-hygiene` preset does.
//!
//! A module regorus refuses is could-not-look, never an empty node list.

use serde_json::{Value, json};

/// The units of one Rego module, or `None` when regorus refused it.
#[must_use]
pub fn units(path: &str, text: &str) -> Option<Vec<Value>> {
    let mut engine = regorus::Engine::new();
    engine.add_policy(path.to_owned(), text.to_owned()).ok()?;
    let json = engine.get_ast_as_json().ok()?;
    let mut policies: Vec<Value> = serde_json::from_str(&json).ok()?;
    let ast = policies.pop()?.get("ast")?.clone();
    let rules = ast.get("rules")?.as_array()?;

    // A helper is total when any rule of its name is a `default`, or any of its
    // bodies is an `else`.
    let mut total: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut functions: Vec<(String, usize)> = Vec::new();
    for rule in rules {
        if let Some(default) = rule.get("Default") {
            if let Some(name) = var_name(default.get("refr")) {
                total.insert(name);
            }
            continue;
        }
        let Some(spec) = rule.get("Spec") else {
            continue;
        };
        let Some(func) = spec.get("head").and_then(|head| head.get("Func")) else {
            continue;
        };
        let Some(name) = var_name(func.get("refr")) else {
            continue;
        };
        let has_else = spec
            .get("bodies")
            .and_then(Value::as_array)
            .is_some_and(|bodies| {
                bodies
                    .iter()
                    .any(|body| body.get("is_else").and_then(Value::as_bool) == Some(true))
            });
        if has_else {
            total.insert(name.clone());
        }
        functions.push((name, first_line(rule).unwrap_or(0)));
    }

    let mut nodes: Vec<Value> = functions
        .iter()
        .map(|(name, line)| {
            json!({
                "kind": "function",
                "position": "rule",
                "line": line,
                "name": name,
                "counts": {"total": total.contains(name)},
            })
        })
        .collect();
    let mut bindings = Vec::new();
    collect_bindings(&Value::Array(rules.clone()), &mut bindings);
    nodes.extend(bindings.into_iter().map(|binding| {
        json!({
            "kind": "binding",
            "position": "body",
            "line": binding.line,
            "name": binding.callee.unwrap_or_default(),
            "counts": {"wildcard": binding.wildcard, "lookup": binding.lookup},
        })
    }));
    Some(nodes)
}

/// The name a `{"Var": {"value": …}}` reference spells.
fn var_name(refr: Option<&Value>) -> Option<String> {
    refr?.get("Var")?.get("value")?.as_str().map(str::to_owned)
}

/// The first line any span inside `node` names: regorus attaches spans to
/// tokens, and the earliest one is where the construct starts.
fn first_line(node: &Value) -> Option<usize> {
    match node {
        Value::Object(map) => {
            let here = map
                .get("line")
                .and_then(Value::as_u64)
                .and_then(|line| usize::try_from(line).ok());
            map.values().filter_map(first_line).chain(here).min()
        }
        Value::Array(items) => items.iter().filter_map(first_line).min(),
        _ => None,
    }
}

/// One `:=` whose right side's definedness is a question of its shape
/// ([`collect_bindings`]).
struct Binding {
    /// The bare-named function the right side calls, when it is a call.
    callee: Option<String>,
    /// The left side is a bare `_`: the statement asserts only that the right
    /// side is defined, which is the check the bytecode drops.
    wildcard: bool,
    /// The right side is a lookup (`a.b`, `a[k]`), undefined where the key is.
    lookup: bool,
    line: usize,
}

/// Every `:=` that calls a bare-named function, is a lookup, or binds `_`,
/// with its line. Any other right side (a literal, a variable, a
/// comprehension, a dotted builtin) is not reported: its definedness is not a
/// question of its shape.
fn collect_bindings(node: &Value, out: &mut Vec<Binding>) {
    match node {
        Value::Object(map) => {
            if let Some(assign) = map.get("AssignExpr")
                && assign.get("op").and_then(Value::as_str) == Some("ColEq")
            {
                let rhs = assign.get("rhs");
                let callee = rhs
                    .and_then(|rhs| rhs.get("Call"))
                    .and_then(|call| var_name(call.get("fcn")));
                let lookup = rhs.is_some_and(|rhs| {
                    rhs.get("RefDot").is_some() || rhs.get("RefBrack").is_some()
                });
                let wildcard = var_name(assign.get("lhs")).as_deref() == Some("_");
                if callee.is_some() || lookup || wildcard {
                    out.push(Binding {
                        callee,
                        wildcard,
                        lookup,
                        line: first_line(assign).unwrap_or(0),
                    });
                }
            }
            for value in map.values() {
                collect_bindings(value, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_bindings(item, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const MODULE: &str = "package p

import rego.v1

default total(_) := \"\"

total(args) := m if {
\tsome m in args
}

subject(args) := message if {
\tsome i, word in args
\tword == \"-m\"
\tmessage := args[i + 1]
}

violation contains \"x\" if {
\tmessage := subject(input.argv)
\tt := total(input.argv)
\tnot startswith(message, \"feat\")
}
";

    /// Fails by: a defaulted helper read as partial, a partial one read as
    /// total, or a `:=` bound to a call missed or attributed to the wrong
    /// callee or line.
    #[test]
    fn functions_carry_totality_and_bindings_their_callee() {
        let nodes = units("p.rego", MODULE).expect("regorus parses it");
        let functions: Vec<_> = nodes
            .iter()
            .filter(|node| node["kind"] == "function")
            .map(|node| {
                (
                    node["name"].as_str().unwrap(),
                    node["counts"]["total"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(functions, [("total", true), ("subject", false)]);
        let bindings: Vec<_> = nodes
            .iter()
            .filter(|node| node["kind"] == "binding")
            .map(|node| {
                (
                    node["name"].as_str().unwrap(),
                    node["line"].as_u64().unwrap(),
                )
            })
            .collect();
        // `message := args[i + 1]` is a lookup, so it is a binding with no callee.
        assert_eq!(bindings, [("", 14), ("subject", 18), ("total", 19)]);
        let lookup = nodes
            .iter()
            .find(|node| node["kind"] == "binding" && node["line"] == 14)
            .expect("the lookup binding");
        assert_eq!(lookup["counts"], json!({"wildcard": false, "lookup": true}));
    }

    /// Fails by: `_ := e` not reported, or `=` (which keeps the guard on both
    /// evaluators) or a literal right side reported as a binding.
    #[test]
    fn a_wildcard_binding_is_reported_and_unification_is_not() {
        let module = "package p\n\nimport rego.v1\n\nv if {\n\t_ := input.a\n\t_ = input.b\n\tx := 1\n\tx == 1\n}\n";
        let nodes = units("p.rego", module).expect("parses");
        let bindings: Vec<_> = nodes
            .iter()
            .filter(|node| node["kind"] == "binding")
            .map(|node| (node["line"].as_u64().unwrap(), node["counts"].clone()))
            .collect();
        assert_eq!(bindings, [(6, json!({"wildcard": true, "lookup": true}))]);
    }

    /// Fails by: an `else` body not counted as making the helper total.
    #[test]
    fn an_else_body_makes_a_helper_total() {
        let module = "package p\n\nimport rego.v1\n\nf(x) := 1 if { x == 1 } else := 0\n";
        let nodes = units("p.rego", module).expect("parses");
        let first = nodes.first().expect("one node");
        assert_eq!(first["counts"]["total"], true);
    }

    /// Fails by: a module regorus refuses read as empty and clean.
    #[test]
    fn a_module_that_does_not_parse_is_could_not_look() {
        assert!(units("p.rego", "package").is_none());
    }

    /// Fails by: a span inside an array skipped, so a construct whose earliest
    /// token sits in a list is placed at a later line.
    #[test]
    fn the_first_line_reads_spans_inside_arrays() {
        let node = json!({"line": 5, "args": [{"line": 7}, {"span": {"line": 3}}]});
        assert_eq!(first_line(&node), Some(3));
        assert_eq!(first_line(&json!([{"line": 4}, {"line": 2}])), Some(2));
    }
}
