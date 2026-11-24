use crate::config_check::record::safe_component;
use crate::error::UsageError;

use crate::rest::Query;
use anyhow::Result;

/// The forge's own ceiling on a page, which it CLAMPS to silently.
///
/// A declared `per_page` above it would make every full page look short, and a
/// short page is the walk's end-of-collection signal where no count is stated —
/// so the walk would stop after one page and call the prefix whole.
pub const MAX_PER_PAGE: u32 = 100;

/// The placeholders the engine binds itself, which `--input` may not supply.
///
/// `owner` and `repo` come from the checkout's forge remote and `since` from the
/// producer's clock. Letting a caller bind them would let a record claim a
/// repository or a window nobody resolved.
pub(crate) const RESERVED: [&str; 3] = ["owner", "repo", "since"];

/// One piece of a template: literal text, or a `{name}` to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Piece<'a> {
    Literal(&'a str),
    Name(&'a str),
}

/// A placeholder name: ASCII letters, digits, `_` and `-`.
pub(crate) fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Split a template into literal text and placeholders.
///
/// # Errors
///
/// A message naming the fault — an unclosed `{`, a stray `}`, or a malformed
/// name — never the template's surrounding text beyond the name itself.
pub(crate) fn pieces(template: &str) -> std::result::Result<Vec<Piece<'_>>, String> {
    let mut found = Vec::new();
    let mut rest = template;
    while !rest.is_empty() {
        let Some(open) = rest.find('{') else {
            if rest.contains('}') {
                return Err(String::from("carries a `}` that closes no placeholder"));
            }
            found.push(Piece::Literal(rest));
            break;
        };
        let (literal, tail) = rest.split_at(open);
        if literal.contains('}') {
            return Err(String::from("carries a `}` that closes no placeholder"));
        }
        if !literal.is_empty() {
            found.push(Piece::Literal(literal));
        }
        let tail = &tail[1..];
        let Some(close) = tail.find('}') else {
            return Err(String::from("opens a placeholder it never closes"));
        };
        let name = &tail[..close];
        if !is_name(name) {
            return Err(format!(
                "names a placeholder `{{{name}}}` that is not letters, digits, `_` or `-`"
            ));
        }
        found.push(Piece::Name(name));
        rest = &tail[close + 1..];
    }
    Ok(found)
}

/// The placeholders a row's templates name, endpoint and parameter values both.
///
/// Callable only on a row that already validated; an unparseable template
/// contributes nothing rather than failing twice.
pub(crate) fn placeholders(query: &Query) -> std::collections::BTreeSet<&str> {
    std::iter::once(query.endpoint.as_str())
        .chain(query.params.values().map(String::as_str))
        .filter_map(|template| pieces(template).ok())
        .flatten()
        .filter_map(|piece| match piece {
            Piece::Name(name) => Some(name),
            Piece::Literal(_) => None,
        })
        .collect()
}

/// A dot-separated field path's segments, or `None` where one is empty.
pub(crate) fn segments(path: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = path.split('.').collect();
    (!path.is_empty() && parts.iter().all(|part| !part.is_empty())).then_some(parts)
}

/// Prove every `[[forge.query]]` row well formed, and that a `[[record]]` row
/// declares the family each one writes (CLOUD-253's obligation).
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for the first row that could never run as
/// written, naming the row and the key. Each refusal is a row that would load
/// clean and then fail — or worse, succeed — at fetch time: an id that escapes
/// the store, a placeholder nothing can bind, a page size the forge clamps, a
/// reduction that keeps nothing, or a family no module can read.
pub fn validate(queries: &[Query], families: &[crate::config_model::RecordDeclared]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for query in queries {
        let id = query.id.as_str();
        safe_component("`[[forge.query]]` id", id)?;
        let refuse = |why: String| UsageError::raise(format!("forge query `{id}`: {why}"));
        if !seen.insert(id) {
            return Err(refuse(String::from(
                "is declared twice; one query writes one family",
            )));
        }
        validate_endpoint(&query.endpoint).map_err(|why| refuse(format!("`endpoint` {why}")))?;
        for (name, template) in &query.params {
            if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(refuse(String::from(
                    "a `params` key is empty or not printable",
                )));
            }
            if name == "page" || name == "per_page" {
                return Err(refuse(format!(
                    "`params.{name}` is the walk's own; set `per_page`/`max_pages` instead"
                )));
            }
            pieces(template).map_err(|why| refuse(format!("`params.{name}` {why}")))?;
        }
        if query.rows.as_deref().is_some_and(str::is_empty) {
            return Err(refuse(String::from(
                "`rows` is empty; omit it for a bare array, or name the key the rows are under",
            )));
        }
        if !(1..=MAX_PER_PAGE).contains(&query.per_page) {
            return Err(refuse(format!(
                "`per_page` must be 1..={MAX_PER_PAGE}; the forge clamps above that, and a clamped \
                 page reads as the last one"
            )));
        }
        if query.max_pages == 0 {
            return Err(refuse(String::from(
                "`max_pages` is 0, so the walk could read nothing",
            )));
        }
        validate_select(&query.select).map_err(refuse)?;
        let named = placeholders(query);
        match &query.since {
            Some(since) => {
                if segments(&since.field).is_none() {
                    return Err(refuse(String::from(
                        "`since.field` is not a dot-separated field path",
                    )));
                }
                if since.seconds == 0 {
                    return Err(refuse(String::from(
                        "`since.seconds` is 0, so the window holds nothing",
                    )));
                }
            }
            None if named.contains("since") => {
                return Err(refuse(String::from(
                    "a template names `{since}` but the row declares no `since` window to bind it",
                )));
            }
            None => {}
        }
        if !families.iter().any(|family| family.record == id) {
            return Err(refuse(format!(
                "writes the record family `{id}`, which no `[[record]]` row declares, so no module \
                 could read it"
            )));
        }
        validate_derived(query, queries, &named).map_err(refuse)?;
    }
    Ok(())
}

/// A row's fan-out and spans: every name they add to a recorded row is one no
/// other key of that row already holds, and every path they read is well formed.
pub(crate) fn validate_derived(
    query: &Query,
    queries: &[Query],
    named: &std::collections::BTreeSet<&str>,
) -> std::result::Result<(), String> {
    let mut keys: std::collections::BTreeSet<&str> =
        query.select.iter().map(String::as_str).collect();
    if let Some(each) = &query.each {
        if each.query == query.id {
            return Err(String::from(
                "`each.query` names this row itself, whose record the walk is about to replace",
            ));
        }
        let Some(source) = queries.iter().find(|other| other.id == each.query) else {
            return Err(format!(
                "`each.query` names `{}`, which no `[[forge.query]]` row declares",
                each.query
            ));
        };
        // THE MEMBER IS READ OFF THE RECORDED ROW, which carries the source's
        // `select` paths as its keys, spelled as declared — so a field the source
        // never selected is a member no walk could ever find, refused here rather
        // than read at run time as could-not-look.
        if !source.select.iter().any(|path| path == &each.field) {
            return Err(format!(
                "`each.field` `{}` is not one of `{}`'s `select` paths, which are the only keys its recorded rows carry",
                each.field, each.query
            ));
        }
        if !is_name(&each.input) || RESERVED.contains(&each.input.as_str()) {
            return Err(String::from(
                "`each.input` must be a placeholder name the engine does not bind itself",
            ));
        }
        if !named.contains(each.input.as_str()) {
            return Err(format!(
                "`each.input` binds `{{{}}}`, which no template of this row names",
                each.input
            ));
        }
        if !keys.insert(each.input.as_str()) {
            return Err(String::from(
                "`each.input` is also a `select` path, so a recorded row would carry one key twice",
            ));
        }
    }
    for span in &query.span {
        if !is_name(&span.name) {
            return Err(String::from(
                "a `span.name` is not letters, digits, `_` or `-`",
            ));
        }
        if !keys.insert(span.name.as_str()) {
            return Err(format!(
                "`span.name` `{}` is already a key of the recorded row",
                span.name
            ));
        }
        let unreadable = |path: &str| segments(path).is_none();
        if unreadable(&span.from) || span.to.as_deref().is_some_and(unreadable) {
            return Err(format!(
                "span `{}` reads an instant at a path that is not dot-separated",
                span.name
            ));
        }
    }
    Ok(())
}

/// An endpoint template's own rules, beyond the placeholder grammar.
///
/// API-relative and path-only, for [`crate::rest::get`]'s contract: a leading
/// slash doubles and 404s, and a query string belongs in `params`, where it is
/// encoded. The literal text is held to a path's safe characters so nothing the
/// transport would have to escape can hide in it.
pub(crate) fn validate_endpoint(endpoint: &str) -> std::result::Result<(), String> {
    if endpoint.is_empty() {
        return Err(String::from("is empty"));
    }
    if endpoint.starts_with('/') {
        return Err(String::from(
            "starts with `/`; it is API-relative, and a rooted path doubles the slash and 404s",
        ));
    }
    for piece in pieces(endpoint)? {
        if let Piece::Literal(text) = piece
            && !text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_.~-".contains(&byte))
        {
            return Err(String::from(
                "carries a character outside a path's letters, digits and `/_.~-`; a query \
                 string belongs in `params`",
            ));
        }
    }
    Ok(())
}

/// The reduction's own rules: non-empty, every path well formed, none twice.
pub(crate) fn validate_select(select: &[String]) -> std::result::Result<(), String> {
    if select.is_empty() {
        return Err(String::from(
            "`select` keeps no field; the whole row is never recorded (rule 4), so the \
             reduction must say what it keeps",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for path in select {
        if segments(path).is_none() {
            return Err(String::from(
                "a `select` entry is not a dot-separated field path",
            ));
        }
        if !seen.insert(path.as_str()) {
            return Err(String::from("a `select` entry is listed twice"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn query(text: &str) -> Query {
        toml::from_str(text).unwrap()
    }

    /// Fails by: a reserved placeholder, or a word no template can spell,
    /// admitted as a fan-out's input.
    #[test]
    fn an_each_input_must_be_a_name_the_engine_does_not_bind() {
        let source = query(
            "id = \"heads\"\nendpoint = \"x\"\nper_page = 1\nmax_pages = 1\nselect = [\"sha\"]\n",
        );
        let derived = |input: &str| {
            query(&format!(
                "id = \"tips\"\nendpoint = \"y\"\nper_page = 1\nmax_pages = 1\n\
                 select = [\"date\"]\neach = {{ query = \"heads\", field = \"sha\", input = \"{input}\" }}\n"
            ))
        };
        for input in ["owner", "a.b", "tip"] {
            let row = derived(input);
            let named = std::iter::once(input).collect();
            let verdict = validate_derived(&row, &[source.clone(), row.clone()], &named);
            if input == "tip" {
                assert_eq!(verdict, Ok(()));
            } else {
                assert_eq!(
                    verdict,
                    Err(String::from(
                        "`each.input` must be a placeholder name the engine does not bind itself"
                    )),
                    "{input}"
                );
            }
        }
    }
}
