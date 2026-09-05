//! `Reduce::Each` — the list-side reduction (CLOUD-1380).
//!
//! **The tier that proves the ENGINE builds what the row declares**, which is the
//! half a hand-built `ResultRow` cannot reach. Every case here deserializes its
//! row from TOML through the same `serde` path `batten.toml` is loaded by, so a
//! variant the config surface will not accept fails here rather than passing over
//! a struct this file constructed. `.claude/rules/policy-modules.md` states the
//! general form of that trap: a fixture that fabricates the shape passes over a
//! key nothing fills.
//!
//! The payload side is driven through [`mcp::payload`] from response text rather
//! than from a `serde_json::json!` literal, for the same reason one level down:
//! `payload` is what unframes a server's content blocks, and a case that skipped
//! it would assert the reduction over a tree the dispatch path never produces.

use batten::mcp::{self, Reduce, ResultRow};

/// The row as a consumer writes it, parsed by the config surface's own path.
fn row(toml_text: &str) -> ResultRow {
    toml::from_str(toml_text).expect("the config surface accepts this row")
}

/// A `tools/call` result framing `document` the way a connector frames one.
fn framed(document: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": document.to_string() }]
    })
}

/// The shape a tracker's list response actually has: a page beside its paging.
///
/// **Every element carries fields the row does NOT declare**, and that is the
/// fixture's whole point rather than incidental realism. A page whose elements
/// carry exactly the declared set has nothing for the projection to drop, so the
/// size arm below measures equal and the reduction looks worthless — which is
/// what this fixture did in its first form, and is a test asserting its own
/// premise rather than the property. The measured defect was a payload whose
/// elements carry some thirty fields against a row declaring eight.
fn page() -> serde_json::Value {
    serde_json::json!({
        "cursor": "eyJvIjoyfQ",
        "hasNextPage": true,
        "issues": [
            {
                "id": "CLOUD-1",
                "title": "first",
                "status": "Todo",
                "createdAt": "2026-09-01T00:00:00.000Z",
                "assignee": "someone@example.test",
                "labels": ["one", "two"],
                "team": "Some Team",
                "estimate": 3,
            },
            // NO `status`, which is the second arm's subject: a field the row
            // declares and this element does not carry.
            {
                "id": "CLOUD-2",
                "title": "second",
                "createdAt": "2026-09-02T00:00:00.000Z",
                "assignee": "another@example.test",
                "labels": [],
                "team": "Some Team",
                "estimate": 5,
            },
        ],
    })
}

const LIST_ROW: &str = r#"
method = "list_issues"
reduce = "each"
node = "issues"
fields = ["id", "title", "status"]
"#;

#[test]
fn the_config_surface_accepts_the_each_variant() {
    // The row is only reachable if `each` deserializes. Asserted on its own,
    // because every case below would fail identically on a parse error and none
    // of them would say that is what happened.
    let parsed = row(LIST_ROW);
    assert_eq!(parsed.reduce, Reduce::Each);
    assert_eq!(parsed.node, "issues");
}

#[test]
fn an_array_result_reduces_to_one_projected_object_per_element() {
    // Arm 1 of CLOUD-1380 §7. Before `Reduce::Each` existed this could not be
    // written at all: naming `issues` as `node` made every field lookup miss and
    // the projection came back empty, which is the `array-result-reported-
    // undeclared` mutation this suite is declared against.
    let payload = mcp::payload(&framed(&page()));
    let reduced = mcp::reduce(&row(LIST_ROW), &payload.value).expect("the row reaches its node");

    let issues = reduced
        .get("issues")
        .and_then(serde_json::Value::as_array)
        .expect("the projected elements come back under the array's own key");
    assert_eq!(issues.len(), 2, "one projected object per element");
    assert_eq!(
        issues[0],
        serde_json::json!({ "id": "CLOUD-1", "title": "first", "status": "Todo" }),
        "every declared field the element carries is projected"
    );
}

#[test]
fn a_field_an_element_does_not_carry_is_absent_rather_than_null() {
    // Arm 2. `reduce`'s existing contract for a whole payload, held per element:
    // "the payload does not carry this" and "the reduction dropped it" are
    // different answers, and a caller acts on the second. A `null` here would
    // make a row with no status indistinguishable from one whose status the
    // projection lost.
    let payload = mcp::payload(&framed(&page()));
    let reduced = mcp::reduce(&row(LIST_ROW), &payload.value).expect("the row reaches its node");
    let issues = reduced["issues"].as_array().expect("an array");

    let second = issues[1].as_object().expect("an object");
    assert!(
        !second.contains_key("status"),
        "an absent field is omitted, never emitted as null: {second:?}"
    );
    assert_eq!(second.len(), 2, "and nothing else was invented for it");
}

#[test]
fn a_scalar_sibling_survives_so_paging_stays_answerable() {
    // Arm 3, and the one that discriminates a lazy implementation: a variant
    // returning ONLY the projected array passes both arms above and silently
    // breaks paging. `hasNextPage` and `cursor` are what make the page size a
    // thing the caller controls, and this arm's bound IS the page.
    let payload = mcp::payload(&framed(&page()));
    let reduced = mcp::reduce(&row(LIST_ROW), &payload.value).expect("the row reaches its node");

    assert_eq!(reduced.get("hasNextPage"), Some(&serde_json::json!(true)));
    assert_eq!(
        reduced.get("cursor"),
        Some(&serde_json::json!("eyJvIjoyfQ")),
        "the cursor is what asks for the rest of the page"
    );
}

#[test]
fn the_reduction_is_smaller_than_the_payload_it_reduces() {
    // CLOUD-1380's acceptance, as a COMPARISON rather than against a fixed
    // number: the measured defect was `emitted 20,366` against `stored 17,313`,
    // more out than in, because an undeclared result is re-serialised whole.
    let document = page();
    let payload = mcp::payload(&framed(&document));
    let reduced = mcp::reduce(&row(LIST_ROW), &payload.value).expect("the row reaches its node");

    let emitted = serde_json::to_string(&reduced)
        .expect("the reduction serialises")
        .len();
    let stored = document.to_string().len();
    assert!(
        emitted < stored,
        "a reduction must emit fewer bytes than it stores: {emitted} >= {stored}"
    );
}

#[test]
fn a_node_that_is_not_a_list_is_could_not_look_and_never_an_empty_page() {
    // THE ANTI-VACUITY ARM. An empty page is an ordinary answer, so a broken row
    // reducing to `[]` would be byte-identical to a genuinely empty search on the
    // decision surface — the exact conflation `reduce`'s own doc refuses for a
    // node it cannot reach. `None` is what the caller reports as could-not-look
    // and answers by passing the response through whole.
    let not_a_list = serde_json::json!({ "issues": { "id": "CLOUD-1" } });
    let payload = mcp::payload(&framed(&not_a_list));
    assert_eq!(
        mcp::reduce(&row(LIST_ROW), &payload.value),
        None,
        "a `node` naming a map is could-not-look, never an empty projection"
    );
}

#[test]
fn an_empty_page_still_reduces_because_it_is_a_real_answer() {
    // The other side of the case above, which is what keeps it discriminating: a
    // genuinely empty array IS a list, so it reduces to an empty projection with
    // its paging intact rather than to could-not-look. A search that found
    // nothing is the answer `filing-needs-a-search` acts on.
    let empty = serde_json::json!({ "hasNextPage": false, "issues": [] });
    let payload = mcp::payload(&framed(&empty));
    let reduced = mcp::reduce(&row(LIST_ROW), &payload.value).expect("an empty page is an answer");

    assert_eq!(reduced["issues"], serde_json::json!([]));
    assert_eq!(reduced.get("hasNextPage"), Some(&serde_json::json!(false)));
}

#[test]
fn the_other_two_arms_are_untouched_by_the_new_variant() {
    // CLOUD-1380 §2's "deliberately not in scope": `get_issue` and `save_issue`
    // must emit byte-identical output to today. A shared `reduce` is exactly
    // where that would break silently, so it is asserted rather than assumed.
    let document = serde_json::json!({ "id": "CLOUD-1", "status": "Todo", "body": "x" });
    let payload = mcp::payload(&framed(&document));

    let projected = mcp::reduce(
        &row("method = \"get_issue\"\nreduce = \"project\"\nfields = [\"id\", \"status\"]\n"),
        &payload.value,
    )
    .expect("the project row still reduces");
    assert_eq!(
        serde_json::Value::Object(projected),
        serde_json::json!({ "id": "CLOUD-1", "status": "Todo" })
    );

    let acknowledged = mcp::reduce(
        &row("method = \"save_issue\"\nreduce = \"acknowledge\"\nfields = [\"id\", \"status\"]\n"),
        &payload.value,
    )
    .expect("the acknowledge row still reduces");
    assert_eq!(
        serde_json::Value::Object(acknowledged),
        serde_json::json!({ "id": "CLOUD-1", "status": "Todo" })
    );
}

#[test]
fn this_repositorys_own_list_issues_row_loads_and_declares_each() {
    // The committed row, read from the tree rather than from a fixture: the
    // engine change and the consumer row are two halves of one deliverable, and a
    // variant no committed row raises is the dead-gate class
    // `.claude/rules/policy-modules.md` records for presets.
    let text = std::fs::read_to_string(crate::common::at_root("batten.toml"))
        .expect("the committed authority is readable");
    let config: toml::Value = toml::from_str(&text).expect("batten.toml parses");

    let rows = config
        .get("mcp")
        .and_then(|mcp| mcp.get("result"))
        .and_then(toml::Value::as_array)
        .expect("the `[[mcp.result]]` table is declared");

    let list = rows
        .iter()
        .find(|row| row.get("method").and_then(toml::Value::as_str) == Some("list_issues"))
        .expect("`list_issues` has a row (CLOUD-1380)");

    assert_eq!(
        list.get("reduce").and_then(toml::Value::as_str),
        Some("each")
    );
    assert_eq!(
        list.get("node").and_then(toml::Value::as_str),
        Some("issues")
    );

    // The field set is not free to choose: `graph-check` reads these, and
    // CLOUD-1151's wave ports it onto the capture store. A projection trimmed for
    // size alone would leave that gate unjudgeable rather than red.
    let fields: Vec<&str> = list["fields"]
        .as_array()
        .expect("fields is an array")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    for needed in [
        "id",
        "status",
        "description",
        "projectMilestone",
        "parentId",
    ] {
        assert!(
            fields.contains(&needed),
            "`{needed}` is read by graph-check's port and must survive the projection"
        );
    }
}

#[test]
fn an_undeclared_scalar_sibling_is_not_emitted() {
    // CodeRabbit on #879, and it is rule 4 decided by a byte count. The sibling
    // walk kept every scalar beside the array that was non-empty and under
    // `TOKEN_MAX` — but bounded-and-scalar is a SIZE test, not an authorization,
    // and the row's `fields` declare an ELEMENT, so nothing in a consumer's config
    // covers the envelope at all. A connector putting `account_email` beside its
    // page had it emitted on the strength of being short.
    //
    // The allowlist is what makes the envelope a reviewable set. Adding a paging
    // key is a diff; a server adding a field is not.
    let mut document = page();
    let map = document.as_object_mut().expect("the page is an object");
    map.insert(
        "account_email".to_owned(),
        serde_json::json!("someone@example.test"),
    );
    map.insert("workspaceId".to_owned(), serde_json::json!("ws-1"));

    let payload = mcp::payload(&framed(&document));
    let reduced = mcp::reduce(&row(LIST_ROW), &payload.value).expect("the row reaches its node");

    assert!(
        !reduced.contains_key("account_email"),
        "an undeclared sibling must not ride out on the envelope: {reduced:?}"
    );
    assert!(!reduced.contains_key("workspaceId"));

    let rendered = serde_json::to_string(&reduced).expect("the reduction renders");
    assert!(
        !rendered.contains("someone@example.test"),
        "and it must not appear anywhere in the rendered reduction"
    );

    // THE ANTI-VACUITY HALF, in the same case because the two are one property:
    // an allowlist that dropped the paging keys too would pass every assertion
    // above and silently break paging, which arm 3 exists to prevent.
    assert_eq!(reduced.get("hasNextPage"), Some(&serde_json::json!(true)));
    assert_eq!(
        reduced.get("cursor"),
        Some(&serde_json::json!("eyJvIjoyfQ"))
    );
}
