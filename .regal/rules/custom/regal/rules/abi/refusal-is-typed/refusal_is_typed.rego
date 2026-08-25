# METADATA
# description: |
#   A refusal is `{rule, verdict, subjects}`; `msg` is retired and a verdict is a
#   NAME (CLOUD-1050).
#
#   WHY THIS EXISTS BESIDE A LOAD-TIME REFUSAL, which is strictly stronger where
#   it applies. `policy::load` reads the compiled AST and refuses both shapes, but
#   it only ever sees modules a `[[rule]]` row ENABLES. A module written and not
#   yet registered — the ordinary state of one mid-authoring, and the state every
#   module in a `bundle` root is in before the row lands — is invisible to it.
#   This rule reads the corpus, so it covers the file the day it is written rather
#   than the day it is enabled.
#
#   TWO SHAPES, ONE ARGUMENT. `"msg": "..."` is the retired key: the decoder no
#   longer reads it, so a module carrying it loads clean, evaluates clean and
#   reports NOTHING — a dead gate and a clean tree being byte-identical on the
#   decision surface. `"verdict": sprintf(...)` is a class no reader can look up
#   and no registry can be held to; the whole point of a token is that being told
#   it twice is being told the same thing twice, and a composed one cannot promise
#   that.
#
#   `test_` RULES ARE EXEMPT, and it is a real case rather than a hatch: a
#   module's own test may legitimately construct a violation object to compare
#   against, including one pinning a token that is being retired. The prefix is
#   the one `policy test` already keys on, so no second convention is introduced.
package custom.regal.rules.abi["refusal-is-typed"]

import data.regal.ast
import data.regal.result

# METADATA
# description: the retired `msg` key, and a composed `verdict`
report contains violation if {
	some rule in input.rules
	publishes_a_refusal(rule)
	some node in object_terms(rule)
	some pair in node.value
	pair[0].type == "string"
	pair[0].value == "msg"
	violation := result.fail(rego.metadata.chain(), result.location(rule.head))
}

report contains violation if {
	some rule in input.rules
	publishes_a_refusal(rule)
	some node in object_terms(rule)
	some pair in node.value
	pair[0].type == "string"
	pair[0].value == "verdict"
	pair[1].type != "string"
	violation := result.fail(rego.metadata.chain(), result.location(rule.head))
}

# A rule that PUBLISHES a refusal: `violation` or `deny`, and not a test.
#
# THE NARROWING IS NOT TIDINESS — it is this rule's own first firing, caught by
# running it over the corpus. `policy/verdict-routes-resolve.rego` has a helper
# projecting the registry's routes, and one of its keys is legitimately named
# `verdict` and legitimately bound to a variable. Judged as a refusal that is a
# composed token; judged as what it is, it is a projection with a well-chosen
# field name. A gate whose first firing is a false positive gets an exception
# written for it, and the exception is what rots.
#
# What the narrowing costs, stated: a module that builds its refusal object in a
# HELPER and yields it from `violation` is not judged here. That is could-not-look
# rather than a pass — the load-time check has the same bound and for the same
# reason — and the honest answer is that neither reader follows a value across a
# rule boundary.
publishes_a_refusal(rule) if {
	not is_test(rule)
	ast.ref_to_string(rule.head.ref) in {"violation", "deny"}
}

# A rule the module wrote as one of its own tests.
#
# `ast.ref_to_string` rather than reading `head.ref[0].value` directly, because a
# rule head is a REF and the first term's spelling differs between a bare name
# and a dotted one — the same shape difference `every-package-binds-input`
# records having been caught by twice.
is_test(rule) if startswith(ast.ref_to_string(rule.head.ref), "test_")

# Every object literal anywhere inside a rule.
#
# `walk` rather than a hand-written descent: an object literal can be nested in a
# comprehension, a function argument or another object, and a reader that knew
# only the top level would pass over exactly the module that hid one.
#
# THE RELATION FORM, `walk(x, [path, value])`, not `some pair in walk(x)`. The
# second spelling iterates the ELEMENTS of the returned pair rather than the
# pairs themselves, so `node` binds to a path or to a value and never to a term —
# it matches nothing and reports a clean corpus. Found by the two positive cases
# below failing while the five negative ones passed, which is exactly the
# asymmetry a suite with no positive arm would have shipped.
object_terms(rule) := {node |
	walk(rule, [_, node])
	is_object(node)
	node.type == "object"
	is_array(node.value)
}
