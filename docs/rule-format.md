# Rule format and compatibility

DRL accepts one or more YAML documents with required `id`, `title`, and `detection` fields. `level`
defaults to `medium`; `condition` defaults to `selection`. IDs must be unique across a run.

The format uses Sigma's familiar logsource, selection, condition, modifier, status, reference,
false-positive, level, and ATT&CK tag concepts. It is not a claim of full Sigma backend
compatibility. In particular, DRL evaluates normalized event dictionaries directly and owns its
`correlation` block. Rules should be validated with `drl validate` before comparison with another
Sigma implementation.

## Selection rules

- Fields in one mapping are ANDed.
- A list of mappings is ORed.
- A list of expected field values defaults to any; `|all` requires every value.
- Comparisons are case-insensitive except regular-expression semantics selected by the pattern.
- Nested fields and flattened dotted fields are both readable.
- Missing fields fail comparisons except `|exists: false`.

## Condition grammar

```text
expression := or-expression
or         := and ("or" and)*
and        := unary ("and" unary)*
unary      := "not" unary | primary
primary    := NAME | "(" expression ")" | ("1" | "all") "of" GLOB
```

Unsupported punctuation, unknown names, empty glob groups, and incomplete parentheses fail closed.

## Correlation

Threshold requires `count`; sequence requires at least two valid `ordered` selection names.
`timespan` accepts seconds or a number plus `s`, `m`, `h`, or `d`, capped at 365 days. Missing group
fields use the explicit `<missing>` value, keeping behavior visible rather than silently dropping an
event.

