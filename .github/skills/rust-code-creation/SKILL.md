
## `.github/skills/rust-code-creation/SKILL.md`

```md
---
name: rust-code-creation
description: Create or modify Rust library and CLI code. Use this for implementing features, fixing bugs, refactoring, adding tests, or updating CLI behavior in this Rust repo.
---

# Rust Code Creation Skill

Implement changes as a careful Rust maintainer.

## Workflow

1. Inspect the existing crate structure before editing.
2. Identify whether the change belongs in the library, CLI, tests, or docs.
3. Make the smallest coherent change.
4. Add or update tests for behavior changes.
5. Update README or help text if CLI behavior changes.
6. Run or recommend the standard quality gates.

## Design rules

- Put reusable behavior in the library.
- Keep CLI code thin.
- Preserve public API unless explicitly asked to change it.
- Preserve existing error-handling style.
- Do not add dependencies unless they clearly reduce risk or complexity.
- Prefer simple functions over large generic abstractions.
- Make edge cases explicit.

## Error handling

- Library code should return structured errors.
- CLI code should convert errors into clear user-facing messages.
- Do not leak secrets or internal debug details in normal CLI output.
- Avoid `unwrap`, `expect`, and `panic!` except in tests or documented invariants.

## Tests

For new behavior, add tests that cover:

- Normal success case.
- Invalid input.
- Important edge cases.
- Platform-sensitive behavior when relevant.

Prefer focused unit tests for library logic and integration tests for CLI behavior.

## Final response format

When done, summarize:

```md
## Changed

- ...

## Tests

- Ran: ...
- Not run: ...

## Notes

- ...