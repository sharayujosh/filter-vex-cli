---
name: rust-code-review
description: Review Rust library and CLI changes. Use this for pull request review, code review, security review, or refactoring review in this Rust repo.
---

# Rust Code Review Skill

Review the change as a maintainer of a small open-source Rust library + CLI.

## Review priorities

Check, in this order:

1. Correctness bugs.
2. Public API compatibility.
3. CLI behavior and exit behavior.
4. Error handling quality.
5. Input validation and security issues.
6. Tests for changed behavior.
7. Documentation and README drift.
8. Dependency, MSRV, edition, and Cargo.toml impact.
9. Maintainability.

## What to flag

Flag issues when they are actionable and likely to matter.

Look for:

- New `unwrap`, `expect`, or `panic!` in library code.
- Silent error swallowing.
- Incorrect path handling.
- Bad UTF-8 assumptions.
- Platform-specific assumptions, especially Windows path or newline behavior.
- Breaking changes to public structs, enums, functions, features, or CLI flags.
- Missing tests for new branches or error cases.
- New dependencies that are unjustified or too broad.
- User-facing error messages that are confusing.
- Security-sensitive issues: command injection, path traversal, unsafe temp files, unsafe deserialization, accidental secret logging.

## Output format

Use this format:

```md
## Summary

One or two sentences.

## Blocking issues

- `path:line` — Problem. Why it matters. Suggested fix.

## Non-blocking suggestions

- `path:line` — Suggestion. Why it helps.

## Tests to add or run

- Specific test or command.