# Copilot instructions for this Rust repo

This is a small open-source Rust package with a CLI.

## General behavior

- Prefer small, focused changes.
- Preserve the public API unless the task explicitly asks for a breaking change.
- Do not change the Rust edition, MSRV, license, crate name, or dependency strategy unless asked.
- Avoid adding dependencies. If a dependency is useful, explain why it is worth the cost.
- Keep reusable logic in the library. Keep CLI code thin: argument parsing, user-facing output, process exit behavior.
- Prefer clear, boring Rust over clever abstractions.

## Rust style

- Use `Result` for fallible operations.
- Do not `unwrap`, `expect`, or `panic!` in library code unless there is a proven invariant and a comment explains it.
- In CLI code, convert errors into user-friendly messages.
- Prefer explicit types at API boundaries.
- Keep functions short enough to test and review.
- Avoid `unsafe`. If unavoidable, isolate it, document invariants, and add tests.

## Testing and quality gates

When changing behavior, add or update tests.

Before proposing a final answer or PR, try to run:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features