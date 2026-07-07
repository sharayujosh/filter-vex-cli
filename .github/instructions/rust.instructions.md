
## `.github/instructions/rust.instructions.md`

```md
---
applyTo: "**/*.rs"
---

# Rust-specific instructions

- Follow idiomatic Rust naming and module organization.
- Keep library code independent from CLI concerns.
- Prefer borrowing over cloning, but do not sacrifice readability for micro-optimization.
- Use `Path`/`PathBuf` for paths, not raw strings.
- Use `std::time` types for time values unless the crate already uses another time library.
- Validate external input at the boundary.
- Return structured errors from library code.
- Avoid printing from library code.
- Avoid global mutable state.
- Add focused unit tests near the code under test.
- Add integration tests for CLI-visible behavior when practical.