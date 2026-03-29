## Summary
<!-- What does this PR do? One paragraph. -->

## Type of change
- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / code quality
- [ ] Documentation
- [ ] CI / tooling
- [ ] Dependency update

## Checklist
- [ ] `ruff check` and `ruff format --check` pass locally
- [ ] `mypy src` passes with no new errors
- [ ] `pytest -q` passes across Python 3.11, 3.12, and 3.13
- [ ] If adding a provider or model: `skillscan-trace check --provider <name>` verified
- [ ] If changing CLI behavior: `README.md` and `SPEC.md` updated
- [ ] If adding a canary check: positive + negative test cases added
- [ ] No hardcoded API keys, tokens, or credentials in any file
- [ ] No debug code (`print(f"DBG...")`, `pdb.set_trace()`) left in

## Testing
<!-- Describe how you tested this change. -->

## Related issues
<!-- Closes #xxx -->
