## Summary

<!-- What does this PR do, and why? -->

## Type of change

- [ ] New forensic primitive or recipe
- [ ] Bug fix
- [ ] Documentation
- [ ] Refactor / internal improvement
- [ ] Release tooling

## Capability checklist

If this adds or changes a tool, confirm:

- [ ] Generic artifact parameters (no embedded case constants)
- [ ] Source evidence preserved by default
- [ ] `unsupported` / `error` / `blocked` / negative findings are distinct
- [ ] Returns structured `facts` and explicit `evidence` locators
- [ ] Safety level, network behavior, optional requirements, tags, and produced evidence types declared
- [ ] Regression tests added for success **and** malformed / unsupported input
- [ ] Parser errors are not silently swallowed

## Test plan

```bash
pytest -q
```

## Notes for reviewers

<!-- Anything reviewers should pay special attention to. -->
