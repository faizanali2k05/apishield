# Manual release

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

Use the exact distribution name `apishield` on PyPI. Never commit credentials; use Twine's environment variables or interactive prompt.
