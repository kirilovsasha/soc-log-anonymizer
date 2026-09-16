# Publishing: GitHub Releases, code signing, PyPI

## GitHub Releases

On a version tag (`v2.4.0`) the workflow `.github/workflows/release.yml`:

1. Runs the test suite
2. Builds Windows GUI/CLI onefile artifacts
3. Uploads them to a GitHub Release

Create a release:

```bash
git tag v2.4.0
git push origin v2.4.0
```

## Code signing (Windows)

CI uploads **unsigned** binaries. For production SOC rollouts, sign locally
or in a protected runner with your org certificate:

```bat
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /a dist\soc-log-anonymizer-gui.exe
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /a dist\soc-log-anonymizer-cli.exe
```

See also [WINDOWS_EXE.md](WINDOWS_EXE.md) (SmartScreen notes).

## PyPI

Workflow `.github/workflows/publish-pypi.yml` publishes on tags when
`PYPI_API_TOKEN` (or Trusted Publishing) is configured in repo secrets.

Manual:

```bash
pip install -e ".[dev]"
python -m build
python -m twine upload dist/*
```

Package name: `soc-log-anonymizer` (stdlib-only runtime; `dev`/`publish` extras
are optional).
