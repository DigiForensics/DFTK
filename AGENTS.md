# DFTK repository guidance

DFTK is the primary Agent installation entry point. If a user provides this
repository for installation, follow [INSTALL_AGENT.md](INSTALL_AGENT.md): install
the local DFTK runtime, then run `dftk agent setup --root <evidence> --workspace <case> --install-skill --target <current-host>` so
the matching DFTK-skill bundle is fetched automatically.

Do not install into every Agent host by default. Select the current host explicitly
or run a dry-run when the host cannot be determined. Keep source evidence under a
read-only MCP `--root` and Case material in a separate `--workspace`.
