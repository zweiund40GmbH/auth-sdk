# zwei&40 Login – Client-SDKs. Lokal und in CI identisch (.github/workflows/ci.yml).
set shell := ["bash", "-euo", "pipefail", "-c"]

# Rezepte auflisten
default:
    @just --list

# Alles prüfen (vor jedem Commit)
check: lines rust-check js-check

# Rust-SDK: Format, Lint (alle Features, Warnungen = Fehler), Tests
rust-check:
    cd rust && cargo fmt --all -- --check
    cd rust && cargo clippy --all-targets --all-features --locked -- -D warnings
    cd rust && cargo test --all-features --locked

# Rust-SDK: Paket bauen wie für crates.io (Inhalt prüfen, nichts hochladen)
rust-package:
    cd rust && cargo package --locked --list && cargo package --locked

# Next.js-SDK: Lint, Typprüfung, Tests, Build und Inhalt des npm-Pakets (nichts hochladen)
js-check:
    cd js && yarn lint
    cd js && yarn typecheck
    cd js && yarn test
    cd js && yarn build
    cd js && yarn pack-check

# Dateigrößen: Warnung > 300, Fehler > 400 Zeilen (Quellcode, ohne Lockfiles)
lines:
    #!/usr/bin/env bash
    set -euo pipefail
    warn=0; err=0
    while IFS= read -r f; do
      n=$(wc -l < "$f")
      if [ "$n" -gt 400 ]; then echo "FEHLER $f: $n Zeilen"; err=$((err+1));
      elif [ "$n" -gt 300 ]; then echo "Warnung $f: $n Zeilen"; warn=$((warn+1)); fi
    done < <(git ls-files '*.rs' '*.go' '*.ts' '*.tsx' '*.js' '*.mjs')
    echo "lines: $warn Warnung(en), $err Fehler"
    [ "$err" -eq 0 ]
