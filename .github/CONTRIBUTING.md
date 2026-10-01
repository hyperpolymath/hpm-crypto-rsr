# Contributing to hpm-crypto-rsr

Thanks for your interest. This repository follows the Hyperpolymath
estate standards defined in
[hyperpolymath/standards](https://github.com/hyperpolymath/standards).

## Licence

This project is licensed under **MPL-2.0**. By contributing you agree
that your contributions are licensed under the same terms. Every source
file carries an `SPDX-License-Identifier` header; keep it when editing,
and add one to any new file.

## Development environment

A pinned dev shell is provided:

``` sh
nix develop        # toolchain: just
```

Estate policy is Guix primary / Nix fallback; this repo currently ships
the Nix fallback. A `guix.scm` is welcome if you prefer the primary
tier.

## Build and test

This repo uses [`just`](https://just.systems) (the estate uses
Justfiles, never Makefiles). Recipes available here:

``` sh
just            # list recipes
just fmt        # format
just fmt-check  # check formatting
just lint       # lint
just test-all   # run the full suite
just doctor     # environment diagnostics
```

## Machine-readable artefacts

This repo carries `.machine_readable/` A2ML files (`STATE.a2ml`,
`META.a2ml`, `ECOSYSTEM.a2ml`, `AGENTIC.a2ml`, `NEUROSYM.a2ml`,
`PLAYBOOK.a2ml`). If your change alters project state, architecture, or
operational steps, update the corresponding file in the same PR — CI
validates them.

## Language policy

The estate restricts which languages may be used. In particular Python,
Go, TypeScript, ReScript, V-lang, Java/Kotlin, Swift and Makefiles are
**not** accepted in new code; AffineScript, Rust/SPARK, Zig, Deno,
Gleam, Elixir, Haskell, Idris2, Agda, Julia and OCaml are. CI enforces
this, so check the policy in `hyperpolymath/standards` before
introducing a new language.

## Documentation format

Docs are AsciiDoc (`.adoc`) by default, including `README.adoc`. The
GitHub-required community-health files stay Markdown: `SECURITY.md`,
`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`. Do not add a
`.md` duplicate of a doc that already exists as `.adoc`.

## Pull requests

1.  Branch from `main` — do not push to `main` directly; branch
    protection requires review and passing checks.

2.  Keep the change focused, and explain *why* in the PR body.

3.  Make sure governance CI is green. It checks documentation presence,
    packaging policy, secrets, licence consistency and workflow
    security.

4.  Security issues: follow `SECURITY.md` — report privately, never in a
    public issue.

## Signed commits

Every commit that reaches the default branch must be signed; a ruleset refuses
unsigned pushes. Estate policy:
[SIGNING-POLICY](https://github.com/hyperpolymath/standards/blob/main/docs/SIGNING-POLICY.adoc).

- **People and interactive agents** sign with an SSH key registered on GitHub
  as a *signing* key (`gpg.format=ssh`, `user.signingkey=<key>.pub`,
  `commit.gpgsign=true`). The committer email must be verified on that account.
- **Apps, bots and workflows** never `git push` local commits. They write
  through the API (`createCommitOnBranch` or the estate `signed-push` action)
  so that GitHub signs each commit.
- Merge PRs with **squash**. The ruleset checks every commit on the PR branch,
  not just the result, so one unsigned commit blocks the merge. Re-create such a
  branch with signed commits (`git cherry-pick -S`) and open a new PR.
  Rebase-merge replays commits unsigned and is disabled.
