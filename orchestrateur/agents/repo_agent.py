"""Repo Agent : fait agir l'agent sur son depot GitHub via le CLI gh.

Sous-commandes reconnues dans le payload :
    etat | status          -> depot, derniere version, issues et PR ouvertes
    issues                 -> liste des issues ouvertes
    checks                 -> etat des workflows GitHub Actions
    issue: <titre>         -> cree une issue (corps = constat fourni apres le titre)

Aucun succes n'est affiche sans lecture de retour : chaque action est re-verifiee
par un appel gh distinct. Si gh n'est pas authentifie, l'agent le dit.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parents[2]  # ...\Documents\security
GH_FALLBACK = r"C:\Program Files\GitHub CLI\gh.exe"


def _gh() -> str:
    return shutil.which("gh") or (GH_FALLBACK if Path(GH_FALLBACK).exists() else "")


def _run(args: list[str]) -> tuple[int, str, str]:
    exe = _gh()
    if not exe:
        raise RuntimeError("gh introuvable : installer GitHub CLI (winget install GitHub.cli)")
    proc = subprocess.run(
        [exe, *args], cwd=str(REPO_DIR), capture_output=True, text=True,
        timeout=120, encoding="utf-8", errors="replace",
    )
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


def _out(cmd: list[str]) -> str:
    code, out, err = _run(cmd)
    if code != 0:
        raise RuntimeError((err or out).splitlines()[0][:200] if (err or out) else f"gh code {code}")
    return out


def _git(*args: str) -> str:
    """Commandes git locales (gh ne les connait pas)."""
    proc = subprocess.run(
        ["git", *args], cwd=str(REPO_DIR), capture_output=True, text=True,
        timeout=60, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "").strip().splitlines()[0][:200])
    return (proc.stdout or "").strip()


def run_repo_task(payload: str) -> tuple[bool, str]:
    action = (payload or "etat").strip().lower()

    who = _out(["api", "user", "--jq", ".login"])
    print(f"  compte gh : {who}")

    if action.startswith("issue:"):
        title = payload.split(":", 1)[1].strip() or "Constat SOC"
        body = (
            "Constat remonte par l'agent cyber.\n\n"
            "Preuve : voir agent-z/knowledge/soc-facts.md et agent-z/logs/.\n"
            "Critere de cloture : verification par une lecture reelle de l'API Wazuh."
        )
        url = _out(["issue", "create", "--title", title, "--body", body, "--label", ""])
        print(f"  issue creee : {url}")
        # re-lecture independante
        num = url.rstrip("/").split("/")[-1]
        state = _out(["issue", "view", num, "--json", "state,title", "--jq", '.state + " | " + .title'])
        print(f"  relecture distante : {state}")
        return state.startswith("OPEN"), f"issue #{num} ouverte : {url}"

    if action.startswith("issues"):
        out = _out(["issue", "list", "--limit", "20", "--json", "number,title,state",
                    "--jq", '.[] | "#\\(.number) [\\(.state)] \\(.title)"'])
        print("\n".join(f"  {l}" for l in out.splitlines()) or "  aucune issue ouverte")
        return True, f"{len(out.splitlines())} issue(s) listee(s)"

    if action.startswith("check"):
        out = _out(["run", "list", "--limit", "5", "--json", "name,status,conclusion,headBranch",
                    "--jq", '.[] | "\\(.name) \\(.status)/\\(.conclusion // "en cours") (\\(.headBranch))"'])
        print("\n".join(f"  {l}" for l in out.splitlines()) or "  aucun workflow lance")
        return True, "workflows lus"

    # etat par defaut
    info = _out(["repo", "view", "--json", "nameWithOwner,visibility,defaultBranchRef,pushedAt,url",
                 "--jq", '"\(.nameWithOwner) | \(.visibility) | \(.defaultBranchRef.name) | pousse \(.pushedAt) | \(.url)"'])
    print(f"  depot : {info}")
    last = _git("log", "-1", "--format=%h %an %s")
    print(f"  commit local : {last}")
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    ahead = _git("rev-list", "--count", f"origin/{branch}..{branch}")
    print(f"  branche : {branch}  en avance de {ahead} commit(s) sur origin")
    issues = _out(["issue", "list", "--state", "open", "--limit", "10", "--json", "number",
                   "--jq", "length"])
    print(f"  issues ouvertes : {issues}")
    return ahead == "0", f"depot synchronise ({ahead} commit en attente)"
