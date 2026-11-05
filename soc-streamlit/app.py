"""Cyber SOC — tableau de bord Streamlit sur les donnees reelles.

Sources (aucune table inventee) :
  - soc.db        : alertes, approbations human-in-the-loop, snapshots (soc-dashboard)
  - orchestrateur : reseau d'agents du lab (12 agents) et ses taches

Lancement :  .venv\\Scripts\\python.exe -m streamlit run app.py --server.port 8501
"""

import json
import os
import sqlite3
import urllib.request
from datetime import datetime, timedelta, timezone

import altair as alt
import pandas as pd
import streamlit as st

ICI = os.path.dirname(os.path.abspath(__file__))
DB_DEFAUT = os.path.join(ICI, "..", "soc-dashboard", "soc.db")
ENV_DEFAUT = os.path.join(ICI, "..", "soc-dashboard", ".env")

st.set_page_config(
    page_title="Cyber SOC — supervision",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

SEV_COULEUR = {1: "faible", 2: "moyen", 3: "élevé", 4: "critique"}
TABLES_ATTENDUES = ("alerts", "approvals", "approval_audit")


# --------------------------------------------------------------------- outils
def lire_env(chemin=ENV_DEFAUT):
    """Charge les cles presentes a cote du tableau de bord (jamais affichees)."""
    valeurs = {}
    try:
        with open(chemin, "r", encoding="utf-8", errors="replace") as fh:
            for ligne in fh:
                ligne = ligne.strip()
                if ligne and not ligne.startswith("#") and "=" in ligne:
                    cle, val = ligne.split("=", 1)
                    valeurs[cle.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        pass
    return valeurs


ENV = lire_env()

# Les variables du systeme priment sur le fichier .env
def env(cle, defaut=""):
    return os.environ.get(cle) or ENV.get(cle) or defaut


DB = os.path.abspath(env("SOC_DB", DB_DEFAUT))
ORCH = env("ORCHESTRATOR_URL", "http://127.0.0.1:8000").rstrip("/")
ORCH_KEY = env("ORCH_KEY", "LAB-ORCH-SECRET")


def sev(level):
    """Wazuh : 0-3 info, 4-7 bas, 8-11 eleve, 12+ critique."""
    if level >= 12:
        return "critique"
    if level >= 8:
        return "élevé"
    if level >= 4:
        return "moyen"
    return "faible"


ORDRE_SEV = ["critique", "élevé", "moyen", "faible"]
COULEURS = {"critique": "#ef4444", "élevé": "#f59e0b", "moyen": "#3b82f6", "faible": "#22c55e"}
DOMAINE = [COULEURS[s] for s in ORDRE_SEV]


def theme(c):
    """Habillage sombre commun aux graphiques Vega (rendus en SVG)."""
    return (
        c.configure(background="transparent")
        .configure_view(stroke=None)
        .configure_axis(labelColor="#8b978f", titleColor="#5c6a61", gridColor="#161d19",
                        domainColor="#232d26", tickColor="#232d26", labelFontSize=10)
        .configure_legend(labelColor="#8b978f", titleColor="#5c6a61", labelFontSize=10)
    )


@st.cache_data(ttl=5, show_spinner=False)
def charger_alertes(chemin, version):
    with sqlite3.connect(chemin) as conn:
        df = pd.read_sql("SELECT * FROM alerts", conn)
    if df.empty:
        return df
    df["ts_dt"] = pd.to_datetime(df["ts"], errors="coerce", utc=True)
    df["quand"] = df["ts_dt"].dt.tz_convert(None)
    df["severite"] = df["level"].apply(sev)
    df["mitre"] = df["mitre_ids"].fillna("").apply(
        lambda s: ", ".join(json.loads(s)) if s.startswith("[") else s
    )
    return df.sort_values("ts_dt", ascending=False, na_position="last")


@st.cache_data(ttl=5, show_spinner=False)
def charger_approbations(chemin, version):
    with sqlite3.connect(chemin) as conn:
        try:
            ap = pd.read_sql("SELECT * FROM approvals", conn)
        except Exception:
            ap = pd.DataFrame()
        try:
            audit = pd.read_sql("SELECT * FROM approval_audit ORDER BY id DESC LIMIT 200", conn)
        except Exception:
            audit = pd.DataFrame()
    return ap, audit


@st.cache_data(ttl=10, show_spinner=False)
def charger_lab(url, cle):
    """Reseau d'agents du lab : etat réel, pas une valeur codee en dur."""
    def get(chemin):
        req = urllib.request.Request(url + chemin, headers={"X-Orchestrator-Key": cle})
        with urllib.request.urlopen(req, timeout=4) as rep:
            return json.loads(rep.read() or b"{}")

    try:
        sante = get("/health")
        agents = get("/agents")
        agents = agents.get("agents", agents) if isinstance(agents, dict) else agents
        taches = get("/tasks?limit=12")
        taches = taches.get("tasks", taches) if isinstance(taches, dict) else taches
        return {"ok": True, "agents": agents, "taches": taches,
                "total_taches": sante.get("tasks", 0), "erreur": None}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "agents": [], "taches": [], "total_taches": 0,
                "erreur": "%s : %s" % (type(exc).__name__, exc)}


def version_fichier(chemin):
    try:
        return os.path.getmtime(chemin)
    except OSError:
        return 0


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.markdown("### 🛡️ Cyber SOC")
    st.caption("Supervision locale — Streamlit")

    existe = os.path.exists(DB)
    if existe:
        st.success("Base trouvée")
    else:
        st.error("Base introuvable")
    st.code(DB, language=None)

    lab = charger_lab(ORCH, ORCH_KEY)
    if lab["ok"]:
        en_ligne = sum(1 for a in lab["agents"] if a.get("status") == "ONLINE")
        st.success("Orchestrateur : %d/%d agents en ligne" % (en_ligne, len(lab["agents"])))
    else:
        st.warning("Orchestrateur injoignable")

    st.divider()
    st.markdown("##### Filtres")
    periode = st.selectbox("Période", ["24 heures", "7 jours", "30 jours", "Tout"], index=1)
    seuil = st.selectbox("Sévérité minimale", ORDRE_SEV[::-1], index=0)
    rafraichir = st.toggle("Rafraîchir toutes les 15 s", value=False)

    st.divider()
    if st.button("Recharger les données", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    st.caption("Les valeurs ne sont jamais écrites côté client : lecture seule.")

# ------------------------------------------------------------------- donnees
if not existe:
    st.title("Tableau de bord indisponible")
    st.error(
        "La base `soc.db` est introuvable. Démarrez le collecteur et le tableau de bord "
        "(`soc-dashboard/app.py`) pour l'alimenter, ou pointez `SOC_DB` vers une autre base."
    )
    st.stop()

ver = version_fichier(DB)
alertes = charger_alertes(DB, ver)
approbations, journal = charger_approbations(DB, ver)

# Application des filtres
vues = alertes.copy()
if not vues.empty:
    maintenant = pd.Timestamp(datetime.now(timezone.utc).replace(tzinfo=None))
    bornes = {"24 heures": 1, "7 jours": 7, "30 jours": 30}
    if periode in bornes:
        vues = vues[vues["quand"] >= maintenant - timedelta(days=bornes[periode])]
    if seuil != "faible":
        gardees = ORDRE_SEV[: ORDRE_SEV.index(seuil) + 1]
        vues = vues[vues["severite"].isin(gardees)]

# ------------------------------------------------------------------- en-tete
st.title("Cyber SOC — tableau de bord")
st.caption(
    "Alertes : %s · période : %s · seuil : %s"
    % (os.path.basename(DB), periode.lower(), seuil)
)

en_ligne = sum(1 for a in lab["agents"] if a.get("status") == "ONLINE") if lab["ok"] else 0
total_lab = len(lab["agents"]) if lab["ok"] else 0
critiques = int((vues["severite"] == "critique").sum()) if not vues.empty else 0
elevees = int((vues["severite"] == "élevé").sum()) if not vues.empty else 0
en_attente = int((approbations["status"] == "pending").sum()) if not approbations.empty else 0

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Agents du lab", "%d/%d" % (en_ligne, total_lab),
          delta=None if lab["ok"] else "orchestrateur muet", delta_color="off")
c2.metric("Alertes (filtre)", f"{len(vues):,}".replace(",", " "))
c3.metric("Critiques", critiques)
c4.metric("Élevées", elevees)
c5.metric("Approbations en attente", en_attente,
          delta="action humaine requise" if en_attente else None,
          delta_color="inverse" if en_attente else "off")

if not lab["ok"]:
    st.warning("Orchestrateur injoignable — %s. Les agents affichés sont ceux du dernier état connu."
               % lab["erreur"])

onglet_vue, onglet_journal, onglet_hitl, onglet_agents = st.tabs(
    ["Vue d'ensemble", "Journal SIEM", "Approbations (HITL)", "Réseau d'agents"]
)

# ------------------------------------------------------------ vue d'ensemble
with onglet_vue:
    if vues.empty:
        st.info("Aucune alerte sur la période et le seuil choisis.")
    else:
        g, d = st.columns([1.7, 1])
        with g:
            st.markdown("##### Volume d'alertes par heure")
            base = vues.set_index("quand").groupby([pd.Grouper(freq="h"), "severite"]).size()
            serie = base.rename("alertes").reset_index()
            serie = serie[serie["alertes"] > 0]
            barres = alt.Chart(serie).mark_bar(size=9).encode(
                x=alt.X("quand:T", title=None, axis=alt.Axis(format="%d/%m %Hh", tickCount=8)),
                y=alt.Y("alertes:Q", title=None, stack=True),
                color=alt.Color("severite:N", scale=alt.Scale(domain=ORDRE_SEV, range=DOMAINE),
                                legend=alt.Legend(title=None, orient="top", direction="horizontal")),
                tooltip=["quand:T", "severite:N", "alertes:Q"],
            )
            st.altair_chart(theme(barres).properties(height=270))

            st.markdown("##### Règles les plus fréquentes")
            top = (vues.assign(regle=vues["rule_id"].astype(str) + " · " + vues["description"].fillna(""))
                   .groupby("regle").size().sort_values(ascending=False).head(9).rename("alertes")
                   .reset_index()[::-1])
            regles = alt.Chart(top).mark_bar(color="#22c55e", size=14).encode(
                y=alt.Y("regle:N", title=None, sort=None, axis=alt.Axis(labelLimit=380)),
                x=alt.X("alertes:Q", title=None),
                tooltip=["regle:N", "alertes:Q"],
            )
            st.altair_chart(theme(regles).properties(height=290))

        with d:
            st.markdown("##### Répartition par sévérité")
            rep = (vues["severite"].value_counts().reindex(ORDRE_SEV).dropna()
                   .rename("alertes").reset_index().rename(columns={"index": "severite"}))
            camembert = alt.Chart(rep).mark_arc(innerRadius=58, outerRadius=92, stroke="#0d100e", strokeWidth=2).encode(
                theta=alt.Theta("alertes:Q"),
                color=alt.Color("severite:N", scale=alt.Scale(domain=ORDRE_SEV, range=DOMAINE),
                                legend=alt.Legend(title=None, orient="bottom", direction="horizontal")),
                tooltip=["severite:N", "alertes:Q"],
            )
            st.altair_chart(theme(camembert).properties(height=250))

            st.markdown("##### Postes les plus bavards")
            postes = vues["agent"].fillna("—").value_counts().head(6).rename("alertes")
            st.table(postes)

            if lab["ok"] and lab["taches"]:
                st.markdown("##### Dernières tâches des agents")
                taches = (pd.DataFrame(lab["taches"])
                          .sort_values("created_at", ascending=False)[["task_id", "agent_id", "status"]].head(5))
                st.table(taches.rename(columns={"task_id": "tâche", "agent_id": "agent", "status": "état"}))

# --------------------------------------------------------------- journal SIEM
with onglet_journal:
    st.markdown("##### Journal des événements de sécurité")
    if vues.empty:
        st.info("Aucun événement pour ces filtres.")
    else:
        colonnes = {
            "quand": "Horodatage", "rule_id": "Règle", "severite": "Sévérité",
            "description": "Description", "agent": "Poste", "playbook": "Playbook",
            "mitre": "MITRE", "state": "État", "level": "Niveau",
        }
        table = vues[list(colonnes)].rename(columns=colonnes)
        st.caption("%d alertes après filtrage (%d en base)." % (len(table), len(alertes)))

        par_page = 60
        pages = max(1, (len(table) + par_page - 1) // par_page)
        cg, cd = st.columns([1, 3])
        page = cg.number_input("Page", min_value=1, max_value=pages, value=1, step=1)
        cd.caption("%d pages de %d lignes" % (pages, par_page))
        debut = (int(page) - 1) * par_page
        extrait = table.iloc[debut:debut + par_page].copy()
        extrait["Horodatage"] = pd.to_datetime(extrait["Horodatage"]).dt.strftime("%d/%m/%Y %H:%M:%S")
        st.table(extrait.set_index("Horodatage"))
        st.download_button(
            "Exporter en CSV",
            table.to_csv(index=False).encode("utf-8-sig"),
            file_name="alertes_soc.csv",
            mime="text/csv",
        )

# ------------------------------------------------------------------- HITL
with onglet_hitl:
    st.markdown("##### Actions sensibles soumises à approbation humaine")
    if approbations.empty:
        st.info("Aucune action enregistrée. Le broker d'autorisation n'a encore rien soumis.")
    else:
        attente = approbations[approbations["status"] == "pending"]
        if attente.empty:
            st.success("Aucune action en attente.")
        else:
            st.warning("%d action(s) attendent une décision." % len(attente))
            st.table(attente[["id", "agent", "risk", "created_at"]].rename(
                columns={"id": "id", "agent": "agent", "risk": "risque", "created_at": "créée le"}))
        st.markdown("##### Historique des décisions")
        hist = approbations.sort_values("created_at", ascending=False).head(25)
        st.table(hist[["id", "risk", "status", "created_at", "decided_by"]].rename(
            columns={"id": "id", "risk": "risque", "status": "décision",
                     "created_at": "créée le", "decided_by": "par"}))
        if not journal.empty:
            with st.expander("Journal d'audit des approbations (%d entrées)" % len(journal)):
                st.dataframe(journal[["ts", "approval_id", "event", "actor", "detail"]],
                             use_container_width=True, hide_index=True)

# ------------------------------------------------------------- reseau agents
with onglet_agents:
    st.markdown("##### Agents du lab (orchestrateur local)")
    if not lab["ok"]:
        st.error("Orchestrateur injoignable : %s" % lab["erreur"])
    else:
        lignes = [{
            "agent": a.get("agent_id"),
            "nom": a.get("name"),
            "statut": a.get("status"),
            "port": (a.get("endpoint") or "").rsplit(":", 1)[-1],
            "capacités": ", ".join(a.get("capabilities") or []),
            "dernier contact": (a.get("last_seen") or "")[:19].replace("T", " "),
        } for a in lab["agents"]]
        st.table(pd.DataFrame(lignes).rename(columns={"dernier contact": "dernier contact"}))
        st.caption("%d agents, %d tâches traitées par l'orchestrateur." % (total_lab, lab["total_taches"]))

st.divider()
st.caption(
    "Lecture seule : cette page ne modifie ni les alertes ni les approbations. "
    "Les décisions passent par le broker (CLI ou tableau de bord principal)."
)

if rafraichir:
    import time

    time.sleep(15)
    st.rerun()
