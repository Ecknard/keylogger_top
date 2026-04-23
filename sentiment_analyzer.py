"""
sentiment_analyzer.py — Partie II, Tâche 6 : Analyse de sentiments
TP1 — Intelligence Artificielle & Cybersécurité

CORRECTIFS v2 :
    ✅ LEXIQUE FRANÇAIS — VADER ne connaît que l'anglais. Injection de 200+
       mots français couvrant les sentiments négatifs courants (détresse,
       pénible, marre, déteste, énervé, déprimé...) ET positifs (super,
       génial, content, heureux...) avec intensificateurs et négations.
    ✅ NORMALISATION — suppression des accents pour les mots-clés connus
       afin de gérer les variantes (detresse / détresse, penible / pénible).
    ✅ NETTOYAGE AZERTY — suppression des timestamps et balises clavier
       avant l'analyse.
    ✅ RÉSULTAT ENRICHI — champ 'confidence' et 'language' ajoutés.
"""

import json
import os
import re
import unicodedata
from datetime import datetime
from typing import Optional

try:
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
    _VADER_AVAILABLE = True
except ImportError:
    _VADER_AVAILABLE = False
    print("[AVERTISSEMENT] vaderSentiment non installé : pip install vaderSentiment")


# ── Singleton ─────────────────────────────────────────────────────────────────
_analyzer: Optional[object] = None

def _get_analyzer():
    global _analyzer
    if _analyzer is None and _VADER_AVAILABLE:
        _analyzer = SentimentIntensityAnalyzer()
        _inject_french_lexicon(_analyzer)
    return _analyzer


# ════════════════════════════════════════════════════════════════════════════════
# LEXIQUE FRANÇAIS COMPLET
# ════════════════════════════════════════════════════════════════════════════════
#
# Chaque entrée est dupliquée : avec ET sans accent (unicodedata.normalize),
# car le keylogger peut capturer les deux formes selon le contexte.
#
# Valeurs VADER : [-4, +4] → compound normalisé entre [-1, +1]
# Règle : |valeur| > 2 = fort signal, 1–2 = modéré, < 1 = faible

_FR_LEXICON_RAW = {
    # ── Négatifs forts ────────────────────────────────────────────────────────
    "horrible":       -3.2, "affreux":        -2.9, "affreuse":       -2.9,
    "terrible":       -2.9, "catastrophe":    -3.0, "catastrophique": -3.0,
    "cata":           -2.5, "desastre":       -3.0, "désastre":       -3.0,
    "desastreux":     -2.9, "désastreux":     -2.9,
    "atroce":         -3.0, "abominable":     -3.0, "ignoble":        -2.8,
    "insupportable":  -2.7, "detestable":     -2.8, "détestable":     -2.8,
    "epouvantable":   -2.9, "épouvantable":   -2.9, "cauchemar":      -2.6,
    "nul":            -2.2, "nulle":          -2.2, "mediocre":       -2.0,
    "médiocre":       -2.0, "pourri":         -2.4, "pourrie":        -2.4,
    "naze":           -2.1, "minable":        -2.3,

    # ── États émotionnels négatifs ────────────────────────────────────────────
    "detresse":       -2.8, "détresse":       -2.8,
    "deprime":        -2.6, "déprimé":        -2.6, "deprimé":        -2.6,
    "deprimee":       -2.6, "déprimée":       -2.6,
    "malheureux":     -2.3, "malheureuse":    -2.3,
    "triste":         -2.2, "tristesse":      -2.3,
    "desespere":      -3.0, "désespéré":      -3.0,
    "angoisse":       -2.5, "angoissé":       -2.5,
    "anxieux":        -2.0, "anxieuse":       -2.0,
    "anxiete":        -2.0, "anxiété":        -2.0,
    "peur":           -1.8, "terreur":        -2.8, "terrrifie":      -2.8,
    "honte":          -2.0, "humiliation":    -2.5,
    "souffrance":     -2.8, "souffre":        -2.5, "souffrir":       -2.5,
    "douleur":        -2.5, "douloureux":     -2.4,
    "larmes":         -1.8, "pleure":         -1.9, "pleurer":        -1.9,

    # ── Colère / Frustration ──────────────────────────────────────────────────
    "colere":         -2.4, "colère":         -2.4,
    "furieux":        -2.8, "furieuse":       -2.8,
    "rage":           -2.7, "rageur":         -2.6, "rageuse":        -2.6,
    "enerve":         -2.3, "énervé":         -2.3, "enervé":         -2.3,
    "enervee":        -2.3, "énervée":        -2.3,
    "irrite":         -2.1, "irrité":         -2.1, "irritee":        -2.1,
    "agace":          -2.0, "agacé":          -2.0, "agacee":         -2.0,
    "exaspere":       -2.3, "exaspéré":       -2.3,
    "ras-le-bol":     -2.5, "marre":          -2.2, "assez":          -1.3,
    "insupporte":     -2.3, "insupporté":     -2.3,
    "deteste":        -2.7, "déteste":        -2.7, "detester":       -2.7,
    "hais":           -3.0, "haïs":           -3.0, "haine":          -3.0,
    "odieux":         -2.6, "odieuse":        -2.6,

    # ── Inconfort / Difficulté ────────────────────────────────────────────────
    "penible":        -2.2, "pénible":        -2.2,
    "difficile":      -1.4, "complique":      -1.3, "compliqué":      -1.3,
    "probleme":       -1.6, "problème":       -1.6,
    "erreur":         -1.6, "bug":            -1.4, "bogue":          -1.4,
    "panne":          -1.8, "casse":          -1.8, "cassé":          -1.8,
    "casse-pieds":    -2.0, "chiant":         -2.1, "chiante":        -2.1,
    "fatigue":        -1.5, "fatigué":        -1.8, "fatiguee":       -1.8,
    "epuise":         -2.1, "épuisé":         -2.1, "epuisee":        -2.1,
    "stresse":        -2.0, "stressé":        -2.0, "stressée":       -2.0,
    "inquiet":        -1.9, "inquiete":       -1.9, "inquiète":       -1.9,
    "preoccupe":      -1.7, "préoccupé":      -1.7,
    "impossible":     -1.6, "inacceptable":   -2.2,
    "echoue":         -2.2, "échoué":         -2.2, "rate":           -2.2, "raté": -2.2,
    "echec":          -2.4, "échec":          -2.4,
    "loupe":          -1.8, "loupé":          -1.8, "rater":          -2.0,
    "perdre":         -1.5, "perdu":          -1.7,
    "mauvais":        -1.9, "mauvaise":       -1.9, "mal":            -1.5,

    # ── Intensificateurs ──────────────────────────────────────────────────────
    "tres":           1.4,  "très":           1.4,
    "vraiment":       1.3,  "tellement":      1.4,
    "trop":           1.2,  "extremement":    1.6, "extrêmement":     1.6,
    "totalement":     1.3,  "completement":   1.3, "complètement":    1.3,
    "absolument":     1.4,  "franchement":    1.2,
    "tellement":      1.3,  "vachement":      1.3,
    "super":          1.6,  # (peut amplifier le positif ou le négatif)

    # ── Négations (réduisent/inversent) ───────────────────────────────────────
    "pas":            -0.6, "ne":             -0.3, "jamais":         -0.7,
    "rien":           -0.5, "aucun":          -0.4, "aucune":         -0.4,
    "sans":           -0.3, "ni":             -0.3, "non":            -0.5,
    "plus":           -0.2,  # "ne ... plus"

    # ── Positifs forts ────────────────────────────────────────────────────────
    "excellent":      3.0,  "parfait":        2.8, "parfaite":        2.8,
    "magnifique":     2.9,  "fantastique":    2.8, "fabuleux":        2.7,
    "genial":         2.7,  "génial":         2.7, "geniale":         2.7, "géniale": 2.7,
    "formidable":     2.7,  "extraordinaire": 2.8, "incroyable":      2.5,
    "sublime":        2.8,  "exceptionnel":   2.7, "remarquable":     2.4,
    "impressionnant": 2.3,  "bluffant":       2.4,

    # ── Positifs modérés ──────────────────────────────────────────────────────
    "bien":           1.6,  "bon":            1.6, "bonne":           1.6,
    "content":        2.0,  "contente":       2.0,
    "heureux":        2.4,  "heureuse":       2.4,
    "satisfait":      2.0,  "satisfaite":     2.0,
    "agreable":       1.8,  "agréable":       1.8,
    "sympa":          1.6,  "cool":           1.5,
    "top":            1.8,  "nickel":         1.7, "canon":           1.8,
    "bravo":          2.2,  "chapeau":        1.8, "felicitations":   2.5,
    "félicitations":  2.5,  "super":          2.0,
    "adore":          2.6,  "aime":           1.9, "aimer":           1.9,
    "reussi":         2.0,  "réussi":         2.0, "reussie":         2.0,
    "succes":         2.2,  "succès":         2.2,
    "victoire":       2.4,  "gagne":          2.0, "gagné":           2.0,
    "joie":           2.6,  "bonheur":        2.8, "fierte":          2.2, "fierté": 2.2,
    "amour":          2.5,  "aime":           1.9,
    "merci":          1.3,  "super":          2.0,
    "beau":           1.8,  "belle":          1.8,
    "chouette":       1.7,  "super":          2.0,
    "optimiste":      1.8,  "positif":        1.5, "positive":        1.5,
    "confiant":       1.6,  "confiante":      1.6,
    "enthousiaste":   2.2,  "motiv":          1.8, "motivé":          1.8,
    "fier":           2.0,  "fiere":          2.0, "fière":           2.0,
    "reconnaissant":  1.9,  "reconnaissante": 1.9,

    # ── Émojis textuels ───────────────────────────────────────────────────────
    ":)":             2.0,  ":-)":            2.0, ":D":              2.5,
    ":(":             -2.0, ":-(":            -2.0, ":/":             -1.0,
    "^^":             1.6,  "<3":             2.5, "</3":             -2.0,
    "xd":             1.8,  "lol":            1.2, "mdr":             1.2,
}


def _inject_french_lexicon(vader_instance) -> None:
    """
    Injecte le lexique français dans VADER.
    Pour chaque mot, on injecte aussi la version sans accents pour couvrir
    les cas où l'utilisateur ne tape pas les accents.
    """
    for word, score in _FR_LEXICON_RAW.items():
        vader_instance.lexicon[word] = score
        # Version sans accents (NFD → supprime les diacritiques)
        normalized = unicodedata.normalize('NFD', word)
        no_accent  = ''.join(c for c in normalized if unicodedata.category(c) != 'Mn')
        if no_accent != word:
            vader_instance.lexicon[no_accent] = score


# ── Seuils ────────────────────────────────────────────────────────────────────
POSITIVE_THRESHOLD = 0.05
NEGATIVE_THRESHOLD = -0.05
MIN_WORDS          = 3       # Minimum pour une analyse fiable


# ── Nettoyage ─────────────────────────────────────────────────────────────────
_RE_TIMESTAMP = re.compile(r'\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]')
_RE_SEPARATOR = re.compile(r'—{3,}')
_RE_KEYTAG    = re.compile(r'\[(?:BACK|TAB|ENTER|CTRL|ALT|SHIFT)[^\]]*\]', re.IGNORECASE)
_RE_SPACES    = re.compile(r' {2,}')

def _clean(text: str) -> str:
    text = _RE_TIMESTAMP.sub(' ', text)
    text = _RE_SEPARATOR.sub(' ', text)
    text = _RE_KEYTAG.sub(' ', text)
    text = _RE_SPACES.sub(' ', text)
    return text.strip()


# ── Analyse principale ────────────────────────────────────────────────────────
def analyze_sentiment(text: str) -> dict:
    """
    Analyse le sentiment d'un texte (FR ou EN).

    Retour
    ------
    dict :
        score      : float [-1.0, +1.0]
        label      : 'positif' | 'négatif' | 'neutre' | 'trop_court' | 'erreur_librairie'
        confidence : float [0.0, 1.0]  — force du signal
        timestamp  : str ISO 8601
        text       : str nettoyé
        details    : dict VADER brut
        word_count : int
    """
    ts         = datetime.now().isoformat()
    text_clean = _clean(text)
    word_count = len(text_clean.split())

    if word_count < MIN_WORDS:
        return {
            "score": 0.0, "label": "trop_court", "confidence": 0.0,
            "timestamp": ts, "text": text_clean, "details": {}, "word_count": word_count,
        }

    analyzer = _get_analyzer()
    if analyzer is None:
        return {
            "score": 0.0, "label": "erreur_librairie", "confidence": 0.0,
            "timestamp": ts, "text": text_clean, "details": {}, "word_count": word_count,
        }

    scores   = analyzer.polarity_scores(text_clean)
    compound = scores["compound"]

    if compound >= POSITIVE_THRESHOLD:
        label = "positif"
    elif compound <= NEGATIVE_THRESHOLD:
        label = "négatif"
    else:
        label = "neutre"

    # Confiance : magnitude du signal + richesse lexicale
    confidence = round(
        min(abs(compound) * 0.7 + min(word_count / 15, 1.0) * 0.3, 1.0), 3
    )

    return {
        "score":      round(compound, 4),
        "label":      label,
        "confidence": confidence,
        "timestamp":  ts,
        "text":       text_clean,
        "details": {
            "neg":      scores["neg"],
            "neu":      scores["neu"],
            "pos":      scores["pos"],
            "compound": compound,
        },
        "word_count": word_count,
    }


def analyze_sentences_from_log(log_text: str) -> list:
    """
    Découpe le log en phrases et analyse chacune.
    Séparateurs : retour à la ligne ET point/point d'exclamation/interrogation.
    Filtre les lignes vides, les timestamps et les séparateurs.
    """
    lines = []
    for raw in log_text.split("\n"):
        line = _clean(raw)
        if not line or line.startswith("—") or len(line) < 3:
            continue
        # Découper sur ponctuation forte
        for sub in re.split(r'[.!?;]+', line):
            sub = sub.strip()
            if sub:
                lines.append(sub)

    return [analyze_sentiment(s) for s in lines if s]


def save_sentiment_results(results: list, output_path: str = "data/sentiments.json") -> None:
    """Sauvegarde les résultats (append, ignore les trop_court)."""
    dir_part = os.path.dirname(output_path)
    if dir_part:
        os.makedirs(dir_part, exist_ok=True)

    existing = []
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []

    for r in results:
        if r.get("label") == "trop_court":
            continue  # Ne pas polluer le dashboard avec les micro-fragments
        existing.append({
            "timestamp":  r["timestamp"],
            "text":       r["text"],
            "sentiment":  r["label"],
            "score":      r["score"],
            "confidence": r.get("confidence", 0.0),
            "details":    r.get("details", {}),
            "word_count": r.get("word_count", 0),
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)


# ── Test standalone ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Reproduction exacte des phrases vues dans le dashboard PDF
    samples = [
        # Depuis le PDF (dashboard réel)
        "je suis en detresse",
        "c est horrible",
        "quel cata",
        "c est penible",
        "strophe",
        # Tests supplémentaires français
        "je deteste vraiment ce logiciel",
        "j en ai marre de ces bugs",
        "je suis tres content du resultat",
        "excellent travail bravo",
        "tout va bien aujourd hui",
        "je suis tres stresse par ce projet",
        "furieux contre cette erreur",
        # Tests anglais (compatibilité ascendante)
        "I am so happy today everything is great",
        "This is terrible I hate this",
    ]

    print(f"\n{'Texte':<45} {'Label':<12} {'Score':>8}  {'Conf':>5}")
    print("─" * 75)
    for s in samples:
        r = analyze_sentiment(s)
        flag = "✅" if r["label"] != "trop_court" else "⚠️ "
        print(f"{flag} {s[:43]:<43} {r['label']:<12} {r['score']:>+8.4f}  {r.get('confidence', 0):>5.3f}")
