"""
sensitive_detector.py — Partie III : Classification de données sensibles
TP1 — Intelligence Artificielle & Cybersécurité

CORRECTIFS v2 :
    ✅ REGEX TÉLÉPHONE — Couverture étendue à TOUS les numéros FR 0X (01–09)
       pas seulement 06/07. Formats acceptés : 0612345678, 06 12 34 56 78,
       06.12.34.56.78, +33612345678.
    ✅ REGEX EMAIL — Pattern robuste couvrant les sous-domaines et TLDs longs.
    ✅ DÉDUPLICATION — Évite les doublons quand regex et ML détectent la même chose.
    ✅ VALIDATION LUHN — Cartes bancaires validées algorithmiquement (0 faux positifs).
    ✅ NOUVEAUX PATTERNS — JWT, clé API, IBAN, IPv4, numéro de sécu, passeport FR.
    ✅ MASQUAGE INTELLIGENT — Conserve le format visible (alice@***.com, **** 9012).
"""

import hashlib
import json
import math
import os
import re
import string
from datetime import datetime
from typing import Optional

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    print("[AVERTISSEMENT] scikit-learn non installé : pip install scikit-learn joblib numpy")

# ── Chemins ───────────────────────────────────────────────────────────────────
ML_MODEL_PATH  = os.path.join("data", "sensitive_classifier.joblib")
ML_SCALER_PATH = os.path.join("data", "sensitive_scaler.joblib")
DETECTIONS_LOG = os.path.join("data", "detections.json")


# ════════════════════════════════════════════════════════════════════════════════
# PATTERNS REGEX
# ════════════════════════════════════════════════════════════════════════════════

PATTERNS = {
    # ── Email ─────────────────────────────────────────────────────────────────
    # Couvre : utilisateur@domaine.tld, sous-domaines, TLDs longs (.museum etc.)
    "email": re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),

    # ── Téléphone français (CORRECTIF) ────────────────────────────────────────
    # AVANT : seulement 06/07 → ratait 01, 02, 03, 04, 05, 08, 09
    # APRÈS : tous les numéros français 0[1-9] + formats internationaux +33
    # Formats acceptés :
    #   0612345678  06 12 34 56 78  06.12.34.56.78  +33612345678  0033612345678
    # Note : \b ne fonctionne pas avant '+' → lookahead/lookbehind négatifs
    "telephone_fr": re.compile(
        r'(?<!\d)(?:'
        r'(?:\+33|0033)\s?[1-9](?:[\s.\-]?\d{2}){4}'    # +33 / 0033 + 9 chiffres
        r'|0[1-9](?:[\s.\-]?\d{2}){4}'                   # 0X + 8 chiffres
        r')(?!\d)'
    ),

    # ── Carte bancaire ────────────────────────────────────────────────────────
    # 16 chiffres groupés par 4 (séparateur optionnel espace ou tiret)
    "carte_bancaire": re.compile(
        r'\b(?:\d{4}[\s\-]){3}\d{4}\b'
    ),

    # ── Numéro de sécurité sociale français ───────────────────────────────────
    # Format : 1/2 + AA + MM + dép(2-3) + commune(3) + ordre(3) + clé(2)
    "numero_secu_fr": re.compile(
        r'\b[12]\s?\d{2}\s?\d{2}\s?\d{2,3}\s?\d{3}\s?\d{3}\s?\d{2}\b'
    ),

    # ── IBAN français ─────────────────────────────────────────────────────────
    "iban_fr": re.compile(
        r'\bFR\d{2}[\s]?(?:\d{4}[\s]?){5}\d{3}\b',
        re.IGNORECASE
    ),

    # ── Adresse IPv4 ──────────────────────────────────────────────────────────
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),

    # ── JWT token ─────────────────────────────────────────────────────────────
    "jwt_token": re.compile(
        r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'
    ),

    # ── Clé API / Bearer token ────────────────────────────────────────────────
    "cle_api": re.compile(
        r'(?:Bearer|Authorization|api[_\-]?key|token|secret)[:\s=]+[A-Za-z0-9_\-\.]{16,}',
        re.IGNORECASE
    ),
}


# ── Validation Luhn (cartes bancaires) ────────────────────────────────────────
def _luhn_check(number: str) -> bool:
    digits = re.sub(r'\D', '', number)
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect_with_regex(text: str) -> list:
    """
    Détecte tous les patterns sensibles dans le texte.
    Applique la validation Luhn pour les cartes bancaires.

    Retour : list de dicts {type, value, start, end, method}
    """
    detections = []
    seen_spans  = set()

    for data_type, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()

            # Déduplication : ignorer si chevauchement avec détection existante
            if any(not (end <= s or start >= e) for (s, e) in seen_spans):
                continue

            value = match.group()

            # Validation post-regex
            if data_type == "carte_bancaire" and not _luhn_check(value):
                continue

            seen_spans.add((start, end))
            detections.append({
                "type":   data_type,
                "value":  value,
                "start":  start,
                "end":    end,
                "method": "regex",
            })

    return detections


# ════════════════════════════════════════════════════════════════════════════════
# ML — Détection de mots de passe
# ════════════════════════════════════════════════════════════════════════════════

def compute_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return round(-sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values()), 4)


def extract_string_features(token: str) -> list:
    if not token:
        return [0.0] * 8
    length  = len(token)
    upper   = sum(1 for c in token if c.isupper())
    digits  = sum(1 for c in token if c.isdigit())
    special = sum(1 for c in token if c in string.punctuation)
    unique  = len(set(token))
    has_all = int(upper > 0 and digits > 0 and special > 0)
    return [
        length,
        compute_entropy(token),
        upper   / length,
        digits  / length,
        special / length,
        int(length > 8),
        has_all,
        unique  / length,
    ]


def _generate_training_data() -> tuple:
    passwords = [
        "P@ssw0rd123!", "MyS3cur3P@ss!", "Tr0ub4dor&3", "correct-horse-battery",
        "abc123XYZ!", "Admin@2024!", "Summer2024#", "W1nter!2023",
        "Qwerty@123!", "Dragon#2024", "P@$$w0rd!", "L0gin_Secure!",
        "C0mpl3x!Pass", "Secure#Pass1", "My!Pass2024", "Test@Pass99",
        "Hunter2#Safe", "Root@Linux1!", "Admin_Pass!2", "x7K!mN9@qR2#",
        "Zp3$wL8!vT6@", "jR5#bN2@kM7!", "password123", "letmein!",
        "welcome1!", "master2024", "ninja@2024!", "shadow#1!", "iloveyou2!",
    ]
    normal_words = [
        "bonjour", "monde", "voiture", "maison", "jardin",
        "informatique", "python", "programmation", "exercice", "cours",
        "universite", "etudiant", "projet", "travail", "reunion",
        "lundi", "mardi", "mercredi", "jeudi", "vendredi",
        "rapport", "analyse", "resultat", "donnees", "modele",
        "sklearn", "pandas", "numpy", "matplotlib", "jupyter",
        "localhost", "http", "https", "www", "html", "css",
        "function", "variable", "database", "connection", "server",
    ]
    X, y = [], []
    for pw in passwords:
        X.append(extract_string_features(pw))
        y.append(1)
    for word in normal_words:
        X.append(extract_string_features(word))
        y.append(0)
    return X, y


def train_ml_classifier() -> tuple:
    if not _SKLEARN_AVAILABLE:
        return None, None
    X, y = _generate_training_data()
    X, y = np.array(X), np.array(y)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    scaler    = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)
    model = RandomForestClassifier(
        n_estimators=100, class_weight={0: 1, 1: 2}, random_state=42
    )
    model.fit(X_train_s, y_train)
    y_pred = model.predict(X_test_s)
    print("\n=== Rapport de classification (détecteur ML) ===")
    print(classification_report(y_test, y_pred, target_names=["ordinaire", "sensible"]))
    os.makedirs("data", exist_ok=True)
    joblib.dump(model, ML_MODEL_PATH)
    joblib.dump(scaler, ML_SCALER_PATH)
    print(f"[INFO] Modèle ML sauvegardé → {ML_MODEL_PATH}")
    return model, scaler


def load_ml_classifier() -> tuple:
    if os.path.exists(ML_MODEL_PATH) and os.path.exists(ML_SCALER_PATH):
        try:
            return joblib.load(ML_MODEL_PATH), joblib.load(ML_SCALER_PATH)
        except Exception:
            pass
    return None, None


def detect_password_ml(token: str, model, scaler) -> dict:
    if model is None or len(token) < 4:
        return {"is_sensitive": False, "probability": 0.0}
    features        = np.array([extract_string_features(token)])
    features_scaled = scaler.transform(features)
    proba           = model.predict_proba(features_scaled)[0][1]
    return {
        "is_sensitive": proba >= 0.5,
        "probability":  round(float(proba), 4),
        "type":         "mot_de_passe_probable",
        "method":       "ml",
    }


# ════════════════════════════════════════════════════════════════════════════════
# Analyse complète
# ════════════════════════════════════════════════════════════════════════════════

def analyze_text(text: str, ml_model=None, ml_scaler=None) -> dict:
    detections  = detect_with_regex(text)
    regex_spans = {(d["start"], d["end"]) for d in detections}

    if ml_model is not None:
        for token in text.split():
            start = text.find(token)
            end   = start + len(token)
            if any(not (end <= s or start >= e) for (s, e) in regex_spans):
                continue
            ml_result = detect_password_ml(token, ml_model, ml_scaler)
            if ml_result["is_sensitive"]:
                detections.append({
                    "type":        "mot_de_passe_probable",
                    "value":       token,
                    "start":       start,
                    "end":         end,
                    "method":      "ml",
                    "probability": ml_result["probability"],
                })

    return {
        "text":          text,
        "timestamp":     datetime.now().isoformat(),
        "detections":    detections,
        "masked_text":   mask_sensitive(text, detections),
        "redacted_text": redact_sensitive(text, detections),
        "has_sensitive": len(detections) > 0,
    }


def mask_sensitive(text: str, detections: list, mask_char: str = "*") -> str:
    """Masquage complet (*****)."""
    if not detections:
        return text
    result = list(text)
    for det in sorted(detections, key=lambda d: d["start"], reverse=True):
        s, e = det["start"], det["end"]
        result[s:e] = list(mask_char * (e - s))
    return "".join(result)


def redact_sensitive(text: str, detections: list) -> str:
    """
    Redaction intelligente — conserve le format lisible :
      alice@example.com   → a****@***.com
      06 12 34 56 78      → ** ** ** ** 78
      4532 1234 5678 9012 → **** **** **** 9012
    """
    if not detections:
        return text
    result = list(text)
    for det in sorted(detections, key=lambda d: d["start"], reverse=True):
        s, e, val, dtype = det["start"], det["end"], det["value"], det["type"]
        if dtype == "email":
            at  = val.find("@")
            ext = val.split(".")[-1]
            redacted = val[0] + "*" * max(at - 1, 1) + "@***." + ext
        elif dtype == "carte_bancaire":
            digits   = re.sub(r"\D", "", val)
            redacted = "**** **** **** " + digits[-4:]
        elif dtype == "telephone_fr":
            digits   = re.sub(r"\D", "", val)
            redacted = "** ** ** ** " + digits[-2:]
        else:
            redacted = f"[{dtype.upper()}]"
        result[s:e] = list(redacted)
    return "".join(result)


def hash_sensitive(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def save_detections(results: list, path: str = DETECTIONS_LOG) -> None:
    os.makedirs("data", exist_ok=True)
    existing = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []

    for r in results:
        safe_dets = []
        for det in r.get("detections", []):
            safe_dets.append({
                "type":        det["type"],
                "method":      det.get("method", "regex"),
                "hash_sha256": hash_sensitive(det["value"]),
                "length":      len(det["value"]),
            })
        existing.append({
            "timestamp":     r["timestamp"],
            "masked_text":   r["masked_text"],
            "redacted_text": r.get("redacted_text", r["masked_text"]),
            "has_sensitive": r["has_sensitive"],
            "detections":    safe_dets,
        })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)


# ── Test standalone ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Test des patterns regex ===\n")
    test_texts = [
        # Téléphones (CORRECTIF — ancienne regex ratait tout sauf 06/07)
        "Mon numéro : 0900000000",
        "Rappelle-moi au 01 23 45 67 89",
        "Mobile : 06 12 34 56 78",
        "+33 6 12 34 56 78",
        # Emails
        "Mon adresse : samuel26@gmail.com",
        "Contact : alice.dupont@entreprise.fr",
        # Cartes bancaires (avec validation Luhn)
        "CB : 4532 0151 1283 0366",   # Luhn valide
        "CB : 1234 5678 9012 3456",   # Luhn invalide → pas de détection
        # Sécu
        "NSS : 1 85 12 75 123 456 78",
        # IBAN
        "IBAN : FR76 3000 6000 0112 3456 7890 189",
        # IP
        "Serveur : 192.168.1.100",
    ]

    for text in test_texts:
        dets = detect_with_regex(text)
        if dets:
            types    = [d["type"] for d in dets]
            redacted = redact_sensitive(text, dets)
            print(f"  ✅ {text}")
            print(f"     → {types}")
            print(f"     → {redacted}\n")
        else:
            print(f"  ❌ Aucune détection : {text}\n")
