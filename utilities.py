from PyQt5.QtGui import QColor
import re

from mnemonic import Mnemonic
from unidecode import unidecode

LANGUAGES = {
    "en": "english",
    "zh": "chinese_simplified",
    "zh2": "chinese_traditional",
    "fr": "french",
    "it": "italian",
    "ja": "japanese",
    "ko": "korean",
    "es": "spanish",
}

STRENGTHS = [128, 160, 192, 224, 256]

LENGTHS = [12, 15, 18, 21, 24]

LENGTH_STRENGTH = dict(zip(LENGTHS, STRENGTHS))


class PasswordStrengthMeter:
    @staticmethod
    def calculate_strength(password):
        if not password:
            return 0

        strength = 0

        # Length check
        length = len(password)
        if length >= 8:
            strength += 1
        if length >= 12:
            strength += 1
        if length >= 16:
            strength += 1

        # Character diversity
        if re.search(r"[A-Z]", password):
            strength += 1
        if re.search(r"[a-z]", password):
            strength += 1
        if re.search(r"[0-9]", password):
            strength += 1
        if re.search(r"[^A-Za-z0-9]", password):
            strength += 1

        # Normalize to 0-100 range
        max_possible = 7  # 3 for length + 4 for diversity
        return int((strength / max_possible) * 100)

    @staticmethod
    def get_strength_color(strength):
        if strength < 30:
            return QColor(255, 0, 0)  # Red
        elif strength < 70:
            return QColor(255, 255, 0)  # Yellow
        else:
            return QColor(0, 255, 0)  # Green


def strength(length: int) -> int:
    strength = LENGTH_STRENGTH[length]
    return strength


def generate_seed_phrase(strength: int, lang: str) -> str:
    mnemo = Mnemonic(LANGUAGES[lang])

    seed_phrase = mnemo.generate(strength=strength)
    seed_list = seed_phrase.split()
    final_seed_list = [unidecode(word) for word in seed_list]
    final_seed_phrase = " ".join(final_seed_list)

    return final_seed_phrase
