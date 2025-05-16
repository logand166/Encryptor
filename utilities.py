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
    def calculate_strength(password: str) -> int:
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
    def get_strength_color(strength: int) -> QColor:
        if strength < 30:
            return QColor(255, 0, 0)  # Red
        elif strength < 70:
            return QColor(255, 255, 0)  # Yellow
        else:
            return QColor(0, 255, 0)  # Green


def strength(length: int) -> int:
    strength = LENGTH_STRENGTH[length]
    return strength


def generate_seed_phrase(strength: int = 128, lang: str = "en") -> str:
    """Generate a seed phrase using the Mnemonic library.
    The seed phrase is generated based on the specified strength and language.

    Args:
        strength (int): The strength of the seed phrase. It should be one of the following values:
            128, 160, 192, 224, or 256.
            The default is 128.
        lang (str): The language for the seed phrase. It should be one of the following values:
            "en", "zh", "zh2", "fr", "it", "ja", "ko", or "es".
        The default is "en" (English).

    Returns:
        str: The generated seed phrase.
    """
    mnemo = Mnemonic(LANGUAGES[lang])

    seed_phrase = mnemo.generate(strength=strength)
    seed_list = seed_phrase.split()
    final_seed_list = [unidecode(word) for word in seed_list]
    final_seed_phrase = " ".join(final_seed_list)

    return final_seed_phrase

def log_activity(type: str, path: str = "./", files: str = None) -> None:
    """
    Log the activity of the user along with timestamp.
    Args:
        type (str): The type of activity to log.
    """
    import os
    import csv
    from datetime import datetime

    # Get the current timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if files is None:
        return

    # Create the log message
    if type == "encrypt":
        log_message = f"Encrypted {files} in {path}"
    elif type == "decrypt":
        log_message = f"Decrypted {files} in {path}"
    elif type == "directory-structure":
        log_message = f"{files}"
    elif type == "error":
        log_message = f"Error occurred: {files}"
    elif type == "success":
        log_message = f"Success: {files}"
    elif type == "recover":
        log_message = f"Recovery: {files} at {path}"
    else:
        type = "unknown"
        log_message = f"Unknown activity: {type}"

    # if the path includes a file, get the directory
    if os.path.isfile(path):
        path = os.path.dirname(path)

    # Write the log message to a .log file
    with open(os.path.join(path, "activity.log"), "a") as log_file:
        log_file.write(f"{timestamp} - {log_message}\n")

    # Write the log message to a .csv file
    csv_file_path = os.path.join(path, "activity.log")
    file_exists = os.path.isfile(csv_file_path)
    with open(csv_file_path, "a", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        if not file_exists:
            # Write the header if the file doesn't exist
            csv_writer.writerow(["Timestamp", "Activity", "Path"])
        csv_writer.writerow([timestamp, type, log_message])

if __name__ == "__main__":
    # Example usage
    log_activity("encrypt", "./", "example.txt")
    log_activity("decrypt", "./", "example.txt")
    log_activity("directory-structure", "./", "example_dir")
    log_activity("error", "./", "example_error")
    log_activity("success", "./", "example_success")
    log_activity("unknown", "./", "example_unknown")
    log_activity("unknown", "./", "example_unknown")

def convert_to_multi_line(text: str) -> str:
    """
    Convert a single line of text into a multi-line string.
    Args:
        text (str): The input text to convert.
    Returns:
        str: The converted multi-line string.
    """
    return "\n".join(text.split(";"))