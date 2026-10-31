"""JSON-backed presentation translations; diagnostic operations stay unchanged."""
import json
from pathlib import Path
import re


class Translator:
    def __init__(self, directory=None):
        # __file__ resolves inside PyInstaller's bundled data directory too.
        directory = Path(directory) if directory else Path(__file__).with_name('locales')
        self.catalogs = {}
        for path in sorted(directory.glob('*.json')):
            data = json.loads(path.read_text(encoding='utf-8'))
            self.catalogs[path.stem] = data
        self.catalogs.setdefault('en', {'name': 'English', 'strings': {}})
        self.language = 'en'
        self._patterns = {}

    def select(self, language):
        if language not in self.catalogs:
            raise ValueError('Unknown language: ' + language)
        self.language = language

    def t(self, source):
        return self.catalogs[self.language].get('strings', {}).get(source, source)

    def log(self, text):
        if self.language == 'en':
            return text
        lines = []
        for line in text.splitlines(keepends=True):
            match = re.fullmatch(r'(\[\d{2}:\d{2}:\d{2}\] )?(.*?)(\r?\n)?', line)
            if not match:
                lines.append(line)
                continue
            stamp, message, ending = match.groups()
            leading = message[:len(message) - len(message.lstrip())]
            original = message.lstrip()
            translated = self.t(original)
            if translated == original:
                for pattern, target in self._log_patterns():
                    found = pattern.fullmatch(original)
                    if found:
                        values = self.catalogs[self.language].get('log_values', {})
                        translated = target.format(*(values.get(value, value) for value in found.groups()))
                        break
            # Retain the exact original diagnostic text for support/searching.
            if translated != original:
                lines.append((stamp or '') + leading + translated + '\n')
                lines.append((stamp or '') + leading + '[EN] ' + original + (ending or ''))
            else:
                lines.append(line)
        return ''.join(lines)

    def _log_patterns(self):
        if self.language not in self._patterns:
            patterns = []
            for item in self.catalogs[self.language].get('logs', []):
                # {0}, {1}, ... are data fields, never executable regex/format code.
                parts = re.split(r'(\{\d+\})', item['source'])
                expression = ''.join('(.*?)' if re.fullmatch(r'\{\d+\}', p) else re.escape(p) for p in parts)
                patterns.append((re.compile(expression), item['translation']))
            self._patterns[self.language] = patterns
        return self._patterns[self.language]
