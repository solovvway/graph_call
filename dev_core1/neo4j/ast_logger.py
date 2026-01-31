#!/usr/bin/env python3
"""
Модуль для логирования работы с AST (Abstract Syntax Tree).
Извлечен из auditor.py для переиспользования.
"""

import sys
from typing import Dict, List
from pathlib import Path


class ASTLogger:
    """Класс для логирования прогресса парсинга AST."""
    
    def __init__(self, total_files: int = 0):
        self.total_files = total_files
        self.files_processed = 0
        self.bar_length = 50
    
    def init_progress(self, lang: str = ""):
        """Инициализирует прогресс-бар для текущего языка."""
        if self.total_files > 0:
            sys.stdout.write(f"\r[AST PROGRESS] [{'░' * self.bar_length}] Files parsed: {self.files_processed}/{self.total_files} ({lang})")
            sys.stdout.flush()
    
    def update_progress(self, lang: str = ""):
        """Обновляет прогресс-бар после обработки файла."""
        if self.total_files > 0:
            filled = int((self.files_processed / self.total_files) * self.bar_length)
            filled = min(self.bar_length, filled)
            bar = "█" * filled + "░" * (self.bar_length - filled)
            percentage = int((self.files_processed / self.total_files) * 100)
            progress_text = f"\r[AST PROGRESS] [{bar}] Files parsed: {self.files_processed}/{self.total_files} ({percentage}%) - {lang}"
            sys.stdout.write(progress_text)
            sys.stdout.flush()
    
    def increment(self):
        """Увеличивает счетчик обработанных файлов."""
        self.files_processed += 1
    
    def finish(self):
        """Завершает прогресс-бар (переходит на новую строку)."""
        if self.total_files > 0:
            print()  # Новая строка после завершения прогресс-бара
    
    @staticmethod
    def calculate_total_files(files_map: Dict[str, List[Path]]) -> int:
        """Подсчитывает общее количество файлов для прогресс-бара."""
        return sum(len(paths) for paths in files_map.values())
