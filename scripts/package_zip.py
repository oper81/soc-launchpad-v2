"""Упаковка проекта в zip (stdlib).

Исключает: labs/, __pycache__, .venv, .git.
Запуск: python scripts/package_zip.py
"""
import os
import zipfile
from datetime import datetime

IGNORE_DIRS = {".git", ".venv", "__pycache__", "labs", ".idea", ".vscode"}
IGNORE_EXT = {".pyc", ".pyo", ".jsonl", ".csv"}

def make_zip(output_name="soc-launchpad.zip"):
    # Корень проекта — директория, где лежит папка scripts
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    with zipfile.ZipFile(output_name, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(root_dir):
            # Исключаем ненужные папки
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            
            for file in files:
                if os.path.splitext(file)[1] in IGNORE_EXT:
                    continue
                
                file_path = os.path.join(root, file)
                # Путь внутри архива относительно корня
                arcname = os.path.relpath(file_path, root_dir)
                
                # Не пакуем сам скрипт упаковки и архив
                if arcname == output_name or arcname == os.path.join("scripts", "package_zip.py"):
                    continue
                    
                zf.write(file_path, arcname)
    
    print(f"Готово: {output_name} ({os.path.getsize(output_name)} байт)")

if __name__ == "__main__":
    make_zip()