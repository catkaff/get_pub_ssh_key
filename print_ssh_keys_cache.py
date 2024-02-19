#!/bin/env python3
# -*- coding: utf-8 -*-

import shelve
import argparse
import sys
from datetime import datetime

def print_ssh_keys_cache(cache_file):
    """
    Выводит все ключи и значения из файла кэша ssh_keys_cache.db.
    """
    try:
        with shelve.open(cache_file, 'r') as cache:
            if not cache:
                print("Кэш пуст.")
                return

            for key, value in cache.items():
                print(f"Пользователь: {key}")
                print("SSH ключи:")
                for ssh_key in value['keys']:
                    print(ssh_key)

                # Преобразование времени кэширования в человекочитаемый формат
                cache_time = datetime.fromtimestamp(value['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                print("Время кэширования:", cache_time)
                print("-" * 30)

    except Exception as e:
        print(f"Произошла ошибка при чтении файла кэша: {e}")

def main():
    parser = argparse.ArgumentParser(description="Выводит все ключи и значения из файла кэша ssh_keys_cache.db.")
    parser.add_argument("cache_file", nargs='?', default="ssh_keys_cache.db", help="Путь к файлу кэша ssh_keys_cache.db")
    
    args = parser.parse_args()

    # Если аргументы не были предоставлены, выводим справку
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    print_ssh_keys_cache(args.cache_file)

if __name__ == '__main__':
    main()

