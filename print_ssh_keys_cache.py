#!/bin/env python3
# -*- coding: utf-8 -*-

import shelve

def print_ssh_keys_cache(cache_file='ssh_keys_cache.db'):
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
                print("Время кэширования:", value['timestamp'])
                print("-" * 30)

    except Exception as e:
        print(f"Произошла ошибка при чтении файла кэша: {e}")

if __name__ == '__main__':
    print_ssh_keys_cache()

