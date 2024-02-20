# Скрипт для получения публичных SSH ключей пользователя get_ssh_pub_key.py

Этот скрипт предназначен для получения публичных SSH ключей пользователя из Active Directory (AD) с возможностью кэширования и автоматическим обновлением кэша. Также скрипт может читать локальные публичные ключи пользователя, если они существуют.

## Требования

Для работы скрипта необходимо:

- Python 3
- Библиотеки Python: `ldap3`, `python-dotenv`
- Наличие файла конфигурации в формате `.env` для хранения настроек подключения к AD и других параметров

## Установка

1. Убедитесь, что у вас установлен Python версии 3.x.
2. Установите необходимые зависимости, используя `pip`:

```bash
pip install ldap3 python-dotenv

## Использование

Здесь возникает проблемка передачи переменной окружения в sshd
Решил так "/etc/ssh/sshd_config":

AuthorizedKeysCommand /usr/bin/env SSH_GET_PUBKEY=/opt/get_pub_ssh_key /opt/get_pub_ssh_key/bin/get_ssh_pub_key.py %u
AuthorizedKeysCommandUser root

# Скрипт для синхронизации SSH ключей из Active Directory compare_ad_ssh_keys_with_cache.py



