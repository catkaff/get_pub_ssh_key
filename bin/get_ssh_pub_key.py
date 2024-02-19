#!/bin/env python3
# -*- coding: utf-8 -*-
from ldap3 import Connection, Server, ALL, Tls, SUBTREE
import sys, logging, ssl, os
from dotenv import load_dotenv
import re
import shelve
import time

# проверяет, можно ли записать в файл логов. Если нет, она настраивает логирование в stderr. Это предотвращает прерывание скрипта из-за ошибок доступа к файлу логов.

def setup_logging(script_log_file, script_log_level, log_format, log_datefmt, log_encoding='utf-8'):
    # Получаем корневой логгер
    logger = logging.getLogger()
    # Устанавливаем уровень логирования
    logger.setLevel(logging.getLevelName(script_log_level))

    # Очищаем существующие обработчики, чтобы избежать дублирования сообщений
    while logger.handlers:
        logger.handlers.pop()

    # Проверяем, существует ли директория для файла лога, и создаем ее при необходимости
    log_dir = os.path.dirname(script_log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    # Настраиваем обработчик для записи логов в файл
    try:
        file_handler = logging.FileHandler(script_log_file, encoding=log_encoding)
    except Exception as e:
        # Если возникает ошибка при создании FileHandler, логируем в stderr
        logging.basicConfig(level=logging.getLevelName(script_log_level), format=log_format, datefmt=log_datefmt)
        logging.error(f"Failed to create log file handler: {e}. Logging to stderr instead.")
        return

    file_handler.setFormatter(logging.Formatter(log_format, datefmt=log_datefmt))
    logger.addHandler(file_handler)

# Обрезаем имя домена
def format_username(username: str, ad_domain: str, ipa_domain: str) -> str:
    if ad_domain in username:
        return username.replace(ad_domain,'')
    elif ipa_domain in username:
        return username.replace(ipa_domain, '')
    else:
        return username

# Функция соединения с АД по защищенному шифрованному соединению по 636 порту с использованием корневого сертификата домена.
# AD connect
def ad_connect(ad_user, ad_user_password, ad_kds, adca):

    # Проверяем, существует ли файл сертификата и доступен ли он для чтения
    if not os.path.isfile(adca) or not os.access(adca, os.R_OK):
        logging.error(f"CA certificate file does not exist or is not readable: {adca}")
        sys.exit(1)

    tlset = Tls(validate=ssl.CERT_OPTIONAL, version=ssl.PROTOCOL_TLSv1_2, ca_certs_file=adca)
    timeout = 10
    for ad_kd in ad_kds:
        try:
            server = Server(ad_kd, port=636, use_ssl=True, get_info=ALL, tls=tlset, connect_timeout=timeout)
            ad_connection = Connection(server, ad_user, ad_user_password, read_only=False, lazy=False)
            ad_connection.open()
            if ad_connection.bind():
                logging.info(f'==> AD_KD_Server {ad_kd} connect_status: {ad_connection.result}\n')
                return ad_connection
            else:
                logging.info(f'==> AD_KD_Server {ad_kd} bind_failed: {ad_connection.result}')
        except Exception as e:
            logging.info(f'==> AD_KD_Server {ad_kd} ERROR: {e}')
    logging.error(f'All AD server connections failed: {ad_kds}')
    sys.exit(1)
#  END Connect


# Получает ключи SSH пользователя из AD с кэшированием и истечением срока действия кэша.
def get_user_ad_key_with_expiry(ad_user, ad_user_password, ad_kds, adca, ad_users_dn, username: str, cache_file, expiry):
    """
    :param ad_users_dn: DN (Distinguished Name) для пользователей в AD
    :param username: имя пользователя
    :param cache_file: путь к файлу кэша
    :param expiry: время жизни кэша в секундах (по умолчанию 86400 секунд, т.е. 1 день)
    :return: SSH ключи пользователя или None
    """
    with shelve.open(cache_file) as cache:
        current_time = time.time()
        cached_data = cache.get(username)

        # Проверяем, есть ли данные в кэше и не истек ли их срок
        if cached_data and current_time - cached_data['timestamp'] < expiry:
            logging.info(f'Public ssh key for the {username} in the cache and has not expired')
            return cached_data['keys']
        else:
            logging.info(f'Public ssh key for the {username} does not exist or has expired')

        # Если данных нет в кэше или истек срок, запрашиваем из AD
                # Соединяемся с АД согласно полученным кредам
        ad_connection = ad_connect(ad_user, ad_user_password, ad_kds, adca)
        search_filter = f'(sAMAccountName={username})'
        ad_connection.search(search_base=ad_users_dn, search_filter=search_filter, search_scope=SUBTREE,
                             attributes=['altSecurityIdentities'])
        if ad_connection.entries:
            user = ad_connection.entries[0]
            altSecurityIdentities = user.entry_attributes_as_dict['altSecurityIdentities']
            # Сохраняем результат в кэш с временной меткой
            cache[username] = {'keys': altSecurityIdentities, 'timestamp': current_time}
            logging.info(f"SSH keys for user {username} were successfully retrieved from AD and cached.")
            ad_connection.unbind()
            return altSecurityIdentities
        else:
            logging.error(f"Failed to find user {username} in AD.")
            ad_connection.unbind()
            return None

# Читаем локальные для хоста публичные ключи
def read_local_public_key(user: str):
    home_dir = f"/home/{user}"
    auth_keys_path = os.path.join(home_dir, ".ssh", "authorized_keys")

    if os.path.isfile(auth_keys_path):
        try:
            with open(auth_keys_path, 'r') as f:
                keys = f.readlines()
            logging.info(f"Successfully read local public keys for user {user} from {auth_keys_path}.")
            return keys
        except Exception as e:
            logging.error(f"Error reading local public keys for user {user} from {auth_keys_path}: {e}")
            return None
    else:
        logging.warning(f"Authorized keys file does not exist for user {user} at {auth_keys_path}.")
        return None
    
    
    # Главная программа
# SSH_GET_PUBKEY берем из /etc/environment
if __name__ == '__main__':

    script_log_file = "/var/log/get_ssh_pub_key.log"
    script_log_level = "INFO"
    log_format = "%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s"
    log_datefmt = "%Y-%m-%d %H:%M:%S"
    log_encoding = "utf-8"

    # Получим числовое значение уровня логирования
    level = logging.getLevelName(script_log_level)
    # Настраиваем логгирование всех действий скрипта в файл
    setup_logging(script_log_file, logging.getLevelName(script_log_level), log_format, log_datefmt, log_encoding)

    # Получаем путь к базовой директории из переменной окружения
    base_path = os.getenv('SSH_GET_PUBKEY')

# Здесь возникает проблемка передачи переменной окружения в sshd
# Решил так "/etc/ssh/sshd_config":

# AuthorizedKeysCommand /usr/bin/env SSH_GET_PUBKEY=/opt/get_pub_ssh_key /opt/get_pub_ssh_key/bin/get_ssh_pub_key.py %u
# AuthorizedKeysCommandUser root

    if base_path is None:
        logging.info("Переменная окружения SSH_GET_PUBKEY не установлена.")
        sys.exit(1)

    # Строим путь к файлу конфигурации и к файлу базы данных
    config_file_path = os.path.join(base_path, 'etc', 'get_ssh_key.conf')    

    # Проверяем существование файла конфигурации
    if not os.path.exists(config_file_path):
        logging.error(f"Конфигурационный файл {config_file_path} не найден.")
        sys.exit(1)

    # Попытка загрузить переменные окружения из файла .conf
    if not load_dotenv (config_file_path):
        logging.error("Конфигурационный файл не найден.")
        sys.exit(1)

    # Получение настроек из конфигурационного файла:

    ad_groups_dn = os.getenv('ad_groups_dn')
    if ad_groups_dn is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_groups_dn')
        sys.exit(1)

    ad_users_dn = os.getenv('ad_users_dn')
    if ad_users_dn is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_users_dn')
        sys.exit(1)

    ad_kd = os.getenv('ad_server')
    if ad_kd is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_server')
        sys.exit(1)
    # Разделение строки на список серверов с использованием регулярных выражений
    ad_kds = re.split(r'\s*,\s*', ad_kd.strip())

    adca = os.getenv('ad_ca_sert')
    if adca is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_ca_sert')
        sys.exit(1)

    ad_user = os.getenv('ad_user')
    if ad_user is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_user')
        sys.exit(1)

    ad_user_password = os.getenv('ad_user_password')
    if ad_user_password is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_user_password')
        sys.exit(1)

    ad_domain = os.getenv('ad_domain')
    if ad_domain is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_domain')
        sys.exit(1)

    ipa_domain = os.getenv('ipa_domain')
    if ipa_domain is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ipa_domain')
        sys.exit(1)

    cache_file = os.getenv('cache_file')
    
    if cache_file is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: cache_file')
        sys.exit(1)
    else:
        cache_file = os.path.join(base_path, 'etc', cache_file)
        

    # Значение по умолчанию для expiry
    DEFAULT_EXPIRY = 86400  # Например, 1 день = 86400 секунд
    expiry = os.getenv('expiry', DEFAULT_EXPIRY)
    try:
        expiry = int(expiry)
    except ValueError:
        logging.error(f"Значение 'expiry' должно быть целым числом. Используется значение по умолчанию: {DEFAULT_EXPIRY}")
        expiry = DEFAULT_EXPIRY

    if len(sys.argv) > 1:  # проверяем, есть ли аргументы командной строки
        formatted_username = format_username(sys.argv[1], ad_domain, ipa_domain)

# Сначала смотрим есть ли локальный ключ или ключи для данного пользователя, так как это быстрее и приоритетнее при заходе под локальной УЗ
        local_keys = read_local_public_key(formatted_username)
        if local_keys:
            for key in local_keys:
                print(key, end="")
            sys.exit(0)

# Если же локальной УЗ нет, проверяем есть ли ключ для пользователя из АД
        user_ad_key = get_user_ad_key_with_expiry( ad_user, ad_user_password, ad_kds, adca, ad_users_dn, formatted_username, cache_file, expiry)
        if user_ad_key:  # проверка, что dn_user не пустой и не None
            print(''.join(user_ad_key))
            sys.exit(0)
