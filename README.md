# get_pub_ssh_key
get publick ssh key from local and from AD



# Здесь возникает проблемка передачи переменной окружения в sshd
# Решил так "/etc/ssh/sshd_config":

# AuthorizedKeysCommand /usr/bin/env SSH_GET_PUBKEY=/opt/get_pub_ssh_key /opt/get_pub_ssh_key/bin/get_ssh_pub_key.py %u
# AuthorizedKeysCommandUser root

