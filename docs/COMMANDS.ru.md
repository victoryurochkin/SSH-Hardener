# Команды Linux-сервера

Точные команды с параметрами выбранного сервера доступны в предпросмотре приложения. Источники — `Scripts.cs`, `Fail2BanScripts.cs`, `AccessPolicyScripts.cs`; подстановка параметров — `PlanBuilder.cs` в `src/SSHHardener.Profiles`. Sensitive credentials не являются текстом плана и передаются отдельно по stdin. Не применяйте скопированный пример к другому серверу: он связан с transaction ID и аудитом.

| Фаза | Команды и назначение |
| --- | --- |
| Аудит | Чтение `/etc/os-release`, `id`, `uptime`, `ss`, `systemctl`, `sshd -T/-V`, статусов firewall/SELinux/fail2ban; безопасные метаданные без чтения приватных ключей. |
| Preflight | `sshd -t`, `sshd -T`, проверка unit/Include/Match, `getent`, `stat`, `ss`, наличие `flock`, `runuser`, `sudo`/`visudo`, доступность путей и поддерживаемой конфигурации. |
| Arming | Root-only каталог `/var/lib/ssh-hardener/transactions/<id>`, `cp -p` исходного sshd_config, хеши, файлы состояния; persistent service/timer и boot recovery в `/etc/systemd/system/`; `systemctl daemon-reload`, enable/start и фактическая проверка. |
| Fail2ban | После arming: при необходимости ограниченные по времени `apt-get update` и `apt-get install --no-upgrade --no-remove`; временные маски служб, отдельный journal jail, проверка параметров и whitelist. Чужие SSH-jail не перезаписываются. |
| Пользователь | `useradd -m -s /bin/bash` только по выбору создания; установка публичного ключа в `.ssh/authorized_keys` через `runuser`, проверка пути/владельца/прав; legacy sudo сохраняет прежнее поведение. |
| Advanced access | После arming и создания пользователя: Python 3 обрабатывает sensitive stdin, проверяет существующий пароль через libcrypt либо задаёт пароль новому через `chpasswd -e` stdin; пишет отдельный sudoers с `visudo`, root-owned TOTP/PAM/Match proof и SFTP chroot. Недостающий Google PAM на apt-системах устанавливается ограниченной по времени командой с `/dev/null` stdin и общей package lock. |
| Dual-port | Candidate-конфиг, `sshd -t -f`, `sshd -T -f -C`, атомарная замена файла, `systemctl reload`, проверка listener. На этой фазе сохраняется исходная аутентификация. |
| Проверки клиента | Legacy: два свежих key/sudo SSH-сеанса. Advanced: проверка target key на dual, затем финальной роли через SSH/SFTP; при новой MFA — два финальных входа с разными TOTP time steps. Для non-admin отдельно проверяется fresh original-admin key+root на окончательном порту до commit. |
| Final | Окончательная политика аутентификации/root/forwarding и опциональное удаление старого listener; ещё один новый ключевой вход перед commit. |
| Commit | Под блокировкой запись committed и last-committed; отключение timer/boot recovery только после проверки. |
| Rollback | Восстановление sshd_config, собственных PAM/Match/sudoers/TOTP файлов и правил по snapshots/intents; чужие изменения сохраняются как конфликт. Только собственный новый пароль блокируется при совпадении hash; учётная запись и её данные не удаляются. |

## Различия профилей

- Debian/Ubuntu: служба обычно `ssh.service`; Rocky/AlmaLinux — `sshd.service`. Реальное имя берётся из аудита и проверяется, неизвестное отклоняется.
- UFW: добавление только необходимого TCP allow и при запросе отдельного deny старого порта. Правила помечены transaction ID; откат удаляет только принадлежащие операции numbered rules с проверкой комментария.
- Firewalld: одна распознанная zone, отдельные изменения runtime/permanent, запись намерений перед мутацией и удаление только добавленных элементов при откате.
- SELinux: `semanage port` для ssh_port_t и `restorecon`; инструменты должны быть установлены заранее. Запись другой policy не перетирается автоматически.
- Fail2ban: на Debian/Ubuntu отсутствующие зависимости устанавливаются после подготовки отката. Файл `/etc/fail2ban/jail.d/sshhardener-sshd.local` задаёт отдельный jail `sshhardener-sshd`, `backend=systemd`, фильтр с учётом неверных ключей, `maxretry=3`, `findtime=600`, `bantime=3600` по умолчанию. Выполняются `fail2ban-client -t`, start/reload, status и проверка реальных значений. В SSH включается `LogLevel VERBOSE` для регистрации отдельных отказов ключа; `MaxAuthTries=3` — отдельное ограничение на соединение. Hash владения и строгий read-only probe различают собственные правила и чужой firewall. На RPM-системах зависимости устанавливаются заранее; внешние репозитории не подключаются.
- Нет активного файрвола: приложение не включает новый и не меняет глобальную политику. Raw nftables/iptables и несколько менеджеров блокируют автоматическую настройку.

Управляемые Match допускаются только при совпадающем root-only proof и добавляются в конец main config; чужие Match по-прежнему блокируют применение. MFA использует `publickey,keyboard-interactive:pam`, target-only PAM-блок и `/etc/ssh-hardener/totp/<user>`. Неуказанный новый enrollment сохраняет прежнюю MFA. SFTP-only задаёт `ChrootDirectory /srv/ssh-hardener/sftp/<user>`, `ForceCommand internal-sftp` и запреты forwarding/TTY/tunnel/X11; read-only добавляет `-R`. Restricted sudo принимает только точные systemctl argv над одобренными службами, не универсальный shell.

Транспорт обрамляет скрипт и sensitive payload отдельно, проверяет длины, создаёт root/private helper, открывает его descriptor и удаляет имя до исполнения; скрипт не передаётся через argv. Пакетный subprocess не получает credentials stdin. Пароли, passphrase, seeds/codes и приватный ключ не входят в текст плана. Локальная отмена не доказывает завершение remote descendants: восстановление подтверждается состоянием транзакции.

Массовый режим запускает этот pipeline отдельно для каждого проверенного хоста, с собственной историей, pin и результатом; общего атомарного commit/rollback нет. Подробности — [ADVANCED](ADVANCED.ru.md). При несовпадении preflight с аудитом применение останавливается; имя ОС не обходит проверки.
