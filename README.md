# WireVeil

WireVeil — автономный, автоматически обновляемый агрегатор публичных прокси-ключей, совместимых с Zapret KVN. Он собирает только URI-конфигурации, строго проверяет их, удаляет семантические дубликаты и исключает только подтверждённые российские endpoints.

Поддерживаются VLESS, Trojan, Shadowsocks, VMess, Hysteria, Hysteria2 (`hy2://` и `hysteria2://`) и TUIC. WireGuard, AmneziaWG, многострочные конфигурации, JSON/YAML-клиенты и целиком Base64-кодированные выходные подписки не публикуются.

## Подписки

<!-- WIREVEIL_STATS_START -->
Последнее успешное обновление: **2026-08-25T00:50:15+03:00** (UTC: 2026-08-24T21:50:15Z).

| Подписка | RAW-ссылка | Ключей | Размер |
|---|---|---:|---:|
| Все протоколы | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/subscription.txt) | 4629 | 1.07 MiB |
| VLESS | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/vless.txt) | 4352 | 1.01 MiB |
| Trojan | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/trojan.txt) | 123 | 27.2 KiB |
| Shadowsocks | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/shadowsocks.txt) | 33 | 3.8 KiB |
| VMess | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/vmess.txt) | 6 | 2.3 KiB |
| Hysteria | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/hysteria.txt) | 0 | 0 B |
| Hysteria2 | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/hysteria2.txt) | 115 | 21.6 KiB |
| TUIC | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/tuic.txt) | 0 | 0 B |
<!-- WIREVEIL_STATS_END -->

`stats.json` содержит подробную статистику, размеры и SHA-256 текущей сборки. В `update-history.json` хранятся последние 20 успешных обновлений.

## Источники

| Источник | Назначение | Приоритет |
|---|---|---:|
| [igareck VLESS Black List](https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt) | VLESS для блок-листов | 100 |
| [igareck Black List Mixed](https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt) | Смешанная подборка для блок-листов | 90 |
| [WLUnlocker Blacklist](https://raw.githubusercontent.com/wlunlocker/vpn-configs/main/blacklist_all.txt) | Дополнительная смешанная подборка | 80 |
| [EaveVPN Black List](https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/main/BLACK_SS%2BAll.txt) | Резервная смешанная подборка | 70 |
| [V.O.I.D VLESS](https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/refs/heads/main/url_work.txt) | Дополнительный источник, преимущественно для белых списков | 10 |

Полная машиночитаемая конфигурация находится в [`sources.json`](./sources.json). Источник с более высоким приоритетом побеждает при обнаружении семантически одинаковых ключей.

## Использование с Zapret KVN

Поддержка URL-подписок в Zapret KVN [пока обсуждается](https://github.com/youtubediscord/zapret-kvn/issues/66). Если установленная версия клиента ещё не умеет загружать URL, откройте нужный RAW-файл из таблицы, скопируйте отдельные строки и добавьте их в клиент вручную. Каждый файл — обычный UTF-8 TXT: один исходный URI на строку, без Base64-обёртки.

Проект рассчитан прежде всего на обычное проводное подключение и конфигурации для обхода чёрных списков. Он намеренно не создаёт и не изменяет подписки для модемных роутеров.

## Локальная сборка

Нужен Python 3. Внешних зависимостей нет.

```bash
python -m unittest discover -s tests -v
python scripts/build.py
```

Сборщик повторяет временно неудачные запросы, пропускает недоступные источники, однократно распознаёт Base64-обёрнутый вход и сначала проверяет полный результат во временной директории. Рабочие файлы не меняются, если общая подписка содержит меньше 100 уникальных ключей или не проходит проверку.

Геофильтр определяет страну только по фактическому адресу `server`: доменное имя разрешается в IP, затем точное назначение адреса проверяется через authoritative RDAP. Это важно для небольших российских сетей, переприсвоенных внутри крупного иностранного блока и потому отсутствующих в верхнеуровневой статистике делегаций. Ответы RDAP кешируются по возвращённому диапазону в `geo-cache.json` на семь дней. SNI, Host, флаг и подпись ключа не используются как доказательство страны. Подтверждённые RU-endpoints исключаются, а `UNKNOWN` сохраняются.

## Важное предупреждение

Это публичные бесплатные серверы третьих лиц. WireVeil не владеет ими, не управляет ими и не гарантирует их доступность, конфиденциальность или безопасность. Оператор сервера потенциально может наблюдать незашифрованный трафик и метаданные. Не передавайте через непроверенные серверы чувствительные данные, используйте сквозное шифрование и считайте любой ключ недоверенным.

Используйте WireVeil только в законных целях и с соблюдением применимого законодательства и правил используемых сервисов.

Код проекта распространяется по лицензии [MIT](./LICENSE).
