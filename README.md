# WireVeil

WireVeil — автономный, автоматически обновляемый агрегатор публичных прокси-ключей для клиентов на базе Xray и sing-box. Он собирает ровно 1000 конфигураций для обычного режима чёрных списков, строго проверяет URI, удаляет семантические дубликаты, равномерно распределяет выборку между доступными протоколами и исключает только подтверждённые российские endpoints.

Поддерживаются VLESS, Trojan, Shadowsocks, VMess, Hysteria, Hysteria2 (`hy2://` и `hysteria2://`) и TUIC. В каждой сборке обязательны шесть актуальных типов: VLESS, Trojan, Shadowsocks, VMess, Hysteria2 и TUIC. Парсер и отдельный файл Hysteria v1 сохраняются для совместимости, но этот устаревший тип сейчас отсутствует в выбранных живых источниках. WireGuard, AmneziaWG, многострочные конфигурации, JSON/YAML-клиенты и целиком Base64-кодированные выходные подписки не публикуются.

## Подписки

<!-- WIREVEIL_STATS_START -->
Последнее успешное обновление: **2026-09-03T08:58:02+03:00** (UTC: 2026-09-03T05:58:02Z).

| Подписка | RAW-ссылка | Ключей | Размер |
|---|---|---:|---:|
| Все протоколы | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/subscription.txt) | 1000 | 213.9 KiB |
| VLESS | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/vless.txt) | 178 | 48.8 KiB |
| Trojan | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/trojan.txt) | 178 | 27.4 KiB |
| Shadowsocks | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/shadowsocks.txt) | 178 | 21.8 KiB |
| VMess | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/vmess.txt) | 112 | 38.7 KiB |
| Hysteria | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/hysteria.txt) | 0 | 0 B |
| Hysteria2 | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/hysteria2.txt) | 177 | 28.3 KiB |
| TUIC | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/tuic.txt) | 177 | 49.0 KiB |
<!-- WIREVEIL_STATS_END -->

`stats.json` содержит подробную статистику, размеры и SHA-256 текущей сборки. В `update-history.json` хранятся последние 20 успешных обновлений.

## Источники

| Источник | Назначение | Приоритет |
|---|---|---:|
| [igareck Blacklist Mobile Top](https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt) | Компактная подборка лучших проверенных конфигураций | 100 |
| [igareck Blacklist Mixed](https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt) | Проверенные альтернативные протоколы | 95 |
| [WLUnlocker Blacklist VPN 1](https://raw.githubusercontent.com/wlunlocker/vpn-configs/main/blacklist_vpn1.txt) | Компактная VLESS-подписка | 90 |
| [WLUnlocker Blacklist VPN 2](https://raw.githubusercontent.com/wlunlocker/vpn-configs/main/blacklist_vpn2.txt) | Компактная Shadowsocks/Hysteria2-подписка | 80 |
| [morpheusadam TUIC](https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/tuic.txt) | Ежедневно проверяемый резерв TUIC | 55 |
| [Argh94 All Config](https://raw.githubusercontent.com/Argh94/Proxy-List/main/All_Config.txt) | Широкий резерв актуальных URI-протоколов | 50 |

Полная машиночитаемая конфигурация находится в [`sources.json`](./sources.json). Источник с более высоким приоритетом побеждает при обнаружении семантически одинаковых ключей.

## Использование

Добавьте RAW-ссылку `subscription.txt` в клиент, если он поддерживает URL-подписки с обычным списком URI. Если установленная версия клиента умеет импортировать только отдельные ключи, откройте нужный RAW-файл из таблицы, скопируйте строки и добавьте их вручную. Каждый файл — обычный UTF-8 TXT: один исходный URI на строку, без Base64-обёртки.

Проект рассчитан прежде всего на обычное проводное подключение и конфигурации для обхода чёрных списков. Он намеренно не создаёт и не изменяет подписки для модемных роутеров.

## Локальная сборка

Нужен Python 3. Внешних зависимостей нет.

```bash
python -m unittest discover -s tests -v
python scripts/build.py
```

Сборщик повторяет временно неудачные запросы, требует доступности всех основных источников, однократно распознаёт Base64-обёрнутый вход и сначала проверяет полный результат во временной директории. После геофильтра он выбирает ровно 1000 семантически уникальных ключей круговым проходом по доступным протоколам; внутри каждого протокола первыми идут источники с более высоким приоритетом. Публикация отменяется, если ключей меньше 1000, отсутствует любой из шести обязательных актуальных протоколов или результат не проходит проверку.

Геофильтр определяет страну только по фактическому адресу `server`: доменное имя разрешается в IP, затем точное назначение адреса проверяется через authoritative RDAP. Это важно для небольших российских сетей, переприсвоенных внутри крупного иностранного блока и потому отсутствующих в верхнеуровневой статистике делегаций. Ответы RDAP кешируются по возвращённому диапазону в `geo-cache.json` на семь дней. SNI, Host, флаг и подпись ключа не используются как доказательство страны. Подтверждённые RU-endpoints исключаются, а `UNKNOWN` сохраняются.

## Важное предупреждение

Это публичные бесплатные серверы третьих лиц. WireVeil не владеет ими, не управляет ими и не гарантирует их доступность, конфиденциальность или безопасность. Оператор сервера потенциально может наблюдать незашифрованный трафик и метаданные. Не передавайте через непроверенные серверы чувствительные данные, используйте сквозное шифрование и считайте любой ключ недоверенным.

Используйте WireVeil только в законных целях и с соблюдением применимого законодательства и правил используемых сервисов.

Код проекта распространяется по лицензии [MIT](./LICENSE).
