# WireVeil

WireVeil собирает публичные proxy URI, проверяет формат, удаляет дубликаты и исключает подтверждённые российские endpoints. Репозиторий публикует готовые подписки и Windows-приложение для проверки узлов из сети пользователя.

Поддерживаются VLESS, Trojan, Shadowsocks, VMess, Hysteria, Hysteria2 и TUIC.

## Подписки

<!-- WIREVEIL_STATS_START -->
Последнее успешное обновление: **2026-11-13T22:56:02+03:00** (UTC: 2026-11-13T19:56:02Z).

| Подписка | RAW-ссылка | Ключей | Размер |
|---|---|---:|---:|
| Все протоколы | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/subscription.txt) | 3365 | 695.7 KiB |
| VLESS | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/vless.txt) | 1519 | 345.1 KiB |
| Trojan | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/trojan.txt) | 522 | 81.6 KiB |
| Shadowsocks | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/shadowsocks.txt) | 463 | 54.2 KiB |
| VMess | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/vmess.txt) | 330 | 111.7 KiB |
| Hysteria | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/hysteria.txt) | 0 | 0 B |
| Hysteria2 | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/hysteria2.txt) | 279 | 38.9 KiB |
| TUIC | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/tuic.txt) | 252 | 64.2 KiB |
<!-- WIREVEIL_STATS_END -->

### Проверенные подключения

<!-- WIREVEIL_HEALTH_START -->
Последняя проверка реального подключения: **2026-11-13T23:00:10+03:00** (UTC: 2026-11-13T20:00:10Z). Проверено через `sing-box version 1.14.0`: **920 из 3365** конфигураций передали HTTPS-трафик; после endpoint-дедупликации опубликовано **920**.

| Подписка | RAW-ссылка | Ключей | Размер |
|---|---|---:|---:|
| Только активные и проверенные | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/active.txt) | 920 | 170.0 KiB |
| Рабочие и быстрые (≤ 500 мс) | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/good.txt) | 609 | 109.0 KiB |
<!-- WIREVEIL_HEALTH_END -->

- `good.txt` — рабочие узлы с задержкой не выше 500 мс; рекомендуемый вариант.
- `active.txt` — все узлы, передавшие HTTPS-трафик.
- `subscription.txt` — полный пул после валидации, дедупликации и геофильтра.

Результат проверки зависит от сети и времени запуска. Текущая доступность не гарантирует дальнейшую работу узла.

Подробные данные: [`stats.json`](./stats.json), [`active-stats.json`](./active-stats.json), [`update-history.json`](./update-history.json).

## WireVeil Checker для Windows

[**Скачать установщик Windows x64**](https://github.com/markKikhtenko/WireVeil/releases/latest/download/WireVeilChecker-Setup-x64.exe) · [Portable ZIP](https://github.com/markKikhtenko/WireVeil/releases/latest/download/WireVeilChecker-windows-x64.zip)

Установщик запрашивает UAC и по умолчанию ставит Checker в `C:\Program Files\WireVeil Checker`.

Checker умеет:

- проверять share URI через встроенный sing-box;
- проверять Mihomo/OpenClash URL, YAML, TXT и CSV;
- запускать изолированную самодиагностику ядра, API и HTTP-прокси Mihomo;
- измерять HTTPS-доступность, задержку, скорость и доступ к выбранным сайтам;
- экспортировать рабочие URI, приватный YAML и обезличенный диагностический ZIP;
- обновляться из интерфейса с проверкой SHA-256 установщика.

Быстрый старт:

1. Установите и запустите Checker.
2. Вставьте подписку или выберите файл.
3. Запустите полный тест и экспортируйте прошедшие узлы.

Установщик размещает программу в `C:\Program Files\WireVeil Checker`, а пользовательские настройки — в `%LOCALAPPDATA%\WireVeil Checker`. Portable-версия хранит настройки рядом с приложением. Эти файлы не отправляются в репозиторий. Подробности: [`PORTABLE-CHECKER.md`](./PORTABLE-CHECKER.md).

### Диагностика Mihomo

Во вкладке **Mihomo / OpenClash** нажмите **Диагностика Mihomo**. Checker запустит отдельный временный экземпляр ядра на свободных локальных портах, проверит минимальную конфигурацию, авторизацию и ответы локального API, а затем протестирует пять контрольных HTTPS-сайтов тремя способами: напрямую, через `/proxies/DIRECT/delay` и через временный HTTP-прокси Mihomo.

Диагностика не использует пользовательские подписки, не меняет системный прокси и не останавливает текущую пакетную проверку. Результаты содержат фактические HTTP-коды, задержки и причины ошибок; отчёт можно скопировать или сохранить как TXT/JSON. В отчёт не включаются токены API, приватные подписки и ключи прокси. Временный процесс и конфигурация удаляются при завершении, ошибке или закрытии окна.

## Как формируются подписки

- Источники и их приоритеты заданы в [`sources.json`](./sources.json).
- Полностью эквивалентные URI удаляются; для одинакового endpoint остаётся запись более приоритетного источника.
- Страна определяется по IP через RDAP. Подтверждённые RU endpoints исключаются, `UNKNOWN` сохраняются.
- Активность проверяется реальным HTTPS-запросом через sing-box; ICMP ping не используется.
- Публикация отменяется при ошибке проверки или недостижении защитного минимума.

## Разработка

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/build.py
python scripts/healthcheck.py --sing-box C:\path\to\sing-box.exe
```

Теги `checker-vX.Y.Z` запускают сборку portable ZIP и установщика. Код приложения находится в [`checker_app.py`](./checker_app.py), обновлятора — в [`scripts/app_updater.py`](./scripts/app_updater.py), установщика — в [`installer/WireVeilChecker.iss`](./installer/WireVeilChecker.iss).

## Безопасность и ограничения

Публичные серверы принадлежат третьим лицам. Считайте их недоверенными, используйте сквозное шифрование и не передавайте чувствительные данные через незашифрованные соединения.

WireGuard, AmneziaWG и клиентские JSON/YAML-конфигурации без share URI не входят в общую URI-подписку. Mihomo YAML поддерживается только в Checker.

Пока Authenticode-сертификат не настроен, Windows SmartScreen может предупреждать о неподписанном приложении. Инструкция: [`SIGNING.md`](./SIGNING.md).

Используйте проект в соответствии с применимым законодательством и правилами сервисов.

Лицензия: [MIT](./LICENSE).
