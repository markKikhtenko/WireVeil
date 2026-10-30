# WireVeil

WireVeil собирает публичные proxy URI, проверяет формат, удаляет дубликаты и исключает подтверждённые российские endpoints. Репозиторий публикует готовые подписки и Windows-приложение для проверки узлов из сети пользователя.

Поддерживаются VLESS, Trojan, Shadowsocks, VMess, Hysteria, Hysteria2 и TUIC.

## Подписки

<!-- WIREVEIL_STATS_START -->
Последнее успешное обновление: **2026-10-30T11:56:17+03:00** (UTC: 2026-10-30T08:56:17Z).

| Подписка | RAW-ссылка | Ключей | Размер |
|---|---|---:|---:|
| Все протоколы | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/subscription.txt) | 2391 | 473.0 KiB |
| VLESS | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/vless.txt) | 691 | 146.5 KiB |
| Trojan | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/trojan.txt) | 684 | 111.9 KiB |
| Shadowsocks | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/shadowsocks.txt) | 230 | 20.1 KiB |
| VMess | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/vmess.txt) | 302 | 101.5 KiB |
| Hysteria | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/hysteria.txt) | 0 | 0 B |
| Hysteria2 | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/hysteria2.txt) | 227 | 28.6 KiB |
| TUIC | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/tuic.txt) | 257 | 64.3 KiB |
<!-- WIREVEIL_STATS_END -->

### Проверенные подключения

<!-- WIREVEIL_HEALTH_START -->
Последняя проверка реального подключения: **2026-10-30T11:59:19+03:00** (UTC: 2026-10-30T08:59:19Z). Проверено через `sing-box version 1.14.0`: **778 из 2391** конфигураций передали HTTPS-трафик; после endpoint-дедупликации опубликовано **778**.

| Подписка | RAW-ссылка | Ключей | Размер |
|---|---|---:|---:|
| Только активные и проверенные | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/active.txt) | 778 | 135.3 KiB |
| Рабочие и быстрые (≤ 500 мс) | [RAW](https://raw.githubusercontent.com/markKikhtenko/WireVeil/main/good.txt) | 542 | 92.6 KiB |
<!-- WIREVEIL_HEALTH_END -->

- `good.txt` — рабочие узлы с задержкой не выше 500 мс; рекомендуемый вариант.
- `active.txt` — все узлы, передавшие HTTPS-трафик.
- `subscription.txt` — полный пул после валидации, дедупликации и геофильтра.

Результат проверки зависит от сети и времени запуска. Текущая доступность не гарантирует дальнейшую работу узла.

Подробные данные: [`stats.json`](./stats.json), [`active-stats.json`](./active-stats.json), [`update-history.json`](./update-history.json).

## WireVeil Checker для Windows

[**Скачать установщик Windows x64**](https://github.com/markKikhtenko/WireVeil/releases/latest/download/WireVeilChecker-Setup-x64.exe) · [Portable ZIP](https://github.com/markKikhtenko/WireVeil/releases/latest/download/WireVeilChecker-windows-x64.zip)

Установщик не требует прав администратора. Путь по умолчанию: `%LOCALAPPDATA%\Programs\WireVeil Checker`.

Checker умеет:

- проверять share URI через встроенный sing-box;
- проверять Mihomo/OpenClash URL, YAML, TXT и CSV;
- измерять HTTPS-доступность, задержку, скорость и доступ к выбранным сайтам;
- экспортировать рабочие URI, приватный YAML и обезличенный диагностический ZIP;
- обновляться из интерфейса с проверкой SHA-256 установщика.

Быстрый старт:

1. Установите и запустите Checker.
2. Вставьте подписку или выберите файл.
3. Запустите полный тест и экспортируйте прошедшие узлы.

Настройки хранятся рядом с приложением в `WireVeilChecker.config.json`, `WireVeilChecker.mihomo-sources.json` и `WireVeilChecker.mihomo-ui.json`. Эти файлы не отправляются в репозиторий. Подробности: [`PORTABLE-CHECKER.md`](./PORTABLE-CHECKER.md).

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
