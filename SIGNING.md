# Подпись Windows-сборки

Tagged-релизы `checker-v*` требуют доверенный Authenticode Code Signing
сертификат в формате PFX. Самоподписанные сертификаты намеренно не используются:
они не устраняют предупреждение SmartScreen на других компьютерах.

В настройках GitHub-репозитория (`Settings` → `Secrets and variables` →
`Actions`) нужны два repository secret:

- `WINDOWS_CERTIFICATE_BASE64` — Base64 всего бинарного PFX-файла;
- `WINDOWS_CERTIFICATE_PASSWORD` — пароль PFX.

Получить первое значение локально в PowerShell можно без вывода закрытого ключа
в консоль:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\codesign.pfx")) |
  Set-Clipboard
```

Workflow подписывает `WireVeilChecker.exe`, вложенный `sing-box.exe` и
`libcronet.dll` алгоритмом SHA-256, добавляет доверенную временную метку DigiCert
и проверяет каждую подпись до упаковки ZIP. Если secrets отсутствуют, обычная
веточная сборка остаётся доступна как тестовый artifact, но tagged-релиз
завершается ошибкой и не публикует неподписанный ZIP.
