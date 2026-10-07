# Подпись Windows-сборки

Workflow умеет подписывать tagged-релизы `checker-v*` доверенным Authenticode
Code Signing сертификатом в формате PFX. Пока сертификат не настроен, релиз всё
равно публикуется, но EXE и вложенные бинарные файлы остаются неподписанными и
Windows Defender/SmartScreen может показать предупреждение. Самоподписанные
сертификаты намеренно не используются: они не устраняют предупреждение на других
компьютерах.

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

Если secrets присутствуют, workflow подписывает `WireVeilChecker.exe`, вложенный
`sing-box.exe` и `libcronet.dll` алгоритмом SHA-256, добавляет доверенную
временную метку DigiCert и проверяет каждую подпись до упаковки ZIP. Если secrets
отсутствуют, сборка и tagged-релиз продолжаются с явным предупреждением в логе.
