# Kernel Module: Protect .txt Files from Renaming

## Описание
Модуль ядра Linux, предотвращающий переименование файлов с расширением `.txt`, если их первые 16 байт совпадают с данными из конфигурационного файла `/srv/rename_block.conf`. 

## Требования
- Ядро Linux ≥ 5.4 (тестировано на 5.15.0-88-generic)
- Компилятор GCC и заголовки ядра
- Права root
- Включенные параметры ядра:
---
    CONFIG_KPROBES=y
    CONFIG_KALLSYMS=y
    CONFIG_KALLSYMS_ALL=y
---
## Быстрый старт
### Установка
1. Клонируйте репозиторий
2. Создайте конфигурационный файл (не менее 16 байт):
---
sudo sh -c 'echo -n "SECRET_DATA_HERE" > /etc/rename_block.conf
---
3. Пример создания конфигурациооного файла:
---
sudo sh -c 'echo -n "SECRET_DATA_HERE" > /etc/rename_block.conf
---
4. Скомпилируйте и загрузите модуль
---
make
sudo insmod block_rename.ko
---

### Использование
1. Проверьте корректность загрузки модуля
---
dmesg | grep "block_rename"
# Должно вывести: "Module block rename succesfuel loaded!"
---
2. Тест блокировки с конфигурационным примером
---
echo "SECRET_DATA_HERE123" > test.txt
mv test.txt new_name.txt  # Должно вернуть ошибку "Permission denied"
---

## Параметры ядра
### Обязательные настройки
Проверьте текущие параметры:
---
grep -E "CONFIG_KPROBES|CONFIG_KALLSYMS_ALL" /boot/config-$(uname -r)
---
Если параметры отключены (=n), потребуется пересборка ядра.

### Временное решение (без пересборки)
---
# Разрешить доступ к символам ядра
sudo sysctl -w kernel.kptr_restrict=0
sudo sysctl -w kernel.kallsyms_show_value=1
---