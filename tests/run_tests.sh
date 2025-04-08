#!/bin/bash

# Подготовка
mkdir -p test_files
cd test_files

# Создаём тестовый скрипт
echo "print('Hello, World!')" > good.py
gostsum good.py > good.py.hash
gpg -b good.py.hash  # Предполагается, что ключ уже есть

# Монтируем FUSE
mkdir -p ~/mnt/fuse
sudo ./fusexmp ~/mnt/fuse/ -o allow_other

# Копируем файлы
mkdir -p ~/mnt/fuse/home/apps
cp good.py good.py.hash good.py.hash.sig ~/mnt/fuse/home/apps/

# Тест 1: Успешный запуск
echo "Тест 1: Успешный запуск валидного скрипта"
python3 ~/mnt/fuse/home/apps/good.py
if [ $? -eq 0 ]; then
    echo "Тест 1 пройден: Скрипт выполнился"
else
    echo "Тест 1 провален: Скрипт не выполнился"
fi

# Тест 2: Изменённый скрипт
echo "Тест 2: Блокировка изменённого скрипта"
echo "print('Malicious code')" >> ~/mnt/fuse/home/apps/good.py
python3 ~/mnt/fuse/home/apps/good.py
if [ $? -ne 0 ]; then
    echo "Тест 2 пройден: Скрипт заблокирован"
else
    echo "Тест 2 провален: Скрипт выполнился"
fi

# Очистка
sudo umount ~/mnt/fuse
