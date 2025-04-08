# Модульные тесты

Unit-тесты проверяют отдельные функции кода, такие как вычисление хеша, проверка подписи и фильтрация файлов.

1. **Установка фреймворка для тестирования**

Установите libcheck
```bash
sudo apt install check
```

Убедитесь, что у вас установлены зависимости проекта (libfuse-dev, libgpgme11, libgost-dev и т.д.)

2. **Соберите тесты:**

```bash
gcc -Wall test_fusexmp.c -o test_fusexmp -lcheck -lgpgme -lgpg-error -lgost
```

3. **Запустите тесты:**

```bash
./test_fusexmp
```

# Интеграционные тесты
Интеграционные тесты проверяют работу всей системы: монтирование FUSE, запуск скриптов, проверку целостности и подписи.

1. **Создайте тестовую директорию**:
```bash
mkdir test_files
cd test_files
```

2. **Подготовьте тестовые файлы**:
- Создайте скрипт `good.py`:
```python
print("Hello, World!")
```
- Сгенерируйте хеш и подпись:
```bash
gostsum good.py > good.py.hash
gpg -b good.py.hash  # Создаёт good.py.hash.sig
```
- Экспортируйте открытый ключ:
```bash
gpg --export --output key.pub [ID_ключа]
```

3. **Тест 1: Успешный запуск валидного скрипта**:
- Смонтируйте FUSE:
```bash
sudo ./fusexmp ~/mnt/fuse/ -o allow_other
```
- Скопируйте файлы в примонтированную директорию:
```bash
cp good.py good.py.hash good.py.hash.sig ~/mnt/fuse/home/apps/
```
- Запустите скрипт:
```bash
python3 ~/mnt/fuse/home/apps/good.py
```
- Ожидаемый результат: скрипт выполняется, в `/var/log/syslog` нет ошибок.

4. **Тест 2: Блокировка изменённого скрипта**:
- Измените `good.py`:
```bash
echo "print('Malicious code')" >> ~/mnt/fuse/home/apps/good.py
```
- Запустите скрипт:
```bash
python3 ~/mnt/fuse/home/apps/good.py
```
- Ожидаемый результат: скрипт не выполняется, в `/var/log/syslog` есть запись об ошибке (несовпадение хешей).

5. **Тест 3: Невалидная подпись**:
- Создайте другой ключ и подпишите `good.py.hash`:
```bash
gpg --full-gen-key  # Создайте новый ключ
gpg -b good.py.hash  # Переподпишите
```
- Скопируйте файлы в примонтированную директорию и запустите:
```bash
python3 ~/mnt/fuse/home/apps/good.py
```
- Ожидаемый результат: скрипт не выполняется, в `/var/log/syslog` есть запись об ошибке (невалидная подпись).

6. **Тест 4: Фильтрация файлов**:
- Создайте файл `readme.txt`:
```bash
echo "This is a text file" > ~/mnt/fuse/home/apps/readme.txt
```
- Попробуйте открыть файл:
```bash
cat ~/mnt/fuse/home/apps/readme.txt
```
- Ожидаемый результат: файл открывается (не фильтруется).

# Автоматизация интеграционного тестирования

Запуск:
```bash
chmod +x run_tests.sh
./run_tests.sh
```
