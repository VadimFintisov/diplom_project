## Описание проекта 
Данная методика состоит из двух частей. 

Первая часть описывает действия, выполняемые разработчиком программы, написанной на языке сценариев, по вычислению контрольной суммы внедряемого скрипта, подписанию её валидным ключом разработчика и экспортированию открытого ключа для проверки подписи и расшифрования файла. 

Вторая часть описывает действия пользователя скрипта и включает в себя импортирование открытого ключа, предоставленного разработчиком, проверка подписи файла с эталонным значением контрольной суммы, расшифрование этого файла, вычисление контрольной суммы полученного скрипта и сравнение её с эталонным значением.

## Устанавливаемые пакеты

Для нормального функционирования всех утилит необходимо убедиться в том, что в операционной системе установлены следующие пакеты:

1)	libfuse-dev – содержит средства разработки файловой системы в пользовательском пространстве;
2)	pkg-config – система для управления флагами компиляции и ссы-лок библиотек, которая работает с командами «automake» и «autoconf»;
3)	gostsum – содержит утилиту для расчета контрольной суммы по алгоритму ГОСТ Р 34.11-2012 файлов «gostsum»;
4)	gnupg – содержит утилиту, необходимую для создания ключей, подписания файлов и проверки подписи «gpg»;
5)	libgost-dev – содержит заголовочные файлы и статические биб-лиотеки, необходимые для компиляции приложений, использующих «libgost»;
6)	libgpgme11 – оберточная библиотека, которая обеспечивает при-кладной интерфейс программирования для языка «C» для доступа к некото-рым функциям «GnuPG»;
7)	libgpgme11-dev – содержит заголовочные и иные файлы, необхо-димые для компиляции программ, использующих библиотеку «libgpgme11».

В случае, если какие-либо из вышеперечисленных пакетов	 отсутствуют в системе, либо установлены с ошибками, необходимо правильно установить их с помощью того же менеджера пакетов, используя при необходимости диск со средствами разработки к операционной системе Astra Linux Special Edition.

# Сборка модуля

Перейти в папку проекта
cd ~/projects/fusexmp

Собрать 
 
gcc -Wall new_fusexmp.c pkg-config fuse --cflags --libs -o fusexmp -lgpgme -lgpg-error -lgost 

# Активация fusexmp
Используя менеджер файлов, переходим в папку
projects/fusexmp

в которой находится исполняемый файл виртуальной файловой системы. 
Открываем терминал Сервис’->’Запустить терминал и монтируем виртуальную файловую систему в папку ~/mnt/fuse/

sudo ./fusexmp ~/mnt/fuse/ -o allow_other

Переходим в папку ~/mnt/  
cd ~/mnt

Выполняем команду

sudo su

для получения root прав и переходим в папку, где находится измененный скриптовый файл test.py

cd fuse/home/dytheadoct/apps

Просматриваем содержание этой папки:
ls 

Как видно, в этой же папке находятся файлы с хеш-суммой и цифровой подписью от оригинального скрипта – они будут использоваться для проверки подлинности файла test.py.
Запускаем "вредоносный" скрипт python3 test.py и получаем ошибку.
Чтобы увидеть причину, переходим в соответствующую папку

cd /var/log

и выводим содержимое файла syslog:

cat /var/log/syslog | grep  FUSE_SCRIPT

Видно, что fusexmp не позволил запустить скрипт из-за разницы в hash-суммах файлов.
Таким образом, внутри виртуальной файловой системы, созданной с помощью fusexmp, нельзя запустить изменённые и скриптовые файлы.

# Запуск недоверенных скриптов

Запускаем Мой компьютер, переходим в папку
Домашняя/apps.

В этой папке находится тестовый скрипт на питоне (он имитирует работу, например, какого-либо системного скрипта), файлы с его hash-суммой и электронной подписью.
Открываем терминал
Сервис->Запустить терминал 

Запускаем тестовый скрипт:
python3 test.py

он выводит Hello, IT-Планета!
Закрываем терминал

# Подписывание скриптов

1) В первую очередь необходимо открыть терминал. В терминале ввести команду для генерации ключа подписи, который будет использован для подписания файла с эталонным значением контрольной суммы:

sudo gpg --full-gen-key
 
2)	В списке выбора типа ключа необходимо выбрать вариант (15) GOST R34.10-2012 (sign only), для чего ввести «15» в терминале.
 
3)	В меню выбора срока действия ключа поставить необходимое значение, либо оставить по умолчанию (0), что будет означать неограниченный срок действия ключа. После этого будет выведена дата окончания срока действия ключа, либо написано, что срок действия ключа не ограничен. Если данные верны, вводите «Y», в противном случае вводите «N» и меняете значение срока действия ключа.
 
4)	В следующем пункте создания ключа необходимо ввести ID пользователя. Утилита создаст его из Вашего имени, комментария и адреса электронной почты, которые вы введете. Например: «Ivanov (Ivan Ivanovich) <ivanov@mail.ru>». Соответственно сначала будет предложено ввести Ваше настоящее имя, затем адрес электронной почти и в конце комментарий. После этого на экран будет выведена строка наподобие той, которая была в примере, только с введенными Вами данными. Проверяете правильность ввода. Если какой-то из пунктов введен неверно, его можно изменить, введя соответствующие буквы латинского алфавита: «N» – имя, «C» – комментарий, «E» – адрес электронной почты. Если же все введено верно, то подтверждаете свой выбор, введя «О». Если вы ходите выйти из программы создания ключа, введите «Q».
 
5)	Следующий пункт – создание пароля для защиты закрытого ключа. Именно этот пароль будет использоваться для расшифрования данных закрытого ключа, которые впоследствии будут записаны в файл. После ввода пароля Вам будет предложено подтвердить пароль, пароль необходимо ввести повторно.
6)	Следующим шагом программа начнет генерацию случайных чисел для получения достаточного количества энтропии для дальнейшего создания Вашего ключа. Этот процесс довольно длительный. Чтобы ускорить его, программа предлагает Вам выполнять некоторые действия: печать на клавиатуре, движение мыши, обращение к дискам.
 
7)	После завершения процесса генерации случайных чисел, программа выдаст итоговую информацию по созданию ключа. Если данный ключ первый, который был создан в системе, то программа создаст таблицу доверия, и внесет в нее этот ключ как абсолютно доверенный. Далее программа напишет, что открытый и закрытый ключи созданы и подписаны. Теперь их можно будет найти в директории: 

/root/.gnupg/

где открытый ключ будет содержаться в файле «pubring.gpg», а закрытый – в файле «secring.gpg». После этого программа выведет информацию о том, что в таблице доверия один подписанный ключ и выведет его идентификатор, дату создания, отпечаток и ID пользователя, который создал этот ключ.
 
8)	Следующим шагом будет расчет контрольной суммы используемого скрипта с помощью утилиты «gostsum». Чтобы рассчитать контрольную сумму данной утилитой и сохранить значение в файл, необходимо ввести команду:

gostsum *название файла* > *название выходного файла*

gostsum test.py > test.py.hash

9)	После создания файла с рассчитанным хешем скрипта его необходимо подписать созданным ключом. Сделать это можно с помощью команды:

gpg --sign *имя файла с хешем*

В случае, если в системе несколько ключей для подписания и тот ключ, которым Вы собираетесь подписать скрипт не является ключом по умолчанию для подписывания, то необходимо задать ID пользователя, ключом которого Вы хотите подписать скрипт:

gpg -u *ID пользователя* --sign *имя файла с хешем*
 
Утилита потребует пароль для доступа к закрытому ключу пользователя, создавшего данный ключ. Необходимо ввести пароль, который был задан на этапе создания ключа. Если пароль введен верно, то файл будет подписан, в противном случае утилита сообщит, что введен неверный пароль и предложит попробовать ввести пароль еще раз. 
После этого появится подписанный файл в формате *имя файла с хешем*.gpg, который будет содержать данные самого файла с хешем в зашифрованном виде.
Разработчик должен предоставить пользователю вместе с созданным приложением, написанным на языке сценариев, свой открытый ключ для проверки валидности подписи. Чтобы экспортировать ключ, необходимо воспользоваться командой:

gpg --export --output *выходной файл* *ID ключа*
 
На этом первая часть методики заканчивается. 
