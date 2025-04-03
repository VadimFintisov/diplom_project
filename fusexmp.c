/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags --libs` fusexmp.c -o fusexmp
*/

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64 //FIXED

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <gost/gostapi.h>
#include <gpgme.h>
#include <regex.h>
#include <syslog.h>
#include "stdarg.h" //FIXED
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <gpg-error.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
//#include "t-support.h"

#define MAX_LINE_LENGTH 200
#define MAX_LINE_COUNT 20
#define CONFIGFILE "/etc/fuse_script/extensions.conf"

unsigned int hash_block_size = 512;
int str_array_size, init_success;
int rez_rab = 0;
int rez_gost = 0;
int hashsize = 32;
regex_t file_template[MAX_LINE_COUNT];
char str_array [MAX_LINE_COUNT][MAX_LINE_LENGTH], rez[1], etalonhash_buf[64],
fpr_from_key[40];

static int xmp_getattr(const char *path, struct stat *stbuf)
{
        int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{

	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{

	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{

	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{

	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{

	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{

	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{

	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{

	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{

	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{

	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{

	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{

	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2])
{

	int res;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

int check_import_result (gpgme_import_result_t result, int secret)
{
    if (result->considered!= 1)
    {
        syslog(LOG_ERR, "Неверное число рассматриваемых ключей %i",
               result->considered);
        return 0;
    }
    if (result->no_user_id!= 0)
    {
        syslog(LOG_ERR, "Невероное число ID пользователей %i",
               result->no_user_id);
        return 0;
    }
    if ((secret && result->imported!= 0)
            || (!secret && (result->imported!= 0 && result->imported!= 1)))
    {
        syslog(LOG_ERR, "Невероное число импортированных ключей %i",
               result->imported);
        return 0;
    }
    if (result->imported_rsa!= 0)
    {
        syslog(LOG_ERR, "Неверное число импортированных RSA ключей %i",
               result->imported_rsa);
        return 0;
    }
    if ((secret && result->unchanged!= 0)
            || (!secret && ((result->imported == 0 && result->unchanged!= 1)
                            || (result->imported == 1 && result->unchanged!= 0))))
    {
        syslog(LOG_ERR, "Неверное число неизменённых ключей %i",
               result->unchanged);
        return 0;
    }
    if (result->new_user_ids!= 0)
    {
        syslog(LOG_ERR, "Неверное число новых пользователей %i",
               result->new_user_ids);
        return 0;
    }
    if (result->new_sub_keys!= 0)
    {
        syslog(LOG_ERR, "Неверное число новых дочерних ключей %i",
               result->new_sub_keys);
        return 0;
    }
    if ((secret
         && ((result->secret_imported == 0 && result->new_signatures!= 0)
             || (result->secret_imported == 1 && result->new_signatures > 1)))
            || (!secret && result->new_signatures!= 0))
    {
        syslog(LOG_ERR, "Неверное число новых подписей %i",
               result->new_signatures);
        if (result->new_signatures == 2)
            syslog(LOG_ERR, "### игнорируются из-за проблем c gpg 1.3.4");
        else
            return 0;
    }
    if (result->new_revocations!= 0)
    {
        syslog(LOG_ERR, "Неверное число новых сертификатов отзыва %i",
               result->new_revocations);
        return 0;
    }
    if (!result->imports || result->imports->next)
    {
        syslog(LOG_ERR, "Неверное число отчетов о состоянии");
        return 0;
    }
    if (result->imports->result!= 0)
    {
        syslog(LOG_ERR, "Неверное значение результата %s",
               gpgme_strerror (result->imports->result));
        return 0;
    }
    if ((result->imported == 0 && result->imports->status!= 0)
            || (result->imported == 1
                && result->imports->status!= GPGME_IMPORT_NEW))
    {
        syslog(LOG_ERR, "Неверный статус %i", result->imports->status);
        return 0;
    }
    return 1;
}

static int
check_verify_result (gpgme_verify_result_t result, unsigned int summary,
                     gpgme_error_t status)
{
    gpgme_signature_t sig;

    sig = result->signatures;
    if (!sig)
    {
        syslog(LOG_ERR, "Нет подписей");
        return 0;
    }
    while (sig)
    {
        if ((sig->summary & summary)!= summary)
        {
            syslog(LOG_ERR, "Неверные сводные данные подписи: 0x%x",
                   sig->summary);
            return 0;
        }
        if (gpgme_err_code (sig->status)!= status)
        {
            syslog(LOG_ERR, "Неверное значение подписи: %s",
                   gpgme_strerror (sig->status));
            return 0;
        }
        if (sig->notations)
        {
            syslog(LOG_ERR, "Неверное примечание");
            return 0;
        }
        if (sig->wrong_key_usage)
                {
                    syslog(LOG_ERR, "Неверное использование ключа");
                    return 0;
                }
                sig = sig->next;
            }
            return 1;
        }
//int verify_sig(const char*filepath)
//{
//    gpgme_ctx_t ctx;
//    gpgme_error_t err;
//    gpgme_data_t hash, sig;
//    gpgme_verify_result_t verify_result;
//    const char *sigpath = make_filename (filepath,0),
//            *hashpath = make_filename (filepath,1);
//    int ret, tmp, cmp=0;

//    init_gpgme (GPGME_PROTOCOL_OpenPGP);

//    err = gpgme_new (&ctx);
//    if (!fail_if_err (err))
//        return 0;

//    err = gpgme_data_new_from_file (&sig, sigpath, 1);
//    if (!fail_if_err (err))
//        return 0;

//    err = gpgme_data_new_from_file (&hash, hashpath, 1);
//    if (!fail_if_err (err))
//        return 0;

//    gpgme_data_seek (sig, 0, SEEK_SET);
//    err = gpgme_op_verify (ctx, sig, hash, NULL);
//    if (!fail_if_err (err))
//        return 0;

//    verify_result = gpgme_op_verify_result (ctx);

//    tmp = check_verify_result (verify_result, 0, GPG_ERR_NO_ERROR);

//    if (!tmp)
//        return 0;

//    char *fpr_from_sig = malloc(strlen (verify_result->signatures->fpr));
//    memcpy(fpr_from_sig, verify_result->signatures->fpr,
//           strlen (verify_result->signatures->fpr));

//    cmp = !memcmp(fpr_from_sig, fpr_from_key,
//                  strlen (verify_result->signatures->fpr));
//    gpgme_release (ctx);
//    if (!cmp)
//    {
//        syslog(LOG_ERR, "%s", "Неверный отпечаток ключа");
//        return 0;
//    }

//    ret = gpgme_data_seek (hash, 0, SEEK_SET);
//    if (ret)
//        if (!fail_if_err (gpgme_err_code_from_errno (errno)))
//            return 0;
//    ret = gpgme_data_read (hash, etalonhash_buf, hashsize*2+1);
//    gpgme_data_release (hash);
//    if (ret < 0)
//        if (!fail_if_err (gpgme_err_code_from_errno (errno)))
//            return 0;

//    return 1;
//}

const char *make_filename(const char *filepath, int type)
{
    char *filename = NULL;
    size_t filepath_len = strlen(filepath);
    size_t ext_len = 0;

    if (type == 0) { // signature file
        ext_len = strlen(".sig");
        filename = malloc(filepath_len + ext_len + 1);
        sprintf(filename, "%s%s", filepath, ".sig");
    } else if (type == 1) { // hash file
        ext_len = strlen(".hash");
        filename = malloc(filepath_len + ext_len + 1);
        sprintf(filename, "%s%s", filepath, ".hash");
    } else {
        syslog(LOG_ERR, "Invalid type for make_filename");
        return NULL;
    }

    return filename;
}

int verify_sig(const char* filepath)
{
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t hash, sig;
    gpgme_verify_result_t verify_result;
    const char *sigpath = make_filename (filepath,0),
            *hashpath = make_filename (filepath,1);
    int ret, tmp, cmp=0;
    gpgme_check_version(NULL);
//    init_gpgme (GPGME_PROTOCOL_OpenPGP, NULL);

//    err = gpgme_new (&ctx);
//    if (!fail_if_err (err))
//        return 0;

//    err = gpgme_data_new_from_file (&sig, sigpath, 1);
//    if (!fail_if_err (err))
//        return 0;

//    err = gpgme_data_new_from_file (&hash, hashpath, 1);
//    if (!fail_if_err (err))
//        return 0;
    err = gpgme_new (&ctx);
    if (err!= GPG_ERR_NO_ERROR) {
        fprintf(stderr, "Ошибка инициализации GPGME: %s\n", gpgme_strerror(err));
        return 1;
    }

    err = gpgme_data_new_from_file (&sig, sigpath, 1);
    if (err!= GPG_ERR_NO_ERROR) {
        fprintf(stderr, "Ошибка создания данных из файла %s: %s\n", sigpath, gpgme_strerror(err));
        return 1;
    }

    err = gpgme_data_new_from_file (&hash, hashpath, 1);
    if (err!= GPG_ERR_NO_ERROR) {
        fprintf(stderr, "Ошибка создания данных из файла %s: %s\n", hashpath, gpgme_strerror(err));
        return 1;
    }

//    gpgme_data_seek (sig, 0, SEEK_SET);
//    err = gpgme_op_verify (ctx, sig, hash, NULL);
//    if (!fail_if_err (err))
//        return 0;
    gpgme_data_seek (sig, 0, SEEK_SET);
    err = gpgme_op_verify (ctx, sig, hash, NULL);
    if (err!= GPG_ERR_NO_ERROR) {
        fprintf(stderr, "Ошибка верификации: %s\n", gpgme_strerror(err));
        return 1;
    }

    verify_result = gpgme_op_verify_result (ctx);

    tmp = check_verify_result (verify_result, 0, GPG_ERR_NO_ERROR);

    if (!tmp)
        return 0;

    gpgme_signature_t sigs = verify_result->signatures;
    while (sigs) {
        char *fpr_from_sig = malloc(strlen (sigs->fpr) + 1);
        strcpy(fpr_from_sig, sigs->fpr);

        cmp =!memcmp(fpr_from_sig, fpr_from_key,
                      strlen (sigs->fpr));
        free(fpr_from_sig);
        if (cmp)
            break;
        sigs = sigs->next;
    }

    if (!cmp)
    {
        syslog(LOG_ERR, "%s", "Неверный отпечаток ключа");
        return 0;
    }

//    ret = gpgme_data_seek (hash, 0, SEEK_SET);
//    if (ret)
//        if (!fail_if_err (gpgme_err_code_from_errno (errno)))
//            return 0;
//    ret = gpgme_data_read (hash, etalonhash_buf, hashsize*2+1);
//    gpgme_data_release (hash);
//    if (ret < 0)
//        if (!fail_if_err (gpgme_err_code_from_errno (errno)))
//            return 0;
    ret = gpgme_data_seek (hash, 0, SEEK_SET);
    if (ret) {
        err = gpgme_err_code_from_errno (errno);
        fprintf(stderr, "Ошибка позиционирования в файле: %s\n", gpgme_strerror(err));
        return 1;
    }

    ret = gpgme_data_read (hash, etalonhash_buf, hashsize*2+1);
    gpgme_data_release (hash);
    if (ret < 0) {
        err = gpgme_err_code_from_errno (errno);
        fprintf(stderr, "Ошибка чтения из файла: %s\n", gpgme_strerror(err));
        return 1;
    }

    gpgme_release (ctx);
    return 1;
}

//int compare_hash(const char*heshstring, unsigned char*heshbin, int heshsize)
//{
//    int rez = 0, i;
//    char *Buf = malloc (heshsize*2+1);

//    for (i = 0; i < heshsize; ++i)
//    {
//        sprintf(Buf+i*2,"%02hhx", heshbin[i]);
//    }

//    Buf[heshsize*2] = 0;
//    rez = !memcmp(heshstring, Buf, heshsize*2);
//    free(Buf);

//    return rez;
//}

int compare_hash(const char*heshstring, unsigned char*heshbin, int heshsize)
{
    int rez = 0;
    char *Buf = malloc (heshsize*2+1);

    for (int i = 0; i < heshsize; ++i)
    {
        snprintf(Buf+i*2, 3, "%02hhx", heshbin[i]);
    }

    Buf[heshsize*2] = 0;
    rez = strcmp(heshstring, Buf) == 0;
    free(Buf);

    return rez;
}

//int verify_hash(const char*filepath)
//{
//    int py_file, rezult, tmp;
//    unsigned char real_hash[hashsize];

//    /* открытие скрипта на чтение и подсчет его хеша */
//    py_file = open(filepath,O_RDONLY);
//    if (py_file == -1)
//    {
//        syslog(LOG_ERR, "%s", "Запрашиваемый файл не существует");
//        return 0;
//    }
//    if (rez_gost==0)
//    {
//	gost12_hash_file(py_file, hash_block_size, real_hash);
//    }
//    else gost12_hash_file_512(py_file, hash_block_size, real_hash);
//    close(py_file);

//    /* проверка подписи, сравнение рассчитанного и
//       эталонного хешей */
//    tmp = verify_sig(filepath);
//    if (!tmp)
//        return 2;

//    if (etalonhash_buf != 0)
//    {
//        rezult = compare_hash(etalonhash_buf, real_hash, hashsize);
//    }
//    else rezult = 0;

//    return rezult;
//}

int verify_hash(const char* filepath)
{
    int fd, rezult, tmp;
    unsigned char real_hash[hashsize];

    /* открытие файла на чтение и подсчет его хеша */
    fd = open(filepath, O_RDONLY);
    if (fd == -1)
    {
        syslog(LOG_ERR, "%s", "Запрашиваемый файл не существует");
        return 0;
    }
    if (rez_gost == 0)
    {
        gost12_hash_file(fd, hash_block_size, real_hash);
    }
    else
    {
        gost12_hash_file_512(fd, hash_block_size, real_hash);
    }
    close(fd);

    /* проверка подписи, сравнение рассчитанного и
       эталонного хешей */
    tmp = verify_sig(filepath);
    if (!tmp)
        return 2;

    if (etalonhash_buf != NULL)
    {
        rezult = compare_hash(etalonhash_buf, real_hash, hashsize);
    }
    else
    {
        rezult = 0;
    }

    return rezult;
}

//int init_config()
//{
//    FILE *fp;
//    int i=0, a=0, tmp;
//    const char *keypath = "/home/.keys/key.pub";
//    gpgme_ctx_t ctx;
//    gpgme_error_t err;
//    gpgme_data_t key;
//    gpgme_import_result_t import_result;

//    /* чтение конфигурационного файла, запись его в массив строк
//       и инициализация массива в виде регулярных выражений*/
//    fp = fopen(CONFIGFILE,"r");
//    if(!fp)
//    {
//        init_success=0;
//        return 0;
//    }

//    while (fgets(str_array[i], MAX_LINE_LENGTH, fp))
//    {
//        int len=strlen(str_array[i]);
//        str_array[i][len-1]=0;
//        i++;
//    }
//    fclose(fp);
//    str_array_size=i;

//    for(i=0; i<str_array_size; i++)
//    {
//        a=regcomp(file_template + i, str_array[i], REG_EXTENDED|REG_NOSUB);
//        if(a)
//        {
//            init_success=0;
//            return 0;
//        }
//    }
//    init_success=1;
//    syslog(LOG_INFO, "%s", "Конфигурационный файл загружен");

//    init_gpgme (GPGME_PROTOCOL_OpenPGP);

//    err = gpgme_new (&ctx);
//    if (!fail_if_err (err))
//        return 0;

//    err = gpgme_data_new_from_file (&key, keypath, 1);
//    if (!fail_if_err (err))
//        return 0;

//    err = gpgme_op_import (ctx, key);
//    gpgme_data_release (key);
//    if (!fail_if_err (err))
//        return 0;

//    import_result = gpgme_op_import_result (ctx);
//    tmp = check_import_result (import_result, 0);
//    if (!tmp)
//        return 0;

//    memcpy(fpr_from_key, import_result->imports->fpr,
//           strlen (import_result->imports->fpr));
//    gpgme_release (ctx);

//    syslog(LOG_INFO, "%s", "Ключ проверки загружен");

//    return 1;
//}

int init_config()
{
    FILE *fp;
    int i = 0, a = 0, tmp;
    const char *keypath = "/home/.keys/key.pub";
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t key;
    gpgme_import_result_t import_result;

    /* чтение конфигурационного файла, запись его в массив строк
       и инициализация массива в виде регулярных выражений*/
    fp = fopen(CONFIGFILE, "r");
    if (!fp)
    {
        init_success = 0;
        syslog(LOG_ERR, "%s", "Не удалось открыть конфигурационный файл");
        return 0;
    }

    while (fgets(str_array[i], MAX_LINE_LENGTH, fp))
    {
        int len = strlen(str_array[i]);
        str_array[i][len - 1] = 0;
        i++;
    }
    fclose(fp);
    str_array_size = i;

    for (i = 0; i < str_array_size; i++)
    {
        a = regcomp(&file_template[i], str_array[i], REG_EXTENDED | REG_NOSUB);
        if (a)
        {
            init_success = 0;
            syslog(LOG_ERR, "%s", "Ошибка компиляции регулярного выражения");
            return 0;
        }
    }
    init_success = 1;
    syslog(LOG_INFO, "%s", "Конфигурационный файл загружен");

    gpgme_check_version(NULL);

    err = gpgme_new(&ctx);
    if (err!= GPG_ERR_NO_ERROR)
    {
        syslog(LOG_ERR, "Ошибка инициализации GPGME: %s", gpgme_strerror(err));
        return 0;
    }

    err = gpgme_data_new_from_file(&key, keypath, 1);
    if (err!= GPG_ERR_NO_ERROR)
    {
        syslog(LOG_ERR, "Ошибка чтения ключа: %s", gpgme_strerror(err));
        gpgme_release(ctx);
        return 0;
    }

    err = gpgme_op_import(ctx, key);
    gpgme_data_release(key);
    if (err!= GPG_ERR_NO_ERROR)
    {
        syslog(LOG_ERR, "Ошибка импорта ключа: %s", gpgme_strerror(err));
        gpgme_release(ctx);
        return 0;
    }

    import_result = gpgme_op_import_result(ctx);
    tmp = check_import_result(import_result, 0);
    if (!tmp)
    {
        syslog(LOG_ERR, "Ошибка проверки импорта ключа");
        gpgme_release(ctx);
        return 0;
    }

    memcpy(fpr_from_key, import_result->imports->fpr, strlen(import_result->imports->fpr));
    gpgme_release(ctx);

    syslog(LOG_INFO, "%s", "Ключ проверки загружен");

    return 1;
}

int path_match(const char*filepath){

    regmatch_t pmatch[1];
    int i;
    for(i=0; i<str_array_size; i++)
    {
        rez[0]=regexec(file_template + i, filepath, 1, pmatch, 0);
        if(!rez[0])
        {
            break;
        }
    }
    str_array_size = 0;
    regfree(file_template);

    if (rez[0])
    {
        syslog(LOG_ERR, "%s", "Данный файл не подлежит фильтрации");
        return 0;
    }
    return 1;
}

int check_file(const char*filepath)
{
    int rezult;
    int pathmatch = path_match(filepath);
    if (pathmatch==0)
    {
        return 1;
    }
    rezult = verify_hash(filepath);
    if (!rezult)
    {
       syslog(LOG_ERR, "%s %s", "Ошибка на этапе сравнения значений хэшей при доступе к файлу: ",
               filepath);
        return 0;
    }
    else
        if (rezult == 2)
        {
            syslog(LOG_ERR, "%s %s",
                   "Ошибка проверки подписи файла с эталонным хэш-кодом файла: ",
                   filepath);
            return 0;
        }
    return 1;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
        int res;

        res = open(path, fi->flags);
        if (res == -1)
                return -errno;

        close(res);
        return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	if ((rez_rab == 1) || ((rez_rab == 0) && (offset == 0)))
	{
       		if (fi->flags & 32768)
       		{
       			int n = check_file(path);
       			if (n==0)
               			return -errno;
       		}
	}

        int fd;
	int res;

	(void) fi;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{

	int fd;
	int res;

	(void) fi;
	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{

	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
        /* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{

	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	openlog("FUSE_SCRIPT", 0, LOG_LOCAL0);

	if (argc == 3)
	{
		int a = atoi(argv[2]);
		rez_rab = a;
		argc = 2;
		argv[2]=0;
	}
	if (argc > 3)
	{
		int a = atoi(argv[2]);
                rez_rab = a;
                argv[2]=0;

		int b = atoi(argv[3]);
		rez_gost = b;
		argc = 2;
		argv[3]=0;
	}

	if(rez_rab == 0)
	{
		syslog(LOG_INFO, "Режим работы нормальный");
	}
	else syslog(LOG_INFO, "Режим работы усиленный");

	if(rez_gost == 1)
	{
		hashsize = 64;
		syslog(LOG_INFO, "Размер хэша - 512 бит");
	}
	else syslog(LOG_INFO, "Размер хэша - 256 бит");

	if(init_config() == 0)
    	{
        	syslog(LOG_ERR, "%s", "Ошибка инициализации");
        	return 0;
    	}

	umask(0);
	int res = fuse_main(argc, argv, &xmp_oper, NULL);
        closelog();
	return res;
}
