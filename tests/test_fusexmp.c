#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../fusexmp.c"  // Подключаем основной код (нужны функции)
#include <stdio.h>

// Тест на вычисление ГОСТ-хеша
START_TEST(test_gost_hash_file)
{
    unsigned char hash_output[65] = {};  // Размер для ГОСТ 256 бит (64 символа + '\0')
    unsigned char  hash[32] = {};
    const char *test_file = "good.py";
    const unsigned char *expected_hash = "da167de86bb9f96c0c3e4178e6511bd34aca6ba935efca73b42ccfb419161160";  // Ожидаемый хеш

    // Создаём тестовый файл
    FILE *f = fopen(test_file, "w");
    fprintf(f, "print('Hello, World!')\n");
    fclose(f);
    FILE* f2 = fopen(test_file, "r");
    gost12_hash_file(fileno(f2), 1024, hash);
    for (int i = 0; i < 32; ++i ) {
        sprintf(hash_output+i*2, "%02hhx", hash[i]);
    }
    hash_output[64] = 0;
    unsigned char* p1 = (unsigned int* )hash_output;
    unsigned char* p2 = (unsigned int* )expected_hash;
    printf(hash_output);
    printf("\n");
    fflush(stdout);

    for (int i = 0; i < 64; ++i) {
        ck_assert_uint_eq(p1[i], p2[i]);
    }
}
END_TEST

//// Тест на проверку подписи
START_TEST(test_verify_sig)
{

    const char *file = "test_files/good.py";
    const char *hash_file = "test_files/good.py.hash";
    const char *sig_file = "test_files/good.py.hash.sig";

    // Создаём тестовые файлы
    FILE *f_hash = fopen(hash_file, "w");
    fprintf(f_hash,  "da167de86bb9f96c0c3e4178e6511bd34aca6ba935efca73b42ccfb419161160");
    fclose(f_hash);

    // Предполагаем, что подпись валидна
    int result = verify_sig(file);
    ck_assert_int_eq(result, 0);  // 0 — успех
}
END_TEST

// Тест на фильтрацию файлов
//START_TEST(test_filter_file)
//{
//    const char *py_file = "good.py";
//    const char *txt_file = "readme.txt";

//    ck_assert_int_eq(filter_file(py_file), 1);  // Должен фильтроваться (.py)
//    ck_assert_int_eq(filter_file(txt_file), 0); // Не должен фильтроваться (.txt)
//}
//END_TEST

// Настройка тестового набора
Suite *fusexmp_suite(void)
{
    Suite *s = suite_create("Fusexmp Suite");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_gost_hash_file);
    tcase_add_test(tc_core, test_verify_sig);
//    tcase_add_test(tc_core, test_filter_file);

    suite_add_tcase(s, tc_core);
    return s;
}

int main()
{
    int number_failed;
    Suite *s = fusexmp_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
