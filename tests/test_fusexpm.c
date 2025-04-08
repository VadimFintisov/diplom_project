#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../fusexmp.c"  // Подключаем основной код (нужны функции)

// Тест на вычисление ГОСТ-хеша
START_TEST(test_gost_hash_file)
{
    char hash_output[65];  // Размер для ГОСТ 256 бит (64 символа + '\0')
    const char *test_file = "test_files/good.py";
    const char *expected_hash = "a1b2c3d4e5f6...";  // Ожидаемый хеш (замените на реальный)

    // Создаём тестовый файл
    FILE *f = fopen(test_file, "w");
    fprintf(f, "print('Hello, World!')\n");
    fclose(f);

    gost_hash_file(test_file, hash_output);
    ck_assert_str_eq(hash_output, expected_hash);
}
END_TEST

// Тест на проверку подписи
START_TEST(test_verify_signature)
{
    const char *hash_file = "test_files/good.py.hash";
    const char *sig_file = "test_files/good.py.hash.sig";

    // Создаём тестовые файлы 
    FILE *f_hash = fopen(hash_file, "w");
    fprintf(f_hash, "47dbf3f31719165efb018d3b89bddfddbdd8d7129e1293d4b6353c3abc47e568");
    fclose(f_hash);

    // Предполагаем, что подпись валидна
    int result = verify_signature(hash_file, sig_file);
    ck_assert_int_eq(result, 0);  // 0 — успех
}
END_TEST

// Тест на фильтрацию файлов
START_TEST(test_filter_file)
{
    const char *py_file = "good.py";
    const char *txt_file = "readme.txt";

    ck_assert_int_eq(filter_file(py_file), 1);  // Должен фильтроваться (.py)
    ck_assert_int_eq(filter_file(txt_file), 0); // Не должен фильтроваться (.txt)
}
END_TEST

// Настройка тестового набора
Suite *fusexmp_suite(void)
{
    Suite *s = suite_create("Fusexmp Suite");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_gost_hash_file);
    tcase_add_test(tc_core, test_verify_signature);
    tcase_add_test(tc_core, test_filter_file);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = fusexmp_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}