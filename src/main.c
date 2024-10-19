/**
@file main.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <locale.h>

///\brief Определение размера ключа
#define KEY_SIZE 2048

// Структура для хранения ключей
/**
 @brief Структура для хранения ключей.
 
 Содержит указатель на объект EVP_PKEY, представляющий ключ, 
 а также данные ключа в двоичном формате и его размер.
 */
typedef struct
{
    EVP_PKEY *pkey;
    unsigned char *key_data;
    size_t key_data_len;
} KeyData;

// Функция генерации ключа
/**
 @brief Функция генерации ключа.
 
 Генерирует пару ключей RSA с заданным размером ключа (KEY_SIZE) 
 и сохраняет их в структуру KeyData.
 
 @return Указатель на структуру KeyData, содержащую сгенерированный ключ.
 */
KeyData *generate_key()
{
    KeyData *key = malloc(sizeof(KeyData));
    if (key == NULL)
    {
        fprintf(stderr, "Ошибка выделения памяти\n");
        exit(1);
    }
    key->pkey = EVP_PKEY_new();
    key->key_data = NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL)
    {
        fprintf(stderr, "Ошибка инициализации контекста ключа\n");
        exit(1);
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        fprintf(stderr, "Ошибка инициализации генерации ключа\n");
        exit(1);
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_SIZE) <= 0)
    {
        fprintf(stderr, "Ошибка установки размера ключа\n");
        exit(1);
    }

    if (EVP_PKEY_keygen(ctx, &key->pkey) <= 0)
    {
        fprintf(stderr, "Ошибка генерации ключа\n");
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx);

    // Сохранение ключа в двоичном формате
    key->key_data_len = i2d_PublicKey(key->pkey, &key->key_data);
    printf("Ключи сгенерированы\n");
    return key;
}
/**
  @brief Функция сохранения ключа в файл.
  
  Сохраняет открытый и закрытый ключи в отдельные файлы в формате PEM. 
  Имена файлов формируются путем добавления "_pub.pem" и "_priv.pem" 
  к переданному имени файла.
  
  @param filename Имя файла, к которому будут добавлены суффиксы 
  "_pub.pem" и "_priv.pem" для формирования имен файлов.
  @param key Указатель на структуру KeyData, содержащую ключ.
*/
// Функция сохранения ключа в файл
void save_key(const char *filename, KeyData *key)
{
    char pub_file[2048] = "";
    char priv_file[2048] = "";
    sprintf(pub_file, "%s_pub.pem", filename);
    sprintf(priv_file, "%s_priv.pem", filename);
    BIO *fb = BIO_new_file(pub_file, "wb");
    if (fb == NULL)
    {
        fprintf(stderr, "Ошибка открытия файла %s\n", pub_file);
        exit(1);
    }

    if (PEM_write_bio_PUBKEY(fb, key->pkey) <= 0)
    {
        fprintf(stderr, "Ошибка записи ключа в файл %s\n", pub_file);
        exit(1);
    }
    BIO_free(fb);
    printf("Открытый ключ сохранен\n");

    fb = BIO_new_file(priv_file, "wb");
    if (fb == NULL)
    {
        fprintf(stderr, "Ошибка открытия файла %s\n", priv_file);
        exit(1);
    }

    if (PEM_write_bio_PrivateKey(fb, key->pkey, NULL, NULL, 0, NULL, NULL) <= 0)
    {
        fprintf(stderr, "Ошибка записи ключа в файл %s\n", priv_file);
        exit(1);
    }
    BIO_free(fb);
    printf("Секретный ключ сохранен\n");
}
/**
  @brief Функция загрузки ключа из файла.
  
  Загружает ключ из файла в формате PEM. Тип ключа (открытый или закрытый) 
  определяется параметром `type`.
  
  @param filename Имя файла, из которого будет загружен ключ.
  @param type Тип ключа: "pub" для открытого ключа, "priv" для закрытого ключа.
  
  @return Указатель на структуру KeyData, содержащую загруженный ключ.
*/
// Функция загрузки ключа из файла
KeyData *load_key(const char *filename, const char *type)
{
    KeyData *key = malloc(sizeof(KeyData));
    if (key == NULL)
    {
        fprintf(stderr, "Ошибка выделения памяти\n");
        exit(1);
    }
    key->pkey = NULL;
    key->key_data = NULL;

    BIO *fb = BIO_new_file(filename, "rb");
    if (fb == NULL)
    {
        fprintf(stderr, "Ошибка открытия файла %s\n", filename);
        exit(1);
    }
    if (type == "pub")
    {
        key->pkey = PEM_read_bio_PUBKEY(fb, NULL, NULL, NULL);
        if (key->pkey == NULL)
        {
            fprintf(stderr, "Ошибка чтения ключа из файла %s\n", filename);
            exit(1);
        }
    }
    else if (type == "priv")
    {
        key->pkey = PEM_read_bio_PrivateKey(fb, NULL, NULL, NULL);
        if (key->pkey == NULL)
        {
            fprintf(stderr, "Ошибка чтения ключа из файла %s\n", filename);
            exit(1);
        }
    }
    else
    {
        exit(1);
    }

    // Сохранение ключа в двоичном формате
    key->key_data_len = i2d_PublicKey(key->pkey, &key->key_data);

    BIO_free(fb);
    return key;
}
/**
  @brief Подписывает файл с использованием указанного ключа.
 
  Функция подписывает файл с использованием указанного ключа и
  сохраняет подпись в файл с расширением ".sig".
 
  @param file_path Путь к файлу для подписи.
  @param key Указатель на структуру KeyData, содержащую ключ.
 
  @return Возвращает 0 в случае успеха, 1 в случае ошибки.
*/
// Функция подписи файла
void sign_file(const char *file_path, KeyData *key)
{
    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "Ошибка открытия файла %s\n", file_path);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    unsigned char *file_data = malloc(file_size);
    if (file_data == NULL)
    {
        fprintf(stderr, "Ошибка выделения памяти\n");
        exit(1);
    }

    fread(file_data, 1, file_size, fp);
    fclose(fp);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "Ошибка инициализации контекста хеширования\n");
        exit(1);
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0)
    {
        fprintf(stderr, "Ошибка инициализации алгоритма хеширования\n");
        exit(1);
    }

    if (EVP_DigestUpdate(ctx, file_data, file_size) <= 0)
    {
        fprintf(stderr, "Ошибка обновления хеша\n");
        exit(1);
    }

    unsigned char signature[EVP_PKEY_size(key->pkey)];
    unsigned int signature_len;
    memset(signature, 0, EVP_PKEY_size(key->pkey));

    if (EVP_SignInit_ex(ctx, EVP_sha256(), 0) <= 0)
    {
        fprintf(stderr, "Ошибка инициализации подписи\n");
        exit(1);
    }

    if (EVP_SignUpdate(ctx, file_data, file_size) <= 0)
    {
        fprintf(stderr, "Ошибка обновления подписи\n");
        exit(1);
    }

    if (EVP_SignFinal(ctx, signature, &signature_len, key->pkey) <= 0)
    {
        fprintf(stderr, "Ошибка завершения подписи\n");
        exit(1);
    }

    EVP_MD_CTX_free(ctx);
    free(file_data);

    // Сохранение подписи в файл
    char *signature_file = malloc(strlen(file_path) + strlen(".sig") + 1);
    strcpy(signature_file, file_path);
    strcat(signature_file, ".sig");

    fp = fopen(signature_file, "wb");
    if (fp == NULL)
    {
        fprintf(stderr, "Ошибка открытия файла %s\n", signature_file);
        exit(1);
    }

    fwrite(signature, 1, signature_len, fp);
    fclose(fp);
    free(signature_file);

    printf("Подпись файла %s сохранена в %s\n", file_path, signature_file);
}
/**
  @brief Проверяет подпись файла с использованием указанного ключа.
 
  Функция проверяет подпись файла с использованием указанного ключа и
  выводит результат проверки на консоль.
 
  @param file_path Путь к файлу для проверки.
  @param signature_file Путь к файлу с подписью.
  @param key Указатель на структуру KeyData, содержащую ключ.
 
  @return Возвращает 0 в случае успеха, 1 в случае ошибки.
*/
// Функция проверки подписи файла
void verify_signature(const char *file_path, const char *signature_file, KeyData *key)
{
    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "Ошибка открытия файла %s\n", file_path);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    unsigned char *file_data = malloc(file_size);
    if (file_data == NULL)
    {
        fprintf(stderr, "Ошибка выделения памяти\n");
        exit(1);
    }

    fread(file_data, 1, file_size, fp);
    fclose(fp);

    fp = fopen(signature_file, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "Ошибка открытия файла %s\n", signature_file);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    long signature_size = ftell(fp);
    rewind(fp);

    unsigned char *signature = malloc(signature_size);
    if (signature == NULL)
    {
        fprintf(stderr, "Ошибка выделения памяти\n");
        exit(1);
    }

    fread(signature, 1, signature_size, fp);
    fclose(fp);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "Ошибка инициализации контекста хеширования\n");
        exit(1);
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0)
    {
        fprintf(stderr, "Ошибка инициализации алгоритма хеширования\n");
        exit(1);
    }

    if (EVP_DigestUpdate(ctx, file_data, file_size) <= 0)
    {
        fprintf(stderr, "Ошибка обновления хеша\n");
        exit(1);
    }

    int verified = EVP_VerifyFinal(ctx, signature, signature_size, key->pkey);
    EVP_MD_CTX_free(ctx);
    free(file_data);
    free(signature);

    if (verified == 1)
    {
        printf("Подпись верна\n");
    }
    else
    {
        fprintf(stderr, "Ошибка проверки подписи\n");
        exit(1);
    }
}
/**
  @brief Основная функция программы.
 
  Функция `main` обрабатывает аргументы командной строки и вызывает
  соответствующие функции для генерации ключей, подписи и проверки
  подписи файлов.
 
  @param argc Количество аргументов командной строки.
  @param argv Массив аргументов командной строки.
 
  @return Возвращает 0 в случае успеха, 1 в случае ошибки.
*/
int main(int argc, char **argv)
{
    setlocale(LC_ALL, "Russian");
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    char *key_file = NULL;
    char *file_path = NULL;
    char *signature_file = NULL;
    int generate = 0;
    int sign = 0;
    int verify = 0;

    static struct option long_options[] = {
        {"key", required_argument, 0, 'k'},
        {"file", required_argument, 0, 'f'},
        {"signature", required_argument, 0, 's'},
        {"generate", no_argument, 0, 'g'},
        {"sign", no_argument, 0, 'n'},
        {"verify", no_argument, 0, 'v'},
        {0, 0, 0, 0}};

    int option_index = 0;
    int c;
    while ((c = getopt_long(argc, argv, "k:f:s:gvn", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'k':
            key_file = optarg;
            break;
        case 'f':
            file_path = optarg;
            break;
        case 's':
            signature_file = optarg;
            break;
        case 'g':
            generate = 1;
            break;
        case 'n':
            sign = 1;
            break;
        case 'v':
            verify = 1;
            break;
        default:
            fprintf(stderr, "Неверный аргумент: %c\n", optopt);
            exit(1);
        }
    }

    KeyData *key = NULL;
    if (generate)
    {
        if (key_file == NULL)
        {
            fprintf(stderr, "Необходимо указать файл для сохранения ключа\n");
            exit(1);
        }
        key = generate_key();
        save_key(key_file, key);
    }

    if (sign && file_path != NULL)
    {
        if (key_file != NULL)
        {
            key = load_key(key_file, "priv");
        }
        else
        {
            fprintf(stderr, "Необходимо указать файл с ключом\n");
            exit(1);
        }
        sign_file(file_path, key);
    }
    else if (verify && file_path != NULL && signature_file != NULL)
    {
        if (key_file != NULL)
        {
            key = load_key(key_file, "pub");
        }
        else
        {
            fprintf(stderr, "Необходимо указать файл с ключом\n");
            exit(1);
        }
        verify_signature(file_path, signature_file, key);
    }

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    free(key);

    return 0;
}