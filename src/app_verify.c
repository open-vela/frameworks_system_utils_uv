#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "unzip.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define assert_res(x)                                                                       \
    do {                                                                                    \
        if (!(x)) {                                                                         \
            printf("errno %s, %s:%d >> \t(%s)\n", strerror(errno), __FILE__, __LINE__, #x); \
            goto error;                                                                     \
        }                                                                                   \
    } while (0)

typedef struct app_verify_s {
  char *app_path;
  char *pkg_path;
  unzFile zFile;
  unz_global_info64 zGlobalInfo;
  uint8_t *fingerprint;
} app_verify_t;

// length - data block
typedef struct data_block_s {
    uint8_t* data;
    uint32_t length;
} data_block_t;

typedef struct app_block_s {
    data_block_t data_block;
    data_block_t signature_block;
    data_block_t central_directory_block;
    data_block_t eocd_block;

} app_block_t;

// signature block data structure

/*---------------------

    signature_block_s
    |
    |---- signed_data
    |     |---- digests
    |     |---- certificate
    |
    |---- signatures
    |     |---- signatures_algorithm_id
    |     |---- signatures_content
    |
    |---- public_key

------------------------*/

typedef struct signature_block_s {
    data_block_t one_sign_block;
    data_block_t signed_data;
    data_block_t signatures;
    data_block_t public_key;
    data_block_t digests;
    uint32_t digests_signatures_algorithm_id;
    data_block_t one_digest;
    data_block_t certificate;
    uint32_t signatures_algorithm_id;
    data_block_t signatures_content;
} signature_block_t;

/**
 * @brief Create folder recursively
 */
static int recursion_mkdir(const char* path)
{
    char data[PATH_MAX];
    char* ret;
    int res;

    if ((strcmp(path, ".") == 0) || (strcmp(path, "/") == 0))
        return 0;

    res = access(path, F_OK);

    if (res == 0) {
        return 0;
    } else {
        strcpy(data, path);
        ret = strrchr(data, '/');
        if (ret != 0) {
            *ret = 0;
            recursion_mkdir(data);
        }
    }

    res = mkdir(path, 0777);

    return res;
}

/**
 * @brief Create a file and its folder
 */
static int mkfile(const char* path)
{
    char* ret;
    char fileName[PATH_MAX];
    strcpy(fileName, path);
    ret = strrchr(fileName, '/');
    if (ret == 0) {
        return open(path, O_RDWR | O_CREAT, 0777);
    }
    *ret++ = 0;

    recursion_mkdir(fileName);

    return open(path, O_RDWR | O_CREAT, 0777);
}

/**
 * @brief Save file
 */
int write_file(const char*path, const void* data, size_t size)
{
    FILE* fd;
    int res = -1;
    fd = fopen(path, "wb");
    assert(fd);
    res = fwrite(data, size, 1, fd);
    fclose(fd);
    return res;
}

/**
 * @brief Create PEM format file
 */
static int generate_pem(const char* name, const uint8_t* data, size_t length, const char* type)
{
    FILE* fp = fopen(name, "wb");
    size_t available, buffer_size = (length / 3 + 1) * 4 + 1;
    uint8_t* base64_data = (uint8_t*)malloc(buffer_size);
    size_t res = 0;

    assert(fp);
    fprintf(fp, "-----BEGIN %s-----\n", type);
    assert_res((res = mbedtls_base64_encode(base64_data, buffer_size, &available, data, length)) == 0);
    for (size_t i = 0; i < available / 64; i++) {
        res += fwrite(base64_data + res, 1, 64, fp);
        fwrite("\n", 1, 1, fp);
    }

    if (available % 64 != 0) {
        res += fwrite(base64_data + res, 1, available % 64, fp);
        fwrite("\n", 1, 1, fp);
    }
    fprintf(fp, "-----END %s-----\n", type);

error:
    fclose(fp);
    free(base64_data);
    return res;
}

/**
 * @brief analysis len-data block
 */
static uint8_t* parse_block(uint8_t* data, data_block_t* block)
{
    uint32_t len;
    assert(data && block);

    uint8_t* offset = data;

    memcpy(&len, data, sizeof(len));
    block->length = len;
    offset += 4;
    block->data = offset;
    offset += block->length;

    return offset;
}

/**
 * @brief analysis len-id-data block
 */
static uint8_t* parse_kv_block(uint8_t* data, uint64_t* key, uint8_t** value)
{
    assert(data && key);

    uint8_t* offset = data;
    uint64_t length = 0;
    memcpy(&length, data, sizeof(uint64_t));

    offset += 8;

    memcpy(key, offset, sizeof(uint32_t));
    offset += 4;
    *value = offset;
    offset += length - 4;

    return offset;
}
static app_block_t parse_app_block(const char *app_path, size_t comment_len) {
  int fd = -1;

  app_block_t app_block;
  off_t central_directory_offset = 0;
  off_t  file_offset;

  assert_res((fd = open(app_path, O_RDONLY)) > 0);

  // Get Central_Directory start offset
  off_t central_directory_ptr_offset = -comment_len - 4 - 2;
  lseek(fd, central_directory_ptr_offset, SEEK_END);
  assert_res(read(fd, &central_directory_offset, 4) > 0);

  // Get the length of the signature block
  off_t signature_block_len_offset = central_directory_offset - 16 - 8;
  lseek(fd, signature_block_len_offset, SEEK_SET);
  assert_res(read(fd, &app_block.signature_block.length, 4) > 0);

  // Read the signature block
  off_t signature_block_offset = central_directory_offset - app_block.signature_block.length;
  file_offset = lseek(fd, signature_block_offset, SEEK_SET);
  assert_res((app_block.signature_block.data =
                  malloc(app_block.signature_block.length)) != NULL);
  assert_res((read(fd, app_block.signature_block.data,
                   app_block.signature_block.length)) > 0);

  // Read EOCD
  off_t ecod_start_offset = central_directory_ptr_offset - 16;
  lseek(fd, ecod_start_offset, SEEK_END);
  app_block.eocd_block.length = -1 * ecod_start_offset;
  ecod_start_offset = lseek(fd, 0, SEEK_CUR);
  app_block.eocd_block.data = (uint8_t *)(long)ecod_start_offset;

  // Read Central_Directory
  file_offset = lseek(fd, central_directory_offset, SEEK_SET);
  app_block.central_directory_block.length =
      ecod_start_offset - central_directory_offset;
  app_block.central_directory_block.data = (uint8_t*)(long)file_offset;

  // Read the zip content
  app_block.data_block.length = signature_block_offset;

  app_block.data_block.data = app_block.signature_block.data;

error:
  close(fd);
  return app_block;
}

/**
 * @brief Get the signature piece information
 */
static uint8_t* get_signature_info(uint8_t* data, signature_block_t* info)
{
    uint8_t *offset, *ret;

    // Get the current signature block
    offset = parse_block(data, &info->one_sign_block);

    // Get the current signature data block
    offset = parse_block(info->one_sign_block.data, &info->signed_data);
    offset = parse_block(offset, &info->signatures);
    offset = parse_block(offset, &info->public_key);
    ret = offset;

    // get signed_data
    offset = parse_block(info->signed_data.data, &info->digests);

    memcpy(&info->digests_signatures_algorithm_id, (info->digests.data + 4), sizeof(uint32_t));
    offset = parse_block(info->digests.data + 8, &info->one_digest);

    offset = parse_block(offset, &info->certificate);
    offset = parse_block(info->certificate.data, &info->certificate);

    // get signatures
    offset = parse_block(info->signatures.data, &info->signatures_content);
    memcpy(&info->signatures_algorithm_id, info->signatures_content.data, sizeof(uint32_t));
    offset = parse_block(info->signatures.data + 8, &info->signatures_content);

    return ret;
}

/**
 * @brief Verify the signature on the app
 */
static int verify_block_signature(data_block_t* pubkey, data_block_t* raw_data, data_block_t* signature)
{
    unsigned char* md = NULL;
    int res = -1;
    mbedtls_pk_context pk;

    // Initial public key
    mbedtls_pk_init(&pk);
    assert_res((res = mbedtls_pk_parse_public_key(&pk, pubkey->data, pubkey->length)) == 0);

    // The calculation method of the specific summary
    const mbedtls_md_info_t* mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    assert_res((md = malloc(mbedtls_md_get_size(mdinfo))) != NULL);

    // Verify the data digest
    assert_res((res = mbedtls_md(mdinfo, raw_data->data, raw_data->length, md)) == 0);

    // Verify the signature
    assert_res((res = mbedtls_pk_verify(&pk, mbedtls_md_get_type(mdinfo),
          md, mbedtls_md_get_size(mdinfo), signature->data, signature->length)) == 0);

error:
    free(md);
    mbedtls_pk_free(&pk);
    return res;
}

/**
 * @brief Verify the app Digest
 */
static int app_block_digest_verification(app_verify_t *app_verift_info, data_block_t* digest) {
  int res = -1;
  unsigned char *md = NULL;

  const mbedtls_md_info_t *mdinfo =mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  assert_res(md = malloc(mbedtls_md_get_size(mdinfo)));
//   assert_res(mbedtls_md_file(mdinfo, app_verift_info->app_path,md));

//   memcmp(md, digest->data, mbedtls_md_get_size(mdinfo));
  res = 0;
error:
  free(md);
  return res;
}

/**
 * @brief app Signature verification
 */
static int app_verification(app_verify_t *app_verify_info)
{
    int res = -1;
    uint64_t id;
    app_block_t app_block = { 0 };
    signature_block_t signature_info;
    char cer_path[PATH_MAX];
    // get APK Signing Block
    app_block = parse_app_block(app_verify_info->app_path, app_verify_info->zGlobalInfo.size_comment);

    uint8_t* offset;
    // parse Signing Block
    parse_kv_block(app_block.signature_block.data, &id, &offset);
    parse_block(offset, &app_block.signature_block);
    get_signature_info(app_block.signature_block.data, &signature_info);

    // Save certificate file
    strcpy(cer_path, app_verify_info->app_path);
    strcat(cer_path, ".certificate.pem");
    generate_pem(cer_path, signature_info.certificate.data, signature_info.certificate.length, "CERTIFICATE");
    strcpy(cer_path, app_verify_info->app_path);
    strcat(cer_path, ".certificate.der");
    write_file(cer_path, signature_info.certificate.data, signature_info.certificate.length);

    // Verify block signature
    assert_res((res = verify_block_signature(&signature_info.public_key, &signature_info.signed_data,
                    &signature_info.signatures_content))== 0);

    // Compare whether the signature algorithms are consistent
    assert_res(signature_info.digests_signatures_algorithm_id == signature_info.signatures_algorithm_id);

    // Compare whether the app summary is consistent with the signature block summary
    assert_res(app_block_digest_verification(app_verify_info, &signature_info.one_digest) == 0);
error:
    free(app_block.data_block.data);
    return res;
}

/**
 * @brief app unzip
 */
static int app_unzip(unzFile zFile, const char* pkg_path)
{
    int res = 0, fd = -1;
    char path[PATH_MAX];
    char *fileData = NULL, *fileName = path;

    unz_global_info64 zGlobalInfo;

    assert_res(unzGetGlobalInfo64(zFile, &zGlobalInfo) == UNZ_OK);

    for (int i = 0; i < zGlobalInfo.number_entry; ++i) {
        unz_file_info64 zFileInfo;

        strcpy(path, pkg_path);
        fileName += strlen(pkg_path);
        *fileName++ = '/';
        *fileName = '\0';

        // Get current compressed file information
        assert_res(unzGetCurrentFileInfo64(zFile, &zFileInfo, fileName,
                sizeof(path) - strlen(path), NULL, 0, NULL, 0) == UNZ_OK);

        if (zFileInfo.external_fa) {
            recursion_mkdir(path);
            goto next;
        }

        assert_res(unzOpenCurrentFile(zFile) == UNZ_OK);

        assert_res((res = fd = mkfile(path)) > 0);

        int fileLength = zFileInfo.uncompressed_size;
        assert_res((fileData = malloc(fileLength)) != NULL);

        // unzip file
        assert_res((res = unzReadCurrentFile(zFile, (voidp)fileData, fileLength)) >= 0);

        assert_res((res = write(fd, fileData, res)) > 0);
    next:
        // Close the current compressed file and switch to the next file
        unzCloseCurrentFile(zFile);
        unzGoToNextFile(zFile);
        close(fd);
        free(fileData);
        fileData = NULL;
        fileName = path;
        fd = -1;
    }
    res = 0;
error:
    free(fileData);
    close(fd);
    return res;
}

int app_pre_unzip(app_verify_t* app_verify_info, const char* unzip_filename)
{
    int res = 0, fd = -1;
    char path[PATH_MAX];
    char *fileData = NULL, *fileName = path;

    unz_file_info64 zFileInfo;
    unz_global_info64 zGlobalInfo;

    assert_res(unzip_filename);
    assert_res(unzGetGlobalInfo64(app_verify_info->zFile, &zGlobalInfo) == UNZ_OK);

    strcpy(path, app_verify_info->pkg_path);
    fileName += strlen(app_verify_info->pkg_path);
    *fileName++ = '/';
    *fileName = '\0';

    for (int i = 0; i < zGlobalInfo.number_entry; ++i) {

        assert_res(unzGetCurrentFileInfo64(app_verify_info->zFile, &zFileInfo, fileName,
                       sizeof(path) - strlen(path), NULL, 0, NULL, 0) == UNZ_OK);

        if(strcmp(unzip_filename, fileName)!=0) {
            unzGoToNextFile(app_verify_info->zFile);
            continue;
        }else{
            break;
        }
    }

    assert_res(unzOpenCurrentFile(app_verify_info->zFile) == UNZ_OK);
    assert_res((res = fd = mkfile(path)) > 0);

    int fileLength = zFileInfo.uncompressed_size;
    assert_res((fileData = malloc(fileLength)) != NULL);

    assert_res((res = unzReadCurrentFile(app_verify_info->zFile, (voidp)fileData, fileLength)) >= 0);

    assert_res((res = write(fd, fileData, res)) > 0);
    res = 0;
error:
    unzCloseCurrentFile(app_verify_info->zFile);
    free(fileData);
    close(fd);
    return res;
}


/**
 * @brief app verify & unzip
 */
int app_verify_unzip(app_verify_t* app_verify_info)
{
    int res = -1;

    // Verify app legitimacy
    assert_res(app_verification(app_verify_info) == 0);

    // unzip app
    assert_res((res = app_unzip(app_verify_info->zFile, app_verify_info->pkg_path)) == 0);
error:
    return res;
}

uint8_t* app_get_fingerprint(app_verify_t *app_verify_info)
{
    char cer_path[PATH_MAX];
    strcpy(cer_path, app_verify_info->app_path);
    strcat(cer_path, ".certificate.der");

    const mbedtls_md_info_t* mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    assert_res((app_verify_info->fingerprint = malloc(mbedtls_md_get_size(mdinfo))) != NULL);

    assert_res(0 == mbedtls_md_file(mdinfo, cer_path, app_verify_info->fingerprint ));

    return app_verify_info->fingerprint;
error:
    app_verify_info->fingerprint = NULL;
    free(app_verify_info->fingerprint);
    return NULL;
}

/**
 * @brief app verify init
 */
app_verify_t *app_verify_init(const char *app_path, const char *pkg_path) {
  app_verify_t *app_verify_info = NULL;

  assert_res(app_path);
  assert_res(pkg_path);

  assert_res(app_verify_info = (app_verify_t *)calloc(1, sizeof(app_verify_t)));

  assert_res((app_verify_info->zFile = unzOpen64(app_path)) != NULL);
  assert_res(unzGetGlobalInfo64(app_verify_info->zFile,
                                &app_verify_info->zGlobalInfo) == UNZ_OK);

  assert_res(app_verify_info->app_path = strdup(app_path));
  assert_res(app_verify_info->pkg_path = strdup(pkg_path));

  return app_verify_info;
error:
  unzClose(app_verify_info->zFile);
  free(app_verify_info->pkg_path);
  free(app_verify_info->app_path);
  free(app_verify_info);
  return NULL;
}

void app_verify_close(app_verify_t *app_verify_info) {
  free(app_verify_info->app_path);
  free(app_verify_info->pkg_path);
  free(app_verify_info->fingerprint);
  unzClose(app_verify_info->zFile);
  free(app_verify_info);
}

