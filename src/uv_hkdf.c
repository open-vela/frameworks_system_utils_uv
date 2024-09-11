/*
 * Copyright (C) 2024 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <uv_ext.h>

int uv_hkdf_key_derivation(const void* algo,
    const void* salt, size_t salt_len,
    const void* ikm, size_t ikm_len,
    const void* info, size_t info_len,
    void* okm, size_t okm_len)
{
    if (!algo || (salt_len > 0 && !salt) || (salt_len == 0 && salt) || !ikm || ikm_len == 0 || (info_len > 0 && !info) || (info_len == 0 && info) || !okm || okm_len == 0) {
        return UV_EINVAL;
    }

    const mbedtls_md_info_t* md = mbedtls_md_info_from_string(algo);
    if (md == NULL) {
        return UV_EINVAL;
    }

    return mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len);
}
