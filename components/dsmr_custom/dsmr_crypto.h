#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Decrypt AES-128-GCM encrypted data using vendored MbedTLS.
 *
 * @param key Decryption key (16 bytes for AES-128)
 * @param key_len Length of key in bytes
 * @param iv Initialization Vector
 * @param iv_len Length of IV in bytes
 * @param ciphertext Encrypted data
 * @param ciphertext_len Length of encrypted data
 * @param tag Authentication tag
 * @param tag_len Length of tag
 * @param output Buffer to store decrypted data (must be at least
 * ciphertext_len)
 * @return 0 on success, negative error code on failure
 */
int dsmr_aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *ciphertext, size_t ciphertext_len,
                         const unsigned char *tag, size_t tag_len,
                         unsigned char *output);

/**
 * @brief Decrypt AES-128-GCM data and return the tag it authenticates to.
 *
 * Unlike dsmr_aes_gcm_decrypt(), this never discards the plaintext: it hands
 * the caller the tag computed over @p aad and the ciphertext, so the caller
 * decides what a mismatch means. Needed for meters whose additional
 * authenticated data is unknown, where the plaintext is still usable.
 *
 * @param key Decryption key (16 bytes for AES-128)
 * @param key_len Length of key in bytes
 * @param iv Initialization Vector
 * @param iv_len Length of IV in bytes
 * @param aad Additional authenticated data, may be NULL when aad_len is 0
 * @param aad_len Length of the additional authenticated data
 * @param ciphertext Encrypted data
 * @param ciphertext_len Length of encrypted data
 * @param output Buffer for the plaintext (at least ciphertext_len bytes)
 * @param tag_out Buffer for the computed tag (at least tag_len bytes)
 * @param tag_len Length of the tag to compute
 * @return 0 on success, negative error code on failure
 */
int dsmr_aes_gcm_decrypt_with_tag(const unsigned char *key, size_t key_len,
                                  const unsigned char *iv, size_t iv_len,
                                  const unsigned char *aad, size_t aad_len,
                                  const unsigned char *ciphertext,
                                  size_t ciphertext_len, unsigned char *output,
                                  unsigned char *tag_out, size_t tag_len);

#ifdef __cplusplus
}
#endif
