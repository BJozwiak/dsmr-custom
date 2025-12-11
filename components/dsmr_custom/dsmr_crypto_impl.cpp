#ifdef USE_ESP_IDF

#include "dsmr_crypto.h"
#include "esphome/core/log.h"

// ESP-IDF's MbedTLS uses hardware-accelerated esp_aes_gcm functions
// Include the ESP32-specific header
#include <aes/esp_aes_gcm.h>

extern "C" int dsmr_aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                                    const unsigned char *iv, size_t iv_len,
                                    const unsigned char *ciphertext, size_t ciphertext_len,
                                    const unsigned char *tag, size_t tag_len,
                                    unsigned char *output) {
  
  ESP_LOGV("dsmr_crypto_impl", "Starting AES-GCM decryption using ESP-IDF esp_aes_gcm functions.");

  esp_gcm_context ctx;
  esp_aes_gcm_init(&ctx);

  int ret = esp_aes_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
  if (ret != 0) {
    esp_aes_gcm_free(&ctx);
    return ret;
  }

  // esp_aes_gcm_auth_decrypt argument order:
  // ctx, length, iv, iv_len, add, add_len, tag, tag_len, input, output
  
  //ESP_LOGVV("IV", "Decryption IV (Hex): %02X %02X %02X %02X %02X %02X %02X %02X    %02X %02X %02X %02X",
  //             iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11]);
  //ESP_LOGVV("", "Ciphertext (Hex): %02X %02X %02X %02X %02X %02X %02X %02X    %02X %02X %02X %02X %02X %02X %02X %02X",
  //           ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3],
  //           ciphertext[4], ciphertext[5], ciphertext[6], ciphertext[7],
  //           ciphertext[8],
  //           ciphertext[ciphertext_len -8], ciphertext[ciphertext_len -7],ciphertext[ciphertext_len -6],ciphertext[ciphertext_len -5],
  //           ciphertext[ciphertext_len -4],ciphertext[ciphertext_len -3],ciphertext[ciphertext_len -2],ciphertext[ciphertext_len -1],
  //           ciphertext[ciphertext_len]);
  //             iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11]);
  ret = esp_aes_gcm_auth_decrypt(&ctx, ciphertext_len, iv, iv_len, NULL, 0, tag,
                                 tag_len, ciphertext, output);
  ESP_LOGV("RET", "Decryption result: %d", ret);
  esp_aes_gcm_free(&ctx);
  return ret;
}

#endif // USE_ESP_IDF
