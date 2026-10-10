/* Independent OpenSSL EVP peer. Files contain ephemeral test material only. */
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
static unsigned char *read_bytes(const char *path, int *length) {
  FILE *file = fopen(path, "rb");
  if (!file || fseek(file, 0, SEEK_END)) exit(2);
  long n = ftell(file);
  if (n < 0 || n > 1048600 || fseek(file, 0, SEEK_SET)) exit(2);
  unsigned char *data = calloc((size_t)n + 1, 1);
  if (!data || fread(data, 1, (size_t)n, file) != (size_t)n) exit(2);
  fclose(file); *length = (int)n; return data;
}
int main(int argc, char **argv) {
  if (argc != 7) return 2;
  int encrypt = strcmp(argv[1], "encrypt") == 0;
  if (!encrypt && strcmp(argv[1], "decrypt")) return 2;
  int kn, vn, an, dn, n = 0, total = 0;
  unsigned char *key = read_bytes(argv[2], &kn), *iv = read_bytes(argv[3], &vn);
  unsigned char *aad = read_bytes(argv[4], &an), *data = read_bytes(argv[5], &dn);
  if ((kn != 16 && kn != 32) || vn != 12 || (!encrypt && dn < 16)) return 2;
  unsigned char *out = calloc((size_t)dn + 32, 1);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cipher = kn == 16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
  int good = ctx && out;
  if (encrypt) {
    good = good && EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) == 1;
    good = good && EVP_EncryptUpdate(ctx, NULL, &n, aad, an) == 1;
    good = good && EVP_EncryptUpdate(ctx, out, &n, data, dn) == 1; total = n;
    good = good && EVP_EncryptFinal_ex(ctx, out + total, &n) == 1; total += n;
    good = good && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + total) == 1; total += 16;
  } else {
    good = good && EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) == 1;
    good = good && EVP_DecryptUpdate(ctx, NULL, &n, aad, an) == 1;
    good = good && EVP_DecryptUpdate(ctx, out, &n, data, dn - 16) == 1; total = n;
    good = good && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, data + dn - 16) == 1;
    good = good && EVP_DecryptFinal_ex(ctx, out + total, &n) == 1; total += n;
  }
  if (good) {
    FILE *file = fopen(argv[6], "wb");
    good = file && fwrite(out, 1, (size_t)total, file) == (size_t)total;
    if (file) fclose(file);
  }
  OPENSSL_cleanse(key, (size_t)kn); OPENSSL_cleanse(out, (size_t)dn + 32);
  free(key); free(iv); free(aad); free(data); free(out); EVP_CIPHER_CTX_free(ctx);
  if (!good) { fputs("Authentication or operation failed\n", stderr); return 1; }
  puts("Authenticated reciprocal operation completed"); return 0;
}
