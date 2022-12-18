#include <stddef.h>

int sodium_init(void) __attribute__ ((warn_unused_result));

void randombytes_buf(void * const buf, const size_t size);

int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *c,
                                              unsigned long long *clen_p,
                                              const unsigned char *m,
                                              unsigned long long mlen,
                                              const unsigned char *ad,
                                              unsigned long long adlen,
                                              const unsigned char *nsec,
                                              const unsigned char *npub,
                                              const unsigned char *k);

int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m,
                                              unsigned long long *mlen_p,
                                              unsigned char *nsec,
                                              const unsigned char *c,
                                              unsigned long long clen,
                                              const unsigned char *ad,
                                              unsigned long long adlen,
                                              const unsigned char *npub,
                                              const unsigned char *k)
                                              __attribute__ ((warn_unused_result));

int crypto_aead_xchacha20poly1305_ietf_encrypt(unsigned char *c,
                                               unsigned long long *clen_p,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *nsec,
                                               const unsigned char *npub,
                                               const unsigned char *k);

int crypto_aead_xchacha20poly1305_ietf_decrypt(unsigned char *m,
                                               unsigned long long *mlen_p,
                                               unsigned char *nsec,
                                               const unsigned char *c,
                                               unsigned long long clen,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *npub,
                                               const unsigned char *k)
                                               __attribute__ ((warn_unused_result));
