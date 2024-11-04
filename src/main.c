/*
   main.c  --  This file is part of verify_some_rootfs_files_during_initramfs.

   Copyright (C) 2024 Similaduo

   verify_some_rootfs_files_during_initramfs is free software: you can
   redistribute it and/or modify it under the terms of the GNU General Public
   License as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   verify_some_rootfs_files_during_initramfs is distributed in the hope that it
   will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
   Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see http://www.gnu.org/licenses/.
*/

#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_file(const char *file_path, char **content, size_t *size) {
  FILE *file = fopen(file_path, "rb");
  if (!file) {
    fprintf(stderr, "Error reading file %s: %s\n", file_path, strerror(errno));
    exit(1);
  }

  fseek(file, 0, SEEK_END);
  *size = ftell(file);
  if (*size == -1L) {
    fprintf(stderr, "Error determining file size %s: %s\n", file_path,
            strerror(errno));
    fclose(file);
    exit(1);
  }
  fseek(file, 0, SEEK_SET);

  *content = malloc(*size);
  if (!*content) {
    fprintf(stderr, "Memory allocation failed\n");
    fclose(file);
    exit(1);
  }

  if (fread(*content, 1, *size, file) != *size) {
    fprintf(stderr, "Error reading file %s\n", file_path);
    free(*content);
    fclose(file);
    exit(1);
  }

  fclose(file);
}

void verify_signature(const char *file_path, const char *sig_path,
                      EVP_PKEY *pubkey) {
  char *content;
  size_t size;
  read_file(file_path, &content, &size);

  FILE *sig_file = fopen(sig_path, "rb");
  if (!sig_file) {
    fprintf(stderr, "Error reading signature file %s: %s\n", sig_path,
            strerror(errno));
    free(content);
    exit(1);
  }

  fseek(sig_file, 0, SEEK_END);
  size_t sig_size = ftell(sig_file);
  fseek(sig_file, 0, SEEK_SET);

  unsigned char *sig = malloc(sig_size);
  if (fread(sig, 1, sig_size, sig_file) != sig_size) {
    fprintf(stderr, "Error reading signature file %s\n", sig_path);
    free(content);
    free(sig);
    fclose(sig_file);
    exit(1);
  }

  fclose(sig_file);

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey)) {
    fprintf(stderr, "Error initializing digest verify\n");
    free(content);
    free(sig);
    EVP_MD_CTX_free(mdctx);
    exit(1);
  }

  if (!EVP_DigestVerifyUpdate(mdctx, content, size)) {
    fprintf(stderr, "Error updating digest verify\n");
    free(content);
    free(sig);
    EVP_MD_CTX_free(mdctx);
    exit(1);
  }

  if (!EVP_DigestVerifyFinal(mdctx, sig, sig_size)) {
    fprintf(stderr, "Signature verification failed for %s\n", file_path);
    free(content);
    free(sig);
    EVP_MD_CTX_free(mdctx);
    exit(1);
  }

  EVP_MD_CTX_free(mdctx);
  free(content);
  free(sig);
}

EVP_PKEY *load_public_key(const char *pub_key_path) {
  FILE *pub_key_file = fopen(pub_key_path, "r");
  if (!pub_key_file) {
    fprintf(stderr, "Error opening public key file %s: %s\n", pub_key_path,
            strerror(errno));
    exit(1);
  }

  EVP_PKEY *pubkey = PEM_read_PUBKEY(pub_key_file, NULL, NULL, NULL);
  fclose(pub_key_file);

  if (!pubkey) {
    fprintf(stderr, "Error reading public key from %s\n", pub_key_path);
    exit(1);
  }

  return pubkey;
}

int main(int argc, char *argv[]) {
  if (argc != 6) {
    fprintf(stderr,
            "Usage: %s <pub_key_path> <filelist_path> <filelist_sig_path> "
            "<root_path> <verify_dir>\n",
            argv[0]);
    return 1;
  }

  const char *PUB_KEY_PATH = argv[1];
  const char *FILELIST_PATH = argv[2];
  const char *FILELIST_SIG_PATH = argv[3];
  const char *ROOT_PATH = argv[4];
  const char *VERIFY_DIR = argv[5];

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  EVP_PKEY *pubkey = load_public_key(PUB_KEY_PATH);
  verify_signature(FILELIST_PATH, FILELIST_SIG_PATH, pubkey);

  char *filelist_content;
  size_t filelist_size;
  read_file(FILELIST_PATH, &filelist_content, &filelist_size);

  char *entry = strtok(filelist_content, "\n");
  while (entry) {
    char num[256], path[256];
    if (sscanf(entry, "%[^=]=%s", num, path) == 2) {
      char file_path[512], sig_path[512];

      snprintf(file_path, sizeof(file_path), "%s%s", ROOT_PATH, path);
      snprintf(sig_path, sizeof(sig_path), "%s%s.sig", VERIFY_DIR, num);

      printf("Verifying: %s\n", file_path);
      verify_signature(file_path, sig_path, pubkey);
    }
    entry = strtok(NULL, "\n");
  }

  free(filelist_content);
  EVP_PKEY_free(pubkey);
  EVP_cleanup();
  ERR_free_strings();

  printf("Verification process completed successfully.\n");

  return 0;
}
