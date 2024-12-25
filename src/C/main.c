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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_SIZE 4096

void handle_sigint(int sig) {}

void ask_user(void) {
  char response[3];
  printf("Seems like some of your rootfs file is corrupt, do you want to "
         "continue?\nNOTE: For security reasons, the emergency shell is "
         "disabled in many distros right now.\nSo the only choice you can type "
         "is 'y' or 'Y' if you still want to boot via the rootfs located in "
         "your initial hard drive.\nOf course, if you think the reason of the "
         "corruption of some rootfs file is due to some security issues, "
         "please do not boot from the existing rootfs but boot from a bootable "
         "usb drive to check your rootfs files.\nYou can press ctrl+alt+del to "
         "reboot you computer.\nNow typing your choice ('y' or 'Y' if you "
         "still want to continue) or press ctrl+alt+del to reboot\n");

  while (1) {
    if (fgets(response, sizeof(response), stdin) != NULL) {
      response[strcspn(response, "\n")] = '\0';
      if (strlen(response) > 1) {
        printf("Invalid choice, please input 'y' or 'Y' if you still want to "
               "continue the boot process:\n");
        while (getchar() != '\n') {
        }
      } else if (response[0] == 'y' || response[0] == 'Y') {
        exit(0);
      } else {
        printf("Invalid choice, please input 'y' or 'Y' if you still want to "
               "continue the boot process:\n");
      }
    } else {
      printf("Failed to get input.\n");
      exit(1);
    }
  }
}

void read_file_chunked(const char *file_path,
                       void (*process_chunk)(const unsigned char *, size_t,
                                             EVP_MD_CTX *),
                       EVP_MD_CTX *mdctx) {
  FILE *file = fopen(file_path, "rb");
  if (!file) {
    fprintf(stderr, "Error reading file %s: %s\n", file_path, strerror(errno));
    ask_user();
  }

  unsigned char buffer[CHUNK_SIZE];
  size_t bytes_read;
  while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
    process_chunk(buffer, bytes_read, mdctx);
  }

  if (ferror(file)) {
    fprintf(stderr, "Error reading file %s\n", file_path);
    fclose(file);
    ask_user();
  }

  fclose(file);
}

void process_chunk(const unsigned char *chunk, size_t size, EVP_MD_CTX *mdctx) {
  if (!EVP_DigestVerifyUpdate(mdctx, chunk, size)) {
    fprintf(stderr, "Error updating digest verify\n");
    ask_user();
  }
}

void verify_signature(const char *file_path, const char *sig_path,
                      EVP_PKEY *pubkey) {
  FILE *sig_file = fopen(sig_path, "rb");
  if (!sig_file) {
    fprintf(stderr, "Error reading signature file %s: %s\n", sig_path,
            strerror(errno));
    ask_user();
  }

  fseek(sig_file, 0, SEEK_END);
  size_t sig_size = ftell(sig_file);
  fseek(sig_file, 0, SEEK_SET);

  unsigned char *sig = malloc(sig_size);
  if (fread(sig, 1, sig_size, sig_file) != sig_size) {
    fprintf(stderr, "Error reading signature file %s\n", sig_path);
    free(sig);
    fclose(sig_file);
    ask_user();
  }

  fclose(sig_file);

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey)) {
    fprintf(stderr, "Error initializing digest verify\n");
    free(sig);
    EVP_MD_CTX_free(mdctx);
    ask_user();
  }

  read_file_chunked(file_path, process_chunk, mdctx);

  if (!EVP_DigestVerifyFinal(mdctx, sig, sig_size)) {
    fprintf(stderr, "Signature verification failed for %s\n", file_path);
    free(sig);
    EVP_MD_CTX_free(mdctx);
    ask_user();
  }

  EVP_MD_CTX_free(mdctx);
  free(sig);
}

EVP_PKEY *load_public_key(const char *pub_key_path) {
  FILE *pub_key_file = fopen(pub_key_path, "r");
  if (!pub_key_file) {
    fprintf(stderr, "Error opening public key file %s: %s\n", pub_key_path,
            strerror(errno));
    ask_user();
  }

  EVP_PKEY *pubkey = PEM_read_PUBKEY(pub_key_file, NULL, NULL, NULL);
  fclose(pub_key_file);

  if (!pubkey) {
    fprintf(stderr, "Error reading public key from %s\n", pub_key_path);
    ask_user();
  }

  return pubkey;
}

int main(int argc, char *argv[]) {
  signal(SIGINT, handle_sigint);

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

  FILE *filelist_file = fopen(FILELIST_PATH, "r");
  if (!filelist_file) {
    fprintf(stderr, "Error opening filelist %s: %s\n", FILELIST_PATH,
            strerror(errno));
    EVP_PKEY_free(pubkey);
    ask_user();
  }

  char line[512];
  while (fgets(line, sizeof(line), filelist_file)) {
    char num[256], path[256];
    if (sscanf(line, "%[^=]=%s", num, path) == 2) {
      char file_path[512], sig_path[512];

      snprintf(file_path, sizeof(file_path), "%s%s", ROOT_PATH, path);
      snprintf(sig_path, sizeof(sig_path), "%s%s.sig", VERIFY_DIR, num);

      printf("Verifying: %s\n", file_path);
      verify_signature(file_path, sig_path, pubkey);
    }
  }

  fclose(filelist_file);
  EVP_PKEY_free(pubkey);
  EVP_cleanup();
  ERR_free_strings();

  printf("Verification process completed successfully.\n");

  return 0;
}
