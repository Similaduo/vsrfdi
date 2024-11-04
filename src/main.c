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
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PUB_KEY_PATH "/etc/vsrfdi/pub.asc"
#define FILELIST_PATH "/sysroot/etc/vsrfdi/filelist"
#define FILELIST_SIG_PATH "/sysroot/var/lib/vsrfdi/filelist.sig"
#define ROOT_PATH "/sysroot"
#define VERIFY_DIR "/sysroot/var/lib/vsrfdi/signatures/"

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

void verify_signature(gpgme_ctx_t ctx, const char *file_path,
                      const char *sig_path) {
  char *content;
  size_t size;
  read_file(file_path, &content, &size);

  gpgme_data_t data, sig;
  if (gpgme_data_new_from_mem(&data, content, size, 0) != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Error creating data buffer from memory\n");
    free(content);
    exit(1);
  }
  if (gpgme_data_new_from_file(&sig, sig_path, 1) != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Error reading signature file %s\n", sig_path);
    gpgme_data_release(data);
    free(content);
    exit(1);
  }

  gpgme_op_verify(ctx, sig, data, NULL);
  gpgme_verify_result_t result = gpgme_op_verify_result(ctx);

  if (!result || !result->signatures ||
      result->signatures->status != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Signature verification failed for %s\n", file_path);
    gpgme_data_release(data);
    gpgme_data_release(sig);
    free(content);
    exit(1);
  }

  gpgme_data_release(data);
  gpgme_data_release(sig);
  free(content);
}

void import_public_key(gpgme_ctx_t ctx, const char *pub_key_path) {
  gpgme_data_t key_data;
  if (gpgme_data_new_from_file(&key_data, pub_key_path, 1) !=
      GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Error reading public key file %s\n", pub_key_path);
    exit(1);
  }

  gpgme_op_import(ctx, key_data);
  gpgme_import_result_t import_result = gpgme_op_import_result(ctx);

  if (!import_result || !import_result->imports ||
      import_result->imports->status != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Failed to import public key from %s\n", pub_key_path);
    gpgme_data_release(key_data);
    exit(1);
  }

  gpgme_data_release(key_data);
}

int main(void) {
  if (!gpgme_check_version(NULL)) {
    fprintf(stderr, "Error initializing GPGME\n");
    return 1;
  }

  gpgme_ctx_t ctx;
  if (gpgme_new(&ctx) != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Error creating GPGME context\n");
    return 1;
  }

  import_public_key(ctx, PUB_KEY_PATH);

  verify_signature(ctx, FILELIST_PATH, FILELIST_SIG_PATH);

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

      printf("Verifing for: %s\n", file_path);
      // printf("Reading signature file: %s\n", sig_path);

      verify_signature(ctx, file_path, sig_path);
    }
    entry = strtok(NULL, "\n");
  }

  free(filelist_content);
  gpgme_release(ctx);

  printf("Verification process completed successfully.\n");

  return 0;
}
