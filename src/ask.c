/*
   ask.c  --  This file is part of verify_some_rootfs_files_during_initramfs.

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

// This code is meant to be unchanged except some serious security issues.

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  char response[3];

  printf("Seems like some of your rootfs file is corrupt, do you want to "
         "continue? (y/n)\n");

start:
  if (fgets(response, sizeof(response), stdin) != NULL) {

    response[strcspn(response, "\n")] = '\0';

    if (strlen(response) > 1) {
      printf("Invalid choice, please input only one character (y or n).\n");
      while (getchar() != '\n') {
      }
      goto start;
    }

    if (response[0] == 'y' || response[0] == 'Y') {
      return 0;
    } else if (response[0] == 'n' || response[0] == 'N') {
      execl("/usr/bin/systemctl", "systemctl", "start", "emergency",
            (char *)NULL);
      perror("Failed to execute systemctl poweroff");
      return 1;
    } else {
      printf("Invalid choice, please input y or n.\n");
      goto start;
    }
  } else {
    printf("Failed to get input.\n");
    execl("/usr/bin/systemctl", "systemctl", "start", "emergency",
          (char *)NULL);
    perror("Failed to execute systemctl poweroff");
    return 3;
  }
  return 0;
}
