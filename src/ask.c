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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void handle_sigint(int sig) {}

int main(void) {

  signal(SIGINT, handle_sigint);

  char response[3];

  printf("Seems like some of your rootfs file is corrupt, do you want to "
         "continue?\nNOTE: "
         "If you choose n, you will enter the emergency shell. However, the "
         "emergency shell "
         "might be locked and unavailable.\nAlso, if you think the "
         "reason for the "
         "corruption of some rootfs file is due to some security issues, \n"
         "you should boot via the bootable usb drive to have a check "
         "rather than typing y "
         "to boot from the real "
         "rootfs on your initial hard drive.\nNow typing your choice (y/n):\n");

start:
  if (fgets(response, sizeof(response), stdin) != NULL) {

    response[strcspn(response, "\n")] = '\0';

    if (strlen(response) > 1) {
      printf("Invalid choice, please input only one character (y or n).\nNOTE: "
             "If you choose n, you will enter the emergency shell. However, "
             "the emergency shell "
             "might be locked and unavailable.\nAlso, if you think the "
             "reason for the "
             "corruption of some rootfs file is due to some security issues, \n"
             "you should boot via the bootable usb drive to have a check "
             "rather than typing y "
             "to boot from the real "
             "rootfs on your initial hard drive.\nNow typing your choice "
             "(y/n):\n");
      while (getchar() != '\n') {
      }
      goto start;
    }

    if (response[0] == 'y' || response[0] == 'Y') {
      return 0;
    } else if (response[0] == 'n' || response[0] == 'N') {
      exit(1);
    } else {
      printf("Invalid choice, please input y or n.\nNOTE: "
             "If you choose n, you will enter the emergency shell. However, "
             "the emergency shell "
             "might be locked and unavailable.\nAlso, if you think the "
             "reason for the "
             "corruption of some rootfs file is due to some security issues, \n"
             "you should boot via the bootable usb drive to have a check "
             "rather than typing y "
             "to boot from the real "
             "rootfs on your initial hard drive.\nNow typing your choice "
             "(y/n):\n");
      goto start;
    }
  } else {
    printf("Failed to get input.\n");
    exit(1);
  }
  return 0;
}
