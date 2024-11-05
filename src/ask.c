#include <stdio.h>
#include <string.h>

int main(void) {
  char response[3];

  printf("Seems like some of you rootfs file is corrupt, do you want to "
         "continue? (y/n)\n");

  if (fgets(response, sizeof(response), stdin) != NULL) {
    response[strcspn(response, "\n")] = '\0';

    if (response[0] == 'y' || response[0] == 'Y') {
      return 0;
    } else if (response[0] == 'n' || response[0] == 'N') {
      return 1;
    } else {
      printf("Invalid choice, please input y or n.\n");
      return 2;
    }
  } else {
    printf("Failed to get input.\n");
    return 3;
  }
}
