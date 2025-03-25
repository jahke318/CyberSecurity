#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void flag() {
  printf("The flag goes here");
}

// Check the password
bool checkPassword(char *input) __attribute__((stack_protect));
bool checkPassword(char *input) {
  char passwordBuffer[16];
  char secret[16];
 
  // Set the secret value. Hidden from prying eyes...

  // Check that the passwords match. We're using my super special comparison function that
  // shifts password characters over by 1... throws off the hackers!
  strcpy(passwordBuffer, input);

  for (size_t i = 0; i < sizeof(passwordBuffer); i++) {
    passwordBuffer[i]++;
  }

  for (size_t i = 0; i < sizeof(secret); i++) {
    if (secret[i] != passwordBuffer[i]) {
      printf("Access denied!\n");
      return false;
    }
  }

  return true;
}

int main(int argc, char **argv) {
  // Basic command line argument checking
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <password>\n", argv[0]);
    return 0;
  }

  if (checkPassword(argv[1])) {
    flag();
  }
}
