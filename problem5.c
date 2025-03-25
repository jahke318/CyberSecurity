#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

void flag() {
  printf("The flag goes here");
}

int main() {
  // Get the name of a tempfile we can use. It won't exist yet.
  char destinationFile[1024];
  snprintf(destinationFile, sizeof(destinationFile) - 1, "/tmp/%d", getpid());

  if (access(destinationFile, F_OK) == 0) {
    printf("Hey, you shouldn't have access to my file... What are you trying to pull? Go away!\n");
  } else {
    // I'm tired. Checking access is hard work... I need some sleep. 0.1 seconds should do it.
    // This is not the vulnerability you are looking for... (seriously!)
    usleep(100000);

    // Ok, let's open this file and write the flag to it.
    // Haha... just kidding, the user doesn't have access to the file, so this call will fail.
    FILE *outFile = fopen(destinationFile, "r");
    if (outFile == NULL) {
      printf("This is my file... I told you that you couldn't access it. Neener-neener!\n");
      // If the file did exist, we would write to it here.
    } else {
      // Wait, how can the file both be not accessible and accessible?
      // Is this the fabled Schrödinger's file?!? Here, have my flag and go away!
      flag();
    }
  }
}