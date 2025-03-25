#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void flag() {
  printf("The flag goes here");
}

int main() {
  char password[4] = {0};
  memset(password, (char)0, sizeof(password));

  char input[4] = {0};
  int remainingGuesses = 5;

  // Generate a random string of 3 lowercase letters
  srand((unsigned int)time(NULL));
  for (int i = 0; i < 3; i++) {
    password[i] = (char)'a' + (rand() % 26);
  }

  // Set the number of guesses the user can take
  remainingGuesses = 5;

  printf("We have chosen a random string of lowercase letters for you to guess.\n");
  printf("You have %d guesses, good luck!\n", remainingGuesses);

  do {
    printf("Guess: ");
    if (scanf("%3s", input) != 1) {
      break;
    }

    if (remainingGuesses > 0) {
      if (strncmp(password, input, sizeof(password)) == 0) {
        // Guessed the password
        flag();
        return 0;
      } else {
        --remainingGuesses;
        printf("Incorrect guess. ");
      }
    } else {
      printf("You've run out of guesses! Please quit by pressing 'q': ");
      scanf("%1s", input);
      if (strstr(input, "q")) {
        break;
      }
    }

    
    printf("%d guesses remaining.\n", remainingGuesses);
  } while (true);
}
