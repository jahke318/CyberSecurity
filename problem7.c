#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

pthread_mutex_t balance_mutex = PTHREAD_MUTEX_INITIALIZER;
static const int MAX_BALANCE = 2000000000;

int accountBalance = 1000;

void flag() {
  printf("The flag goes here");
}

// Withdraw an amount from the user's account
void *withdraw(void *arg) {
  unsigned short amount = *(unsigned short *)arg;
  pthread_mutex_lock(&balance_mutex);
  // Ensure the user has enough money to complete this transaction
  if (amount > accountBalance) {
    printf("Insufficient funds for withdrawal of $%hu\n", amount);
    pthread_mutex_unlock(&balance_mutex);
    return NULL;
  }
  // Subtraction seems dangerous... I'll implement my own awesome subtraction
  // method that must be safe!
  printf("Connecting to server to process withdrawal of $%hu...\n", amount);
  for (unsigned short i = 0; i < amount; i++) {
    --accountBalance;
    // This is not the vulnerability you are looking for... (seriously!)
    // It just makes it easier for you to trigger the vulnerability.
    if (i%1000 == 0) usleep(1);
  }
  pthread_mutex_unlock(&balance_mutex);
  return NULL;
}

// Deposit money into the user's account
void *deposit(void *arg) {
  unsigned short amount = *(unsigned short *)arg;
  pthread_mutex_lock(&balance_mutex);
  // Ensure that the deposit won't overflow the balance.
  if ((amount + accountBalance) > MAX_BALANCE) {
    printf("Accounts can at most have $%d. This deposit would put you over that limit!\n", MAX_BALANCE);
    pthread_mutex_unlock(&balance_mutex);
    return NULL;
  }
  // Addition also seems dangerous... I'll implement my own awesome addition
  // method that must be safe!
  printf("Connecting to server to process deposit of $%hu\n", amount);
  for (unsigned short i = 0; i < amount; i++) {
    ++accountBalance;
    if (i%1000 == 0) usleep(1);
  }
  pthread_mutex_unlock(&balance_mutex);
  return NULL;
}

// Give the user their options
void displayMenu() {
  printf("\n");
  printf("1. Withdraw money\n");
  printf("2. Deposit money\n");
  printf("3. Run queued transactions\n");
  printf("4. Show account balance\n");
  printf("5. Quit\n");
  printf("Notice: Withdrawals that are more than your current balance will not be completed.\n\n");
}

// Reads an unsigned short from stdin
unsigned short getUnsignedShortFromStdin(char *input, unsigned short min, unsigned short max, const char *promptOnFailure) {
  do {
    // If fgets fails, the user is done with the program
    if (!fgets(input, BUFSIZ - 1, stdin))
      exit(0);

    unsigned short value;
    if (!strstr(input, "-") && sscanf(input, "%hu", &value) == 1 &&
        value >= min && value <= max) {
      return value;
    }

    printf("%s", promptOnFailure);
  } while (true);
}

int main() {
  unsigned short numThreads = 0;
  pthread_t threads[1000];

  unsigned short numWithdrawals = 0;
  unsigned short withdrawals[1000];

  unsigned short numDeposits = 0;
  unsigned short deposits[1000];

  // Greet user
  printf("Hello, welcome to your Banking Application 2.0. (Now multi-threaded for your convenience!)\n");
  printf("You will queue transactions and then run them all at once.\n");
  printf("You currently have $%d in your account.\n", accountBalance);

  // Keep prompting for input until the user is done
  char input[BUFSIZ];
  unsigned short choiceValue;

  do {
    // Get option
    displayMenu();
    printf("Choose an option: ");
    choiceValue = getUnsignedShortFromStdin(input, 1, 5, "Invalid option. Please enter a valid option: ");

    switch (choiceValue) {
    // Withdrawal
    case 1:
      // Make sure we don't have too many withdrawals pending
      if (numWithdrawals >= 1000) {
        printf("Too many withdrawals pending.\n");
        printf("Please run them before making a new request.\n");
        break;
      }

      printf("How much would you like to withdraw (0-65,535)? ");
      withdrawals[numWithdrawals++] = getUnsignedShortFromStdin(input, 0, USHRT_MAX, "Invalid withdrawal amount. Please enter a valid amount (0-65,535): ");
      break;

    // Deposits
    case 2:
      // Make sure we don't have too many withdrawals pending
      if (numDeposits >= 1000) {
        printf("Too many deposits pending.\n");
        printf("Please run them before making a new request.\n");
        break;
      }

      printf("How much would you like to deposit (0-65,535)? ");
      deposits[numDeposits++] = getUnsignedShortFromStdin(input, 0, USHRT_MAX, "Invalid deposit amount. Please enter a valid amount (0-65,535): ");
      break;

    // Process deposits
    case 3:
      // Process deposits first so we have funds for withdrawals
      printf("Processing %hu deposits.\n", numDeposits);

      // Spawn threads
      for (unsigned short i = 0; i < numDeposits; i++) {
        pthread_create(&threads[numThreads], NULL, deposit, (void *)&deposits[i]);
        ++numThreads;
      }

      // Waits until each thread is done
      for (unsigned short i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
      }

      numDeposits = 0;
      numThreads = 0;

      // Next process the withdrawals
      printf("Processing %hu withdrawals.\n", numWithdrawals);

      for (unsigned short i = 0; i < numWithdrawals; i++) {
        pthread_create(&threads[numThreads], NULL, withdraw, (void *)&withdrawals[i]);
        ++numThreads;
      }
      for (unsigned short i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
      }

      numWithdrawals = 0;
      numThreads = 0;

      break;

    // Get balance
    case 4:
      pthread_mutex_lock(&balance_mutex);
      printf("Current balance: $%d\n", accountBalance);
      pthread_mutex_unlock(&balance_mutex);
      break;

    // Exit
    case 5:
      // Do nothing, as we will exit the loop when we are done.
      break;
    }
  } while (choiceValue != 5);

  pthread_mutex_lock(&balance_mutex);
  // If the user managed to overdraft, we need to fix that
  if (accountBalance < -1000) {
    flag();
  }
  pthread_mutex_unlock(&balance_mutex);

  return 0;
}
