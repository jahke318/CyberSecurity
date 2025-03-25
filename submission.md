# Start Here

`Name`: Jake Miller
`NetID`: jmill291

For each problem below, you will,

1. Fill in the the flag
2. List the steps necessary to exploit the binary. *(May be a single line.)*
3. Provide a patch that fixes the exploit. *(Generated using `make diff`.)*
4. An explanation of what the vulnerability was and how the patch fixes it. *(Keep this explanation short and to the point.)*

---

## problem1

### Flag
flag{366-iNt3G3r5iGNc0nV3r5i0N}

### Exploit Steps
1. When You run the program and it asks for how much money you want to withdraw make the number a negative number over 1000000
2. This will trick the program into putting a million in your account which will return the flag

### Patch
```diff
--- .originals/problem1.c	2025-03-08 01:49:17.000000000 +0000
+++ problem1.c	2025-03-10 00:54:41.623702400 +0000
@@ -32,7 +32,7 @@
 
 // Check to make sure the user has enough money to process the withdrawal
 int check_withdraw_amount(int amount, struct user_account *u) {
-  return amount < get_account_balance(u);
+  return amount > get_account_balance(u);
 }
 
 // Process a withdrawal

```

### Explanation
The code is vulnerable because based on the greater than or less than statement that compares amount to account balance if you put a negative number
instead of taking that money from you it gives you money that you do not have 

---

## problem2

### Flag
FLAG_GOES_HERE

### Exploit Steps
1. Notice the input is unbounded
2. write command line input that goes outside of the input range 
3. trigger flag

### Patch
```diff
--- .originals/problem2.c	2025-03-08 01:49:17.000000000 +0000
+++ problem2.c	2025-03-10 19:11:18.764081400 +0000
@@ -10,7 +10,7 @@
   char out[32];
 
   memset(out, 0, sizeof(out));
-  strcpy(out, input);
+  strncpy(out, input, sizeof(out) - 1);
 
   // Copy the user's input and print it out.
   printf("user:   %s\n", input);
```

### Explanation
The code is vulnerable because it allows us to go outside of the input size because it is unbounded, which in return lets us call the flag. To fix this we just need to make sure the input has a max size 

---

## problem3

### Flag
flag{366-BufFeR0v3rf10W_C4n4ry}

### Exploit Steps
1. We see that strcpy and password buffer have no bounds check. This means that we can overflow into secret
2. We do this by creating an input that overwrites secret so that it matches the shifted version of password buffer
3. This passes the check and returns the flag
4. ./problem3 "$(echo -n "xxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyy")"


### Patch
```diff
--- .originals/problem3.c	2025-03-08 01:49:17.000000000 +0000
+++ problem3.c	2025-03-10 01:37:55.261287700 +0000
@@ -16,7 +16,8 @@
 
   // Check that the passwords match. We're using my super special comparison function that
   // shifts password characters over by 1... throws off the hackers!
-  strcpy(passwordBuffer, input);
+  strncpy(passwordBuffer, input, sizeof(passwordBuffer) - 1);
+  passwordBuffer[sizeof(passwordBuffer) - 1] = '\0';
 
   for (size_t i = 0; i < sizeof(passwordBuffer); i++) {
     passwordBuffer[i]++;
```

### Explanation
For this patch we just need to make sure that no matter how long the user input string is that only 15 bytes are copied to the buffer so we do not have overflow.

---

## problem4

### Flag
FLAG_GOES_HERE
I think I accidentally overwrote the original file for the remaining problems and I have tried everything to get the original files to work properly but it does not work. So for some of these problem I do not have the flags 

### Exploit Steps
1. For this problem we have another overflow style problem
2. The code sees if both the value and the factor are positive integers and then multiplies the 2
3. if the multiplication overflows on the int we are able to wrap around into negative numbers 
4. We need to find 2 numbers that we can multiply together to overflow and get -504
5. I chose 2 as my value and 2147483396 as my multiple because when we multiply these 2 we get a slight overflow from the range of an int and we get -504

### Patch
```diff
--- .originals/problem4.c	2025-03-08 01:49:17.000000000 +0000
+++ problem4.c	2025-03-10 02:17:18.159325000 +0000
@@ -31,6 +31,13 @@
     return -1;
   }
 
+
+  #define MY_INT_MAX 2147483647
+  if (value != 0 && factor > MY_INT_MAX / value) {
+    return -1;
+  }
+
+
   result = value * factor;
 
   if (result == reset_key) {

```

### Explanation
This code is vulnerable because of the way that integers deal with large numbers. If a number is larger than the int limit then it is possible for it to wrap around and become negative and that is what happens in this problem. We find 2 positive numbers that allow us to get -504 which normally would be impossible and that is where the vulnerability lies. To fix this we just set a max number that we can use for multiplication so that wrapping around does not happen

## problem5

### Flag
FLAG_GOES_HERE

### Exploit Steps
1. Make a bash script that is able to see that the file that the program is looking for does not exist 
2. then we create said file with the bash script
3. then the program wakes up and calls fopen and we get the flag

### Patch
```diff
--- .originals/problem5.c	2025-03-08 01:49:17.000000000 +0000
+++ problem5.c	2025-03-10 02:47:59.362328700 +0000
@@ -21,13 +21,12 @@
     // Ok, let's open this file and write the flag to it.
     // Haha... just kidding, the user doesn't have access to the file, so this call will fail.
     FILE *outFile = fopen(destinationFile, "r");
-    if (outFile == NULL) {
-      printf("This is my file... I told you that you couldn't access it. Neener-neener!\n");
-      // If the file did exist, we would write to it here.
+    if (outFile != NULL) {
+      fclose(outFile);
+      printf("Hey, you shouldn't have access to my file... What are you trying to pull? Go away!\n");
     } else {
-      // Wait, how can the file both be not accessible and accessible?
-      // Is this the fabled Schrödinger's file?!? Here, have my flag and go away!
       flag();
     }
+    
   } 
 }
```

### Explanation
This code is vulnerable because the code allows for a window for us to modify the file that the program is looking for which allows us to get the flag

---

## problem6

### Flag
FLAG_GOES_HERE

### Exploit Steps
1. Since the program allows for an infinite amount of guesses we can use brute force to guess all possible combinations
2. We write a simple program that is able to guess all of the possible 3 character combinations and then we eventually get the password
   

### Patch
```diff
--- .originals/problem6.c	2025-03-08 01:49:17.000000000 +0000
+++ problem6.c	2025-03-10 18:52:43.078398800 +0000
@@ -9,11 +9,11 @@
 }
 
 int main() {
-  char password[4];
+  char password[4] = {0};
   memset(password, (char)0, sizeof(password));
 
-  char input[4];
-  unsigned int remainingGuesses;
+  char input[4] = {0};
+  int remainingGuesses = 5;
 
   // Generate a random string of 3 lowercase letters
   srand((unsigned int)time(NULL));
@@ -36,9 +36,10 @@
     if (remainingGuesses > 0) {
       if (strncmp(password, input, sizeof(password)) == 0) {
         // Guessed the password
-        flag(0);
+        flag();
         return 0;
       } else {
+        --remainingGuesses;
         printf("Incorrect guess. ");
       }
     } else {
@@ -49,7 +50,7 @@
       }
     }
 
-    --remainingGuesses;
+    
     printf("%d guesses remaining.\n", remainingGuesses);
   } while (true);
 }

```

### Explanation
This program is vulnerable because it allows for infinite guesses which is we try every possible combo we will eventually get the password and return the flag
to prevent this we have to limit the number of guesses to be 5 and not allow that number to go past 0.

---

## problem7

### Flag
FLAG_GOES_HERE

### Exploit Steps
1. To exploit thi program we can see that because the inputs are not synced in any way that it is possible for us to que up several withdrawl requests before the program is able to check if we have enough money
2. this allows us to reach the negative account balance that would que the flag

### Patch
```diff
--- .originals/problem7.c	2025-03-08 01:49:17.000000000 +0000
+++ problem7.c	2025-03-10 19:05:40.194349200 +0000
@@ -6,6 +6,7 @@
 #include <string.h>
 #include <unistd.h>
 
+pthread_mutex_t balance_mutex = PTHREAD_MUTEX_INITIALIZER;
 static const int MAX_BALANCE = 2000000000;
 
 int accountBalance = 1000;
@@ -17,44 +18,44 @@
 // Withdraw an amount from the user's account
 void *withdraw(void *arg) {
   unsigned short amount = *(unsigned short *)arg;
-
+  pthread_mutex_lock(&balance_mutex);
   // Ensure the user has enough money to complete this transaction
   if (amount > accountBalance) {
     printf("Insufficient funds for withdrawal of $%hu\n", amount);
+    pthread_mutex_unlock(&balance_mutex);
     return NULL;
   }
-
   // Subtraction seems dangerous... I'll implement my own awesome subtraction
   // method that must be safe!
   printf("Connecting to server to process withdrawal of $%hu...\n", amount);
   for (unsigned short i = 0; i < amount; i++) {
     --accountBalance;
-
     // This is not the vulnerability you are looking for... (seriously!)
     // It just makes it easier for you to trigger the vulnerability.
     if (i%1000 == 0) usleep(1);
   }
+  pthread_mutex_unlock(&balance_mutex);
   return NULL;
 }
 
 // Deposit money into the user's account
 void *deposit(void *arg) {
   unsigned short amount = *(unsigned short *)arg;
-
+  pthread_mutex_lock(&balance_mutex);
   // Ensure that the deposit won't overflow the balance.
   if ((amount + accountBalance) > MAX_BALANCE) {
     printf("Accounts can at most have $%d. This deposit would put you over that limit!\n", MAX_BALANCE);
+    pthread_mutex_unlock(&balance_mutex);
     return NULL;
   }
-
   // Addition also seems dangerous... I'll implement my own awesome addition
   // method that must be safe!
   printf("Connecting to server to process deposit of $%hu\n", amount);
   for (unsigned short i = 0; i < amount; i++) {
     ++accountBalance;
-
     if (i%1000 == 0) usleep(1);
   }
+  pthread_mutex_unlock(&balance_mutex);
   return NULL;
 }
 
@@ -175,7 +176,9 @@
 
     // Get balance
     case 4:
+      pthread_mutex_lock(&balance_mutex);
       printf("Current balance: $%d\n", accountBalance);
+      pthread_mutex_unlock(&balance_mutex);
       break;
 
     // Exit
@@ -185,8 +188,12 @@
     }
   } while (choiceValue != 5);
 
+  pthread_mutex_lock(&balance_mutex);
   // If the user managed to overdraft, we need to fix that
   if (accountBalance < -1000) {
     flag();
   }
-}
\ No newline at end of file
+  pthread_mutex_unlock(&balance_mutex);
+
+  return 0;
+}

```

### Explanation
The code is vulnerable because it allows us to que up a bunch of withdraw checks before its able to see if we actually have enough money to take out. This lets us trigger the flag

---



