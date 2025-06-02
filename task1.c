#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

#define MAX_MESSAGE_LEN 256
#define INITIAL_REMINDERS_CAPACITY 4
#define TIMER_SIGNAL SIGRTMIN

// Структура для нагадування
typedef struct {
    timer_t timer_id;
    char message[MAX_MESSAGE_LEN];
    struct timespec interval;
    int reminder_uid;
    int is_active;
} Reminder;

// Структура для повідомлення через pipe
typedef struct {
    int reminder_uid;
} ReminderPipeMessage;

int reminder_pipe_fd[2];
Reminder *reminders_list = NULL;
size_t reminders_count = 0;
size_t reminders_capacity = 0;
int next_reminder_uid = 1;

volatile sig_atomic_t shutdown_requested_flag = 0;

// Обробник сигналів таймера
static void timer_event_signal_handler(int signum, siginfo_t *siginfo, void *context) {
    (void)signum;
    (void)context;

    ReminderPipeMessage msg;
    msg.reminder_uid = (int)(intptr_t)siginfo->si_value.sival_ptr;

    write(reminder_pipe_fd[1], &msg, sizeof(ReminderPipeMessage));
}

// Обробник SIGINT (Ctrl+C)
static void sigint_shutdown_handler(int signum) {
    (void)signum;
    char shutdown_msg[] = "\nREMINDER_SYS: Отримано SIGINT, починаю завершення...\n";
    write(STDOUT_FILENO, shutdown_msg, sizeof(shutdown_msg) - 1);
    shutdown_requested_flag = 1;

    // Запис у pipe, щоб розбудити select(), якщо він чекає
    char dummy_char = '!';
    write(reminder_pipe_fd[1], &dummy_char, 1);
}

// Функції для керування списком нагадувань
int add_reminder_to_list(timer_t timer_id, const char *message, long first_delay_sec, long interval_sec) {
    if (reminders_count >= reminders_capacity) {
        reminders_capacity = (reminders_capacity == 0) ? INITIAL_REMINDERS_CAPACITY : reminders_capacity * 2;
        Reminder *new_list = realloc(reminders_list, reminders_capacity * sizeof(Reminder));
        if (!new_list) {
            perror("Неможливо розширити пам'ять для списку нагадувань");
            return -1;
        }
        reminders_list = new_list;
    }

    Reminder *new_reminder = &reminders_list[reminders_count];
    new_reminder->timer_id = timer_id;
    strncpy(new_reminder->message, message, MAX_MESSAGE_LEN - 1);
    new_reminder->message[MAX_MESSAGE_LEN - 1] = '\0';
    new_reminder->reminder_uid = next_reminder_uid++;
    new_reminder->is_active = 1;

    new_reminder->interval.tv_sec = interval_sec;
    new_reminder->interval.tv_nsec = 0;

    reminders_count++;
    return new_reminder->reminder_uid;
}

// Основна логіка
int main() {
    struct sigaction sa_timer, sa_int_handler;
    fd_set read_fds;
    char user_input_buffer[512];

    printf("Система Нагадувань (PID: %d) запущена.\n", getpid());
    printf("Введіть 'add <затримка_сек> <інтервал_сек> <повідомлення>' для додавання нагадування (<інтервал_сек> = 0 для одноразового нагадування)\n");
    printf("Введіть 'exit' або натисніть Ctrl+C для виходу.\n");

    // Ініціалізація self-pipe
    if (pipe(reminder_pipe_fd) == -1) {
        perror("Неможливо створити self-pipe");
        exit(EXIT_FAILURE);
    }
    if (fcntl(reminder_pipe_fd[0], F_SETFL, O_NONBLOCK) == -1 ||
        fcntl(reminder_pipe_fd[1], F_SETFL, O_NONBLOCK) == -1) {
        perror("Неможливо встановити неблокуючий режим для pipe");
        close(reminder_pipe_fd[0]); close(reminder_pipe_fd[1]);
        exit(EXIT_FAILURE);
    }

    // Встановлення обробника сигналів таймера
    sa_timer.sa_flags = SA_SIGINFO | SA_RESTART;
    sa_timer.sa_sigaction = timer_event_signal_handler;
    sigemptyset(&sa_timer.sa_mask);
    if (sigaction(TIMER_SIGNAL, &sa_timer, NULL) == -1) {
        perror("Неможливо встановити обробник для TIMER_SIGNAL");
        exit(EXIT_FAILURE);
    }

    // Встановлення обробника SIGINT
    sa_int_handler.sa_handler = sigint_shutdown_handler;
    sigemptyset(&sa_int_handler.sa_mask);
    sa_int_handler.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa_int_handler, NULL) == -1) {
        perror("Неможливо встановити обробник SIGINT");
        exit(EXIT_FAILURE);
    }

    // Основний цикл програми
    while (!shutdown_requested_flag) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds); // Моніторимо стандартний ввід
        FD_SET(reminder_pipe_fd[0], &read_fds); // Моніторимо self-pipe

        printf(">");
        fflush(stdout);

        int max_fd = (STDIN_FILENO > reminder_pipe_fd[0]) ? STDIN_FILENO : reminder_pipe_fd[0];
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL); // Блокуючий select

        if (shutdown_requested_flag) break;

        if (activity < 0) {
            if (errno == EINTR) continue;
            perror("Помилка select");
            break;
        }

        // Обробка події з self-pipe (спрацював таймер)
        if (FD_ISSET(reminder_pipe_fd[0], &read_fds)) {
            ReminderPipeMessage pipe_msg;
            ssize_t bytes_read = read(reminder_pipe_fd[0], &pipe_msg, sizeof(pipe_msg));

            if (bytes_read > 0) {
                if (bytes_read == 1 && ((char*)&pipe_msg)[0] == '!') {
                    // Це байт від sigint_handler для пробудження select
                }
                else if (bytes_read == sizeof(ReminderPipeMessage)) {
                    int found_idx = -1;
                    for (size_t i = 0; i < reminders_count; i++) {
                        if (reminders_list[i].reminder_uid == pipe_msg.reminder_uid && reminders_list[i].is_active) {
                            found_idx = i;
                            break;
                        }
                    }

                    if (found_idx != -1) {
                        time_t now_t = time(NULL);
                        struct tm *tm_info = localtime(&now_t);
                        char time_str[30];
                        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                        
                        printf("\n[%s] НАГАДУВАННЯ (ID %d): %s\n",
                               time_str, reminders_list[found_idx].reminder_uid, reminders_list[found_idx].message);

                        // Якщо нагадування одноразове, деактивуємо його та видаляємо таймер
                        if (reminders_list[found_idx].interval.tv_sec == 0 && reminders_list[found_idx].interval.tv_nsec == 0) {
                            printf("(Одноразове нагадування ID %d виконано.)\n", reminders_list[found_idx].reminder_uid);
                            timer_delete(reminders_list[found_idx].timer_id);
                            reminders_list[found_idx].is_active = 0;
                        }
                    }
                }
            }
            else if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("Помилка читання з pipe"); break;
            }
        }

        // Обробка вводу користувача
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(user_input_buffer, sizeof(user_input_buffer), stdin) == NULL) {
                printf("\nREMINDER_SYS: Отримано EOF, завершую роботу...\n");
                shutdown_requested_flag = 1;
                continue;
            }
            user_input_buffer[strcspn(user_input_buffer, "\n")] = 0;

            if (strcmp(user_input_buffer, "exit") == 0 || strcmp(user_input_buffer, "quit") == 0) {
                shutdown_requested_flag = 1;
                continue;
            }
            else if (strncmp(user_input_buffer, "add ", 4) == 0) {
                long delay_sec, interval_sec;
                char message_buf[MAX_MESSAGE_LEN] = {0};

                if (sscanf(user_input_buffer + 4, "%ld %ld %255[^\n]", &delay_sec, &interval_sec, message_buf) >= 2) {
                    if(strlen(message_buf) == 0 && sscanf(user_input_buffer + 4, "%ld %ld", &delay_sec, &interval_sec) == 2){
                        snprintf(message_buf, MAX_MESSAGE_LEN, "Стандартне нагадування");
                    }


                    if (delay_sec < 0 || interval_sec < 0) {
                        printf("REMINDER_SYS: Затримка та інтервал не можуть бути від'ємними.\n");
                        continue;
                    }

                    timer_t new_timerid;
                    struct sigevent sev = {0};
                    struct itimerspec its = {0};
                    int new_reminder_uid = next_reminder_uid;

                    sev.sigev_notify = SIGEV_SIGNAL;
                    sev.sigev_signo = TIMER_SIGNAL;
                    sev.sigev_value.sival_ptr = (void*)(intptr_t)new_reminder_uid;

                    if (timer_create(CLOCK_REALTIME, &sev, &new_timerid) == -1) {
                        perror("Неможливо створити таймер");
                        continue;
                    }

                    its.it_value.tv_sec = delay_sec;
                    its.it_value.tv_nsec = 0;
                    its.it_interval.tv_sec = interval_sec; // Інтервал повторення (0 для одноразового)
                    its.it_interval.tv_nsec = 0;

                    if (timer_settime(new_timerid, 0, &its, NULL) == -1) {
                        perror("Неможливо встановити час таймера");
                        timer_delete(new_timerid); // Очистка, якщо не вдалося встановити
                        continue;
                    }

                    if (add_reminder_to_list(new_timerid, message_buf, delay_sec, interval_sec) != -1) {
                        printf("REMINDER_SYS: Нагадування ID %d додано: '%s' через %ldс, повтор кожні %ldс.\n",
                               new_reminder_uid, message_buf, delay_sec, interval_sec);
                    }
                    else {
                         timer_delete(new_timerid); // Якщо не вдалося додати до списку
                    }

                }
                else {
                    printf("REMINDER_SYS: Неправильний формат команди 'add'. Очікується: add <затримка_с> <інтервал_с> <повідомлення>\n");
                }
            }
            else if (strlen(user_input_buffer) > 0) {
                printf("REMINDER_SYS: Невідома команда: %s\n", user_input_buffer);
            }
        }
    }

    // Завершення роботи та очищення ресурсів
    printf("REMINDER_SYS: Починаю процедуру завершення...\n");
    for (size_t i = 0; i < reminders_count; i++) {
        if (reminders_list[i].is_active) { // Видаляємо тільки активні таймери
            printf("Видаляю таймер для нагадування ID %d...\n", reminders_list[i].reminder_uid);
            timer_delete(reminders_list[i].timer_id);
        }
    }
    free(reminders_list);
    close(reminder_pipe_fd[0]);
    close(reminder_pipe_fd[1]);
    printf("REMINDER_SYS: Програму завершено.\n");

    return 0;
}
