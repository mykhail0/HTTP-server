#ifndef ERR_H
#define ERR_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// Prints info about unsuccessful system call and exits.
extern void syserr(const char *fmt, ...);

// Prints error info and exits.
extern void fatal(const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ERR_H */
