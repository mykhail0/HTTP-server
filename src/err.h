#ifndef ERR_H
#define ERR_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// Print info about unsuccessful system call and exit.
extern void syserr(const char* fmt, ...);

// Print error info and exit.
extern void fatal(const char* fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ERR_H */
