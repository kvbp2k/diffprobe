#ifndef _ANALYSIS_H_
#define _ANALYSIS_H_

int initperl(char **env);
int endperl();

int delayrun(const char *filename, const char *probetype, const int probedir, 
		const int trial, const int p_port, const int a_port, char **env,
		double *p, int *h, int *diffresult, double *delaydiff);

int detectabilityrun(const char *filename, const int probedir, 
		const int trial, const int p_port, const int a_port, char **env,
		double *p, int *h, int *diffresult, double *delaydiff);

int lossrun(const char *filename, const char *probetype, const int probedir, 
		const int trial, const int p_port, const int a_port, char **env,
		double *p, int *h, int *retval, int *plost, int *ptotal, int *alost, int *atotal);

int proportiontestrun(int plost, int ptotal, int alost, int atotal, 
			char **env, double *p, int *h, int *retval);

int pairedlossrun(const char *filename, const char *sndfilename,
		const char *probetype, const int probedir, 
		const int trial, const int p_port, const int a_port, char **env,
		double *p, int *h, int *retval, 
		int *plost, int *ptotal, int *alost, int *atotal);

#endif

