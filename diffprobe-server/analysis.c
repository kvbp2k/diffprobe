#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;

typedef struct {
    char type;       
    void *pdata;
} Out_Param;

// following function reproduced from ezembed.c:
// Sriram Srinivasan, "Advanced Perl Programming",
// published by O'Reilly
int perl_call_va (char *subname, ...)
{
	char *p;
	char *str = NULL; int i = 0; double d = 0;
	int  nret = 0; /* number of return params expected*/
	//int  ax;
	int ii=0;
	Out_Param op[20];
	va_list vl;
	int out = 0;
	int result = 0;

	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(sp);
	va_start (vl, subname);

	/*printf ("Entering perl_call %s\n", subname);*/
	while ((p = va_arg(vl, char *))) {
		/*printf ("Type: %s\n", p);*/
		switch (*p)
		{
			case 's' :
				if (out) {
					op[nret].pdata = (void*) va_arg(vl, char *);
					op[nret++].type = 's';
				} else {
					str = va_arg(vl, char *);
					/*printf ("IN: String %s\n", str);*/
					ii = strlen(str);
					XPUSHs(sv_2mortal(newSVpv(str,ii)));
				}
				break;
			case 'i' :
				if (out) {
					op[nret].pdata = (void*) va_arg(vl, int *);
					op[nret++].type = 'i';
				} else {
					ii = va_arg(vl, int);
					/*printf ("IN: Int %d\n", ii);*/
					XPUSHs(sv_2mortal(newSViv(ii)));
				}
				break;
			case 'd' :
				if (out) {
					op[nret].pdata = (void*) va_arg(vl, double *);
					op[nret++].type = 'd';
				} else {
					d = va_arg(vl, double);
					/*printf ("IN: Double %f\n", d);*/
					XPUSHs(sv_2mortal(newSVnv(d)));
				}
				break;
			case 'O':
				out = 1;  /* Out parameters starting */
				break;
			default:
				fprintf (stderr, "perl_eval_va: Unknown option \'%c\'.\n"
						"Did you forget a trailing NULL ?\n", *p);
				return 0;
		}
	}

	va_end(vl);

	PUTBACK;
	result = perl_call_pv(subname, G_EVAL | ((nret == 0) ? G_DISCARD :
			(nret == 1) ? G_SCALAR  :
			G_ARRAY)  );



	SPAGAIN;
	/*printf ("nret: %d, result: %d\n", nret, result);*/
	if (nret > result)
		nret = result;

	for (i = --nret; i >= 0; i--) {
		switch (op[i].type) {
			case 's':
				str = POPp;
				/*printf ("String: %s\n", str);*/
				strcpy((char *)op[i].pdata, str);
				break;
			case 'i':
				ii = POPi;
				/*printf ("Int: %d\n", ii);*/
				*((int *)(op[i].pdata)) = ii;
				break;
			case 'd':
				d = POPn;
				/*printf ("Double: %f\n", d);*/
				*((double *) (op[i].pdata)) = d;
				break;
		}
	}

	FREETMPS ;
	LEAVE ;
	return result;
}

int initperl(char **env)
{
	int argcc = 0;
	char **argv = NULL;
	PERL_SYS_INIT3(&argcc, &argv, &env);
	my_perl = perl_alloc();

	return 0;
}

int endperl()
{
	perl_free(my_perl);
	PERL_SYS_TERM();

	return 0;
}

int delayrun(const char *filename, const char *probetype, const int probedir, 
		const int trial, const int p_port, const int a_port, char **env,
		double *p, int *h, int *diffresult, double *delaydiff)
{
	int ret = 0;
	char *args[] = { "", "delayrun.pl" };

	perl_construct(my_perl);

	perl_parse(my_perl, NULL, 2, args, NULL);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	/*** skipping perl_run() ***/
	ret = perl_call_va("delayrun", "s", filename, "s", probetype, "i", probedir, 
			"i", trial, "i", p_port, "i", a_port,
			"OUT", "d", p, "i", h, "i", diffresult, "d", delaydiff, NULL);
	if(ret <= 0)
	{
		fprintf(stderr, "delay analysis error.\n");
		return -1;
	}

	perl_destruct(my_perl);

	return 0;
}

int detectabilityrun(const char *filename, const int probedir, 
		const int trial, const int p_port, const int a_port, char **env,
		double *p, int *h, int *diffresult, double *delaydiff)
{
	int ret = 0;
	char *args[] = { "", "detectability.pl" };

	perl_construct(my_perl);

	perl_parse(my_perl, NULL, 2, args, NULL);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	/*** skipping perl_run() ***/
	ret = perl_call_va("detectiontest", "s", filename, "i", probedir, "i", trial,
			"i", p_port, "i", a_port,
			"OUT", "d", p, "i", h, "i", diffresult, "d", delaydiff, NULL);
	if(ret <= 0)
	{
		fprintf(stderr, "delay analysis error.\n");
		return -1;
	}

	perl_destruct(my_perl);

	return 0;
}

int lossrun(const char *filename, const char *probetype, const int probedir, 
		const int trial, const int p_port, const int a_port, char **env,
		double *p, int *h, int *retval, int *plost, int *ptotal, int *alost, int *atotal)
{
	int ret = 0;
	char *args[] = { "", "lossrun.pl" };

	perl_construct(my_perl);

	perl_parse(my_perl, NULL, 2, args, NULL);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	/*** skipping perl_run() ***/
	ret = perl_call_va("lossrun", "s", filename, "s", probetype, "i", probedir, 
			"i", trial, "i", p_port, "i", a_port,
			"OUT", "d", p, "i", h, "i", retval, 
			"i", plost, "i", ptotal, "i", alost, "i", atotal, NULL);
	if(ret <= 0)
	{
		fprintf(stderr, "loss analysis error.\n");
		return -1;
	}

	perl_destruct(my_perl);

	return 0;
}

int proportiontestrun(int plost, int ptotal, int alost, int atotal, 
			char **env, double *p, int *h, int *retval)
{
	int ret = 0;
	char *args[] = { "", "lossrun.pl" };

	perl_construct(my_perl);

	perl_parse(my_perl, NULL, 2, args, NULL);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	/*** skipping perl_run() ***/
	ret = perl_call_va("proportionrun", "i", plost, "i", ptotal, "i", alost, "i", atotal, 
			"OUT", "d", p, "i", h, "i", retval, NULL);
	if(ret <= 0)
	{
		fprintf(stderr, "loss analysis error.\n");
		return -1;
	}

	perl_destruct(my_perl);

	return 0;
}

int pairedlossrun(const char *filename, const char *sndfilename,
		const char *probetype, const int probedir, 
		const int trial, const int p_port, const int a_port, char **env,
		double *p, int *h, int *retval, 
		int *plost, int *ptotal, int *alost, int *atotal)
{
	int ret = 0;
	char *args[] = { "", "lossrun.pl" };

	perl_construct(my_perl);

	perl_parse(my_perl, NULL, 2, args, NULL);
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	/*** skipping perl_run() ***/
	ret = perl_call_va("pairedlossrun", "s", filename, "s", probetype, "i", probedir, 
			"i", trial, "i", p_port, "i", a_port, "s", sndfilename,
			"OUT", "d", p, "i", h, "i", retval, 
			"i", plost, "i", ptotal, "i", alost, "i", atotal, NULL);
	if(ret <= 0)
	{
		fprintf(stderr, "loss analysis error.\n");
		return -1;
	}

	perl_destruct(my_perl);

	return 0;
}

