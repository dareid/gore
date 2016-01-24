package sexp

type expressionType int

const (
	xtNull         expressionType = 0  /* P data: [0] */
	xtInt          expressionType = 1  /* P data: [4]int */
	xtString       expressionType = 3  /* P data: [n]char null-term. strg. */
	xtLang         expressionType = 4  /* - */
	xtS4           expressionType = 7  /* P data: [0] */
	xtVector       expressionType = 16 /* P data: [?]REXP,REXP,.. */
	xtClos         expressionType = 18 /* P X formals, X body  (closure; since 0.1-5) */
	xtSymName      expressionType = 19 /* s same as xtStr (since 0.5) */
	xtListNoTag    expressionType = 20 /* s same as xtVector (since 0.5) */
	xtListTag      expressionType = 21 /* P X tag, X val, Y tag, Y val, ... (since 0.5) */
	xtLangNoTag    expressionType = 22 /* s same as xtListNoTag (since 0.5) */
	xtLangTag      expressionType = 23 /* s same as xtListTag (since 0.5) */
	xtExpVector    expressionType = 26 /* s same as xtVector (since 0.5) */
	xtIntArray     expressionType = 32 /* P data: [n*4]int,int,.. */
	xtDoubleArray  expressionType = 33 /* P data: [n*8]double,double,.. */
	xtStringArray  expressionType = 34 /* P data: string,string,.. (string=byte,byte,...,0) padded with '\01' */
	xtBoolArray    expressionType = 36 /* P data: int(n),byte,byte,... */
	xtRaw          expressionType = 37 /* P data: int(n),byte,byte,... */
	xtComplexArray expressionType = 38 /* P data: [n*16]double,double,... (Re,Im,Re,Im,...) */
	xtUnknown      expressionType = 48 /* P data: [4]int - SEXP type (as from TYPEOF(x)) */
)
