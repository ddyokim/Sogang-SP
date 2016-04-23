#ifndef _20141505_H
#define _20141505_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#define STR_MAX 1000
#define DUMP_SIZE 1048576
#define TABLE_SIZE 20
#define CMD_CNT 17
#define ADDR_MAX 1048575
#define HEX_MAX 255

#define INVALID_CMD 0
#define CORRECT_CMD 1
#define INVALID_RANGE 2
#define EXECPTION 3

typedef struct _HIST{
    struct _HIST *next;
    char cmd[STR_MAX+1];
} HIST;
typedef struct _OPCODE{
    struct _OPCODE *next;
    char mnemonic[STR_MAX+1];
    char format[STR_MAX+1];
    int opcode;
}OPCODE;
typedef struct _SYMBOL {
    struct _SYMBOL *next;
    char label[STR_MAX+1];
    int locctr;
} SYMBOL;
typedef struct _EXSYM {
    struct _EXSYM *next;
    char label[STR_MAX+1];
    int address;
    int length;
} EXSYM;
typedef struct _BP {
    struct _BP *next;
    int address;
} BP;
BP *bp_head=NULL, *bp_now=NULL;
HIST *front=NULL, *rear=NULL;
OPCODE *table[TABLE_SIZE];
SYMBOL *symtab[TABLE_SIZE];
EXSYM *estab[TABLE_SIZE];
BP* mkbp(int address) {
    BP* newnode = (BP*)malloc(sizeof(BP));
    newnode->next = NULL;
    newnode->address = address;
    return newnode;
}
EXSYM* mkexsym(int address, int length, char *label) {
    EXSYM* newnode = (EXSYM*)malloc(sizeof(EXSYM));
    newnode->next = NULL;
    newnode->address = address;
    newnode->length = length;
    strncpy(newnode->label,label,STR_MAX+1);
    return newnode;
}
SYMBOL* mksym(int locctr, char *label) {
    SYMBOL* newnode = (SYMBOL*)malloc(sizeof(SYMBOL));
    newnode->next = NULL;
    newnode->locctr = locctr;
    strncpy(newnode->label,label,STR_MAX+1);
    return newnode;
}
OPCODE* mkopc(int opc, char *mnemonic, char *format) {
    OPCODE* newnode = (OPCODE*)malloc(sizeof(OPCODE));
    newnode->next = NULL;
    newnode->opcode = opc;
    strncpy(newnode->mnemonic,mnemonic,STR_MAX+1);
    strncpy(newnode->format,format,STR_MAX+1);
    return newnode;
}
void mkhis(char *str) {
    HIST* newnode = (HIST*)malloc(sizeof(HIST));
    newnode->next = NULL;
    strncpy(newnode->cmd,str,STR_MAX+1);

    if(!(front))
        front = rear = newnode;
    else {
        rear->next = newnode;
        rear = rear->next;
    }
}
int d_start, d_end; //dump start/end address
int addr, value; // address and value for edit command
int f_start, f_end; //fill start/end addres
int prog_addr; //program start address
int exec_addr; //execute address
char file[STR_MAX];
unsigned char d[DUMP_SIZE]; //dump
char *help_list[CMD_CNT] = {
    "h[elp]",
    "d[ir]",
    "q[uit]",
    "hi[story]",
    "du[mp] [start, end]",
    "e[dit] address, value",
    "f[ill] start, end, value",
    "reset",
    "opcode mnemonic",
    "opcodelist",
    "assemble filename",
    "type filename",
    "symbol",
    "progaddr [address]",
    "loader [object filename1] [object filename2] [...]",
    "bp [clear]|[address]",
    "run"
};

/* fuction definition */
void scan(char*, char*);
void pass_blank(char*, int*);
void mv_hex(char*, int*, char*, int*);
int check_blank(char*, int);
int check_cmd(char*, char*);
int check_hex(char*);
int check_dump(char*, char*);
int check_edit(char*, char*);
int check_fill(char*, char*);
int check_opcode(char*, char*);
int check_range(char*, int);
int check_type(char*, char*);
int check_assemble(char*, char*);
int check_reg(char*);
void invalid_range();
void invalid_cmd();
void no_mnemonic();
void no_file();
void invalid_string(char *);
void dump();
void help();
void dir();
void history();
void edit();
void fill();
void reset();
int hash(char*);
void make_table();
void opcodelist();
void assemble();
void free_all();
int dec(char*);
void cut_asm(char*, char*, char*, char*);
void fileread(FILE*, char*, char*, char*, char*);
int pass1(FILE*, FILE*, char*, char*, char*, char*, char*, int*, int*);
int pass2(FILE*, FILE*, FILE*, char*, int);
void print_symbol();
int set_progaddr(char *,char *);
int loader(char *, char*);
int loader_pass1(char*, int*, int*);
int loader_pass2(char*, int*);
void clear_estab();
int check_bp(char*, char*);
void run();
#endif
