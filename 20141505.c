#include "20141505.h"
int main() {
    char str[STR_MAX+1];
    char cmd[STR_MAX+1];

    //make hash table
    make_table();

    do {
        printf("sicsim> ");
        memset(str, 0, sizeof(str));
        memset(cmd, 0, sizeof(cmd));
        scan(str, cmd);
    } while(check_cmd(str,cmd));
    free_all();
    return 0;
}
/* invalid command */
void invalid_cmd() {
    printf("*** Invalid Command! ***\n");
}
/* invalid range */
void invalid_range() {
    printf("*** invalid range! ***\n");
}
/* invalid mnemonic */
void no_mnemonic() {
    printf("*** Mnemonic doesn't exist ***\n");
}
/* invalid file name */
void no_file() {
    printf("*** File doesn't exist ***\n");
}
/* pass the blank from str */
void pass_blank(char *str, int *i) {
    for(;str[*i] == ' ' || str[*i] == '\t';++(*i));
}
/* scan 1 line to str, extract command */
void scan(char *str, char *cmd) {
    char tmp;
    int i=0;
    //scan 1 line
    while((tmp=getchar()) == ' ' || tmp == '\t')
        str[i++] = tmp;
    if(tmp == '\n') return;
    str[i++] = tmp;
    while((tmp=getchar()) !='\n' && tmp != EOF) {
        if(i<STR_MAX)
            str[i++] = tmp;
    }
    str[i] = '\0';
    //cmd saves command string
    sscanf(str," %s",cmd);
}

/* check blank */
int check_blank(char* str, int i) {
    pass_blank(str,&i);
    if(str[i] != '\0')
        return 0;
    return 1;
}

/* check cmd syntax error */
int check_cmd(char* str,char* cmd) {
    int i = 0, c = 0;
    int h = 0;
    pass_blank(str,&i);
    i+=strlen(cmd);
    // help
    if(!strcmp(cmd,"h") || !strcmp(cmd,"help")) {
        if((c=check_blank(str, i)) == CORRECT_CMD)
            help();
    }
    //dir
    else if(!strcmp(cmd,"d") || !strcmp(cmd,"dir")) {
        if((c=check_blank(str, i)) == CORRECT_CMD)
            dir();
    }
    //quit
    else if(!strcmp(cmd,"q") || !strcmp(cmd,"quit")) {
        if((c=check_blank(str, i)) == CORRECT_CMD)
            return 0;
    }
    //history
    else if(!strcmp(cmd,"hi") || !strcmp(cmd,"history")) {
        if((c=check_blank(str, i)) == CORRECT_CMD)
            h = 1;
    }
    //dump
    else if(!strcmp(cmd,"du") || !strcmp(cmd,"dump")) {
        if((c=check_dump(str, cmd)) == CORRECT_CMD)
            dump();
        else if(c == INVALID_RANGE)  // if invalid range
            invalid_range();
    }
    //edit
    else if(!strcmp(cmd,"e") || !strcmp(cmd,"edit")) {
        if((c=check_edit(str, cmd)) == CORRECT_CMD)
            edit();
        else if(c == INVALID_RANGE) //if invalid range
            invalid_range();
    }
    //fill
    else if(!strcmp(cmd,"f") || !strcmp(cmd,"fill")) {
        if((c=check_fill(str,cmd)) == CORRECT_CMD)
            fill();
        else if(c == INVALID_RANGE) // if invalid range
            invalid_range();
    }
    //reset
    else if(!strcmp(cmd,"reset")) {
        if((c=check_blank(str, i)) == CORRECT_CMD)
            reset();
    }
    //opcode
    else if(!strcmp(cmd,"opcode")) {
        if((c=check_opcode(str,cmd)) == INVALID_RANGE)
            no_mnemonic();
    }
    //opcodelist
    else if(!strcmp(cmd,"opcodelist")) {
        if((c=check_blank(str,i)) == CORRECT_CMD)
            opcodelist();
    }
    //tpye
    else if(!strcmp(cmd,"type")) {
        if((c=check_type(str,cmd)) == INVALID_RANGE)
            no_file();
    }
    //assemble
    else if(!strcmp(cmd,"assemble")) {
        if((c=check_assemble(str,cmd)) == CORRECT_CMD) 
            assemble();
        else if(c == INVALID_RANGE)  // if there is no file
            no_file();
    }
    //symbol
    else if(!strcmp(cmd,"symbol")) {
        if((c=check_blank(str, i)) == CORRECT_CMD) {
            print_symbol();
        }
    }
    //progaddr
    else if(!strcmp(cmd,"progaddr")) {
        if((c=set_progaddr(str,cmd)) == INVALID_RANGE)
            invalid_range();
    }
    //loader
    else if(!strcmp(cmd,"loader")) {
        if((c=loader(str,cmd)) == INVALID_RANGE) // file does not exist
            no_file();
    }
    //bp
    else if(!strcmp(cmd,"bp")) {
        if((c=check_bp(str,cmd)) == INVALID_RANGE)
            invalid_range();
    }
    //run
    else if(!strcmp(cmd,"run")) {
        if((c=check_blank(str, i)) == CORRECT_CMD) 
            run();
    }
    if(strlen(str) == 0) return 1;
    if(c == CORRECT_CMD) mkhis(str); //if correct command, make history
    if(h) history(); //history print
    else if(c == INVALID_CMD)  //if command is not valid
        invalid_cmd();
    return 1;
}
/* print help list */
void help() {
    int i;
    for(i=0;i<CMD_CNT;++i)
        printf("%s\n",help_list[i]);
}
/* print dir */
void dir() {
    //if(strlen(cmd) == 0) return 1;
    DIR *dirp;
    struct dirent *dp;
    struct stat st;
    dirp = opendir(".");

    while((dp = readdir(dirp)) != NULL) {
        if(!strcmp(dp->d_name,".") || !strcmp(dp->d_name,".."))
            continue;
        stat(dp->d_name, &st);
        printf("%20s",dp->d_name);

        if(S_ISDIR(st.st_mode)) //is dir
            printf("/");
        else if(S_IXUSR & st.st_mode) //is exe
            printf("*");
    }
    printf("\n");
    closedir(dirp);
}
/* print history */
//if(strlen(cmd) == 0) return 1;
void history() {
    int i = 1;
    HIST* tmp = front;
    for(;tmp;tmp=tmp->next, ++i) 
        printf("%5d %s\n",i, tmp->cmd);
}
/* check hex */
int check_hex(char *a) {
    if(*a>='a' && *a<='f') //from a to f
        (*a)+='A'-'a';
    if((*a >='0' && *a<='9') || (*a>='A' && *a<='F')) // 0-9 or from A to F
        return 1;
    else return 0;
}
/* check addr range / hex range 
 * mode = 1 : addr range check
 * mode = 2 : hex range check
 * mode = 3 : return hex no range
 * if range error return -1, else ret
 */
int check_range(char *a, int mode) {
    int i;
    int ret=0;
    for(i=0;a[i];++i) {
        ret*=16;
        if(a[i] >= '0' && a[i] <='9')
            ret+=a[i]-'0';
        else ret+=a[i]-'A'+10;
        if(mode == 1 && ret > ADDR_MAX) 
            return -1;
        if(mode == 2 && ret > HEX_MAX)
            return -1;
    }
    return ret;
}
/* check dump syntax error */
int check_dump(char *str, char *cmd) {
    int slen = strlen(str);
    int i = 0, idx;
    int start = d_start, end = d_end;
    char s[STR_MAX+1]={0,}, e[STR_MAX+1]={0,};

    pass_blank(str, &i);
    i+=strlen(cmd);
    pass_blank(str, &i);
    if(i < slen) { //if start value exist
        mv_hex(str,&i,s,&idx);
        if(str[i] != ' ' && str[i] != '\t' && str[i] != ',' && str[i] !='\0') 
            return INVALID_CMD;
        if(idx == 0) return INVALID_CMD;

        if((start = check_range(s,1)) == -1) return INVALID_RANGE;

        //if(strlen(cmd) == 0) return 1;
        pass_blank(str,&i);

        if(i < slen) { // if end value exist
            if(str[i] != ',') {
                return 0;
            }
            i++; //pass ','
            pass_blank(str,&i);
            mv_hex(str,&i,e,&idx);

            if(str[i] != ' ' && str[i] != '\t' && str[i] != '\0') 
                return INVALID_CMD;
            if(idx == 0) return INVALID_CMD;
            if((end = check_range(e,1)) == -1) return INVALID_RANGE;
        }
        else end = 0;

        if(end != 0 && start > end) { //invalid range
            return INVALID_RANGE;
        }
        if(start >= DUMP_SIZE || end >= DUMP_SIZE) {  //invalid range
            return INVALID_RANGE;
        }
    }
    else end = 0;
    pass_blank(str, &i);
    if(i < slen) return INVALID_CMD;
    // if start and end are valid
    d_start = start;
    d_end = end;
    return 1;
}
/* copy hex part to arr */
void mv_hex(char *str, int *i, char *arr, int *idx) {
    for(*idx = 0;check_hex(&str[*i]);++(*i)) {
        arr[(*idx)++] = str[*i];
    }
}
/* print dump */ 
void dump() {
    int i, j, x;
    int sl, el;
    if(d_start == DUMP_SIZE)
        d_start = 0;
    sl = d_start/16*16; //floor

    if(d_end == 0) //if end value is not selected
        d_end = d_start+159;

    el = (d_end+16)/16*16; //ceiling

    if(el >= DUMP_SIZE)
        el = d_end = DUMP_SIZE-1;

    for(i=sl;i<el;) {
        printf("%05X ",i);  //dump start line addr
        x = i;
        for(j=0;j<16;++i,++j) {
            if(i>=d_start && i<= d_end)
                printf("%02X ",d[i]); //print hex
            else printf("   ");
        }
        printf("; ");
        for(i=x, j=0;j<16;++i, ++j) {
            if(d[i] >= 32 && d[i] <=126) // print data
                printf("%c",d[i]);
            else printf(".");
        }
        printf("\n");
    }
    d_start = d_end+1;
}
/* check edit syntax error */
int check_edit(char *str, char *cmd) {
    int slen = strlen(str);
    int i = 0, idx;
    char a[STR_MAX+1]={0,}, v[STR_MAX+1]={0,};
    int aa, vv;

    pass_blank(str, &i);
    i+=strlen(cmd);
    pass_blank(str, &i);
    if(i >= slen) return INVALID_CMD; // no addr

    mv_hex(str,&i,a,&idx);
    if(idx == 0) return INVALID_CMD;
    if((aa = check_range(a,1)) == -1) return INVALID_RANGE;  //addr invalid range

    pass_blank(str, &i);
    if(str[i] != ',') return INVALID_CMD; // no value
    //if(strlen(cmd) == 0) return 1;
    i++;

    pass_blank(str,&i);
    mv_hex(str,&i,v,&idx);
    if(idx == 0) return INVALID_CMD;
    if((vv = check_range(v,2)) == -1) return INVALID_RANGE; //value invalid range

    pass_blank(str, &i);
    if(i < slen) return INVALID_CMD;

    //if value is correct
    addr = aa;
    value = vv;
    return 1;
}
/* edit value */
void edit() {
    d[addr] = value;
}
/* check fill syntax error */
int check_fill(char *str, char *cmd) {
    int slen = strlen(str);
    int i = 0, idx;
    int start, end, vv;
    char s[STR_MAX+1]={0,}, e[STR_MAX+1]={0,}, v[STR_MAX+1]={0,};

    pass_blank(str, &i);
    i+=strlen(cmd);
    pass_blank(str, &i);
    if(i >= slen) return INVALID_CMD; // no start

    mv_hex(str,&i,s,&idx);
    if(idx == 0) return INVALID_CMD;
    if((start = check_range(s,1)) == -1) return INVALID_RANGE;

    pass_blank(str, &i);
    if(str[i] != ',') return INVALID_CMD; //no end
    i++;

    pass_blank(str,&i);
    mv_hex(str,&i,e,&idx);
    if(idx == 0) return 0;
    if((end = check_range(e,1)) == -1) return INVALID_RANGE;

    pass_blank(str,&i);
    if(str[i] != ',') return INVALID_CMD; // no value
    i++;

    pass_blank(str,&i);

    mv_hex(str,&i,v,&idx);
    if(idx == 0) return INVALID_CMD;
    if((vv = check_range(v,2)) == -1) return INVALID_RANGE; //value invalid range

    pass_blank(str,&i);
    if(i < slen) return INVALID_CMD;
    //if value is correct
    f_start = start;
    f_end = end;
    value = vv;
    return 1;
}

/* fill dump */
void fill() {
    int i;
    for(i=f_start;i<=f_end;++i)
        d[i] = value;
}
/* reset dump */
void reset() {
    memset(d,0,sizeof(d));
}
/* check opcode syntax error */
int check_opcode(char *str, char *cmd) {
    int slen = strlen(str);
    int i = 0;
    char mnemonic[STR_MAX+1] = {0,};
    OPCODE *tmp;

    pass_blank(str,&i);
    i+=strlen(cmd);
    pass_blank(str, &i);
    if(i >= slen)
        return INVALID_CMD;
    sscanf(str+i,"%s",mnemonic);
    tmp = table[hash(mnemonic)]; //find hash
    while(tmp) {
        if(!strcmp(tmp->mnemonic,mnemonic)) { //find mnemonic
            printf("opcode is %X\n",tmp->opcode);
            return CORRECT_CMD;
        }
        tmp = tmp->next;
    }
    return INVALID_CMD;
}
/* print opcode list */
void opcodelist() {
    int i;
    OPCODE *tmp;
    for(i=0;i<TABLE_SIZE;++i) {
        printf("%2d : ",i);
        if(table[i]) { //if table[i] (head) exist
            for(tmp=table[i];tmp->next;tmp=tmp->next) {
                printf("[%s,%X] -> ",tmp->mnemonic, tmp->opcode);
            }
            printf("[%s,%X]",tmp->mnemonic, tmp->opcode);
        }
        printf("\n");
    }
}
/* make hash table */
void make_table() {
    FILE *in = fopen("opcode.txt","r"); //file reed
    int opc, h;
    char mnemonic[STR_MAX+1]={0,}, format[STR_MAX+1]={0,};
    OPCODE *node, *tmp;

    while(fscanf(in,"%X %s %s",&opc, mnemonic, format) != EOF) { //file reed
        node = mkopc(opc,mnemonic,format);
        if(table[(h=hash(mnemonic))] == NULL) { //head exist
            table[h] = node;
        } else {
            for(tmp=table[h];tmp->next;tmp=tmp->next);
            tmp->next = node;
        }
    }
    fclose(in);
}
/* free all data */
void free_all() {
    HIST *h_tmp, *h_del;
    OPCODE *o_tmp, *o_del;
    int i;
    for(h_tmp=front;h_tmp;) {
        h_del=h_tmp;
        h_tmp=h_tmp->next;
        free(h_del);
    }
    front=NULL;
    for(i=0;i<TABLE_SIZE;++i) {
        for(o_tmp=table[i];o_tmp;) {
            o_del=o_tmp;
            o_tmp=o_tmp->next;
            free(o_del);
        }
        table[i]=NULL;
    }
}
/* hash function */
int hash(char *s)
{
    int i,sum;
    int len=strlen(s);
    for(i=0,sum=0;i<len;i++)
        sum+=s[i];
    return sum%20;
}
/* check type func syntax error and open/print file*/
int check_type(char *str, char *cmd) {
    FILE *fp = NULL;
    int slen = strlen(str);
    int i = 0;
    char tmp;

    pass_blank(str,&i);
    i+=strlen(cmd);
    pass_blank(str, &i);
    if(i >= slen) // no filename
        return INVALID_CMD; 

    // scan file name
    sscanf(str+i,"%s",file);
    i+=strlen(file);
    pass_blank(str,&i);
    if(i < slen) // Syntax error
        return INVALID_CMD;

    //open file
    fp = fopen(file,"r");
    if(fp == NULL)  { // file does not exist
        //fclose(fp);
        return INVALID_RANGE;
    }

    // print file
    while((tmp=fgetc(fp)) != EOF) {
        printf("%c",tmp);
    }

    fclose(fp);    
    return CORRECT_CMD;
}
/* check assemble command syntax error */
int check_assemble(char *str, char *cmd) {
    FILE *fp = NULL;
    int slen = strlen(str);
    int i = 0;

    pass_blank(str,&i);
    i+=strlen(cmd);
    pass_blank(str, &i);
    if(i >= slen) // no filename
        return INVALID_CMD; 
    // scan file name
    sscanf(str+i,"%s",file);
    i+=strlen(file);
    pass_blank(str,&i);
    if(i < slen) // Syntax error
        return INVALID_CMD;

    // check file extension
    if(strcmp(file+strlen(file)-4,".asm"))
        return INVALID_CMD;

    // file exist
    fp = fopen(file,"r");
    if(fp == NULL)  { // file does not exist
        fclose(fp);
        return INVALID_RANGE;
    }
    fclose(fp);
    return CORRECT_CMD;
}
/* check string decimal, and return value */
int dec(char *str) {
    int i;
    int a=0;
    for(i=0;str[i];++i) {
        if(str[i] > '9' || str[i] < '0')
            return -1;
        a*=10;
        a+=str[i]-'0';
    }
    return a;
}
/* cut command [symbol] [opcode] [operand]  */
void cut_asm(char *str, char *label, char *opcode, char *operand) {
    int i = 0, slen = strlen(str), tmp;
    char l[STR_MAX+1]={0}, c[STR_MAX+1]={0};
    pass_blank(str,&i);
    sscanf(str+i,"%s",l);
    i+=strlen(l);
    pass_blank(str,&i);
    // no operand
    if( i >= slen) { sscanf(str, "%s", opcode);return; }
    sscanf(str+i,"%s",c);
    i+=strlen(c);
    tmp = i;
    pass_blank(str,&i);
    if(i >= slen || str[i] == ',' || str[tmp-1] == ',') { // no symbol
        sscanf(l,"%s",opcode);
        sscanf(c,"%s",operand);
        strncpy(operand+strlen(c),str+i,strlen(str+i));
    }
    else { // symbol exist
        sscanf(l,"%s",label);
        sscanf(c,"%s",opcode);
        strncpy(operand,str+i,strlen(str+i));
    }
}
/* print invalid string */
void invalid_string(char *str) {
    printf(" *** error string : %s\t",str);
}
/* read file one line to cmd */
void fileread(FILE *fp, char *cmd, char *label, char *opcode, char *operand) {
    int i;
    memset(cmd, 0, sizeof(char)*STR_MAX+1);
    for(i=0;;++i) {
        cmd[i] = fgetc(fp);
        if(cmd[i] == EOF || cmd[i] == '\n') {
            cmd[i] = '\0'; // end of string
            break;
        }
    }
    memset(label, 0, sizeof(char)*STR_MAX+1);
    memset(opcode, 0, sizeof(char)*STR_MAX+1);
    memset(operand, 0, sizeof(char)*STR_MAX+1);
    cut_asm(cmd, label, opcode, operand); //line cut
}
/* check it is valid register */
int check_reg(char *str) {
    char *reg[] = {"A","X","L","B","S","T","F","D","PC","SW"};
    int i;
    if(strlen(str) == 0) return 0;
    for(i=0;i<10;++i) {
        if(i!=7 && !strcmp(str, reg[i]))
            return i;
    }
    return -1;
}
/* command type : 
   0 = start
   1 = format 1
   2 = format 2
   3 = format 3
   4 = format 4
   5 = base
   6 = variable
   7 = WORD
   8 = BYTE hex
   9 = BYTE char
   10 = end
   intermediate file format :
   [command type] [locctr] [label] [opcode] [operand]
 */
/* pass1 process (make sym table, checking syntax error) */
int pass1(FILE *fp, FILE *inter, char *cmd, char *label, char *opcode, char *operand, 
        char *base, int *locctr, int *start_addr) {
    int format, flag, h, oplen, i;
    int ret = 1;
    char reg1[STR_MAX+1], reg2[STR_MAX+1];
    SYMBOL *sym_tmp, *node;
    OPCODE *op_tmp;

    if(!strcmp(opcode,"START")) {
        if(dec(operand) == -1) {    //operand is not decimal
            invalid_string(cmd);
            printf("invalid operand ***\n");
            ret = 0;
        }
        *start_addr = *locctr = dec(operand);
        fprintf(inter,"%d %04X %s\n",0,*locctr,cmd);
        fileread(fp,cmd,label,opcode,operand);
    } else  *locctr = 0;

    while(strcmp(opcode, "END")) {
        format = 0;
        if(feof(fp)) {  // no end line
            invalid_string(cmd);
            printf("no END line ***");
            ret = 0;
        }
        if(cmd[0] != '.') { //if it's comment
            if(!strcmp(opcode,"START")) {
                invalid_string(cmd);
                printf("START is not first ***\n");
                ret = 0;
            }
            // format 4 erase +
            if(opcode[0] == '+') {
                format = 4;
                oplen = strlen(opcode);
                for(i=0;i<oplen-1;++i)
                    opcode[i] = opcode[i+1];
                opcode[i] = '\0';
            }

            if(strlen(label) > 0) { //if label exist
                sym_tmp = symtab[(h=hash(label))];
                node = mksym(*locctr, label);
                if(symtab[h] == NULL) { //head exist
                    symtab[h] = node;
                } else {
                    while(sym_tmp) {
                        if(!strcmp(sym_tmp->label,label)) {
                            invalid_string(cmd);
                            printf("duplicate symbol ***\n");
                            ret = 0;
                        }
                        sym_tmp = sym_tmp->next;
                    }
                    for(sym_tmp=symtab[h];sym_tmp->next;sym_tmp=sym_tmp->next);
                    sym_tmp->next = node;
                }
            }
            if(!strcmp(opcode,"BASE"))
                fprintf(inter, "5      ");

            //find opcode
            flag=0;
            op_tmp = table[hash(opcode)]; //find hash
            while(op_tmp) {
                if(!strcmp(op_tmp->mnemonic,opcode)) { //find mnemonic
                    flag = 1;
                    break;
                }
                op_tmp = op_tmp->next;
            }

            if(flag) { // if opcode exist
                //find opcode format
                if(!strcmp(op_tmp->format,"1")) {
                    format = 1;
                } else if(!strcmp(op_tmp->format,"2")) {
                    format = 2;
                    memset(reg1,0,sizeof(reg1));
                    memset(reg2,0,sizeof(reg2));
                    sscanf(operand,"%[^,],%s",reg1,reg2);
                    if(check_reg(reg1) == -1) { // invalid register
                        invalid_string(cmd);
                        printf(" invalid register ***\n");
                        ret = 0;
                    } else if(check_reg(reg2) == -1) { //invalid register
                        invalid_string(cmd);
                        printf(" invalid register ***\n");
                        ret = 0;
                    }
                } else if(format == 0) {
                    format = 3;
                }
                fprintf(inter,"%d %04X ",format, *locctr);
                *locctr += format;
            } else if(!strcmp(opcode,"BASE")) { //BASE
                strncpy(base,operand,STR_MAX+1);
            } else if(!strcmp(opcode,"RESW")) {
                fprintf(inter,"6 %04X ", *locctr);
                *locctr += 3*dec(operand);
            } else if(!strcmp(opcode,"RESB")) {
                fprintf(inter,"6 %04X ", *locctr);
                *locctr += dec(operand);
            } else if(!strcmp(opcode,"BYTE")) {
                if(operand[1] != '\'' || operand[strlen(operand)-1] != '\'') {
                    invalid_string(cmd);
                    printf(" invalid value ***\n");
                }
                if(operand[0] == 'X') { // byte value is hex
                    if(operand[1] != '\'' || operand[strlen(operand)-1] !='\'') {
                        invalid_string(cmd);
                        printf(" invalid data ***\n");
                        ret = 0;
                    }
                    // check data is hex and the number of hex is even count
                    if(check_hex(operand+2) == 0 || (strlen(operand)-3)%2 != 0) {
                        invalid_string(cmd);
                        printf(" invalid hex ***\n");
                        ret = 0;
                    }
                    fprintf(inter,"8 %04X ", *locctr);
                    *locctr += (strlen(operand)-2)/2;
                }
                else if(operand[0] == 'C') { //byte value is char
                    fprintf(inter,"9 %04X ", *locctr);
                    *locctr += strlen(operand)-3;
                } 
                else {
                    invalid_string(cmd);
                    printf(" invalid value ***\n");
                    ret = 0;
                }
            } else if(!strcmp(opcode,"WORD")) { // WORD
                if(dec(opcode) == -1) {
                    invalid_string(cmd);
                    printf("invalid decimal ***\n");
                    ret = 0;
                }
                fprintf(inter,"7 %04X ",*locctr);
                *locctr+= 3;
            } else { // invalid opcode
                invalid_string(cmd);
                printf("invalid operand ***\n");
                ret = 0;
            }
            // intermeditate print
            fprintf(inter,"%s\n",cmd);
        }
        fileread(fp,cmd,label,opcode,operand);
    }
    fprintf(inter,"10 %04X %s\n",*locctr,cmd);
    return ret;
}
/* pass2 process */
int pass2(FILE *inter, FILE *obj, FILE *lst, char *base, int program_len) {
    FILE *tfp = fopen("temporary.txt","w"); // temporary file
    FILE *mfp = fopen("temporary_modification.txt", "w"); // temporary for modification file
    char cmd[STR_MAX+1]={0,};
    char label[STR_MAX+1]={0,}, opcode[STR_MAX+1]={0,}, operand[STR_MAX+1]={0,};
    char object_code[STR_MAX+1]={0,}, symbol[STR_MAX+1]={0,};
    int line_number = 5, locctr, disp;
    int type, op_num, sym_addr,start_addr, base_addr, pc_addr, i, len;
    char reg1[STR_MAX+1], reg2[STR_MAX+1];
    int is_line_first = 1;
    int objectcode_size = 0;
    SYMBOL *sym_tmp;
    OPCODE *op_tmp;

    fscanf(inter,"%d %X ",&type, &locctr);
    fileread(inter,cmd,label,opcode,operand);

    if(type == 0) { // START
        start_addr = locctr;
        //print obj file head recor
        fprintf(obj,"H%-6s%06X%06X\n",label, start_addr, program_len);
        fprintf(lst,"%3d\t\t%04X\t%-6s\t%-6s\t%-6s\n",line_number, locctr, label, opcode, operand);
        fscanf(inter,"%d ",&type);
        if(type != 5) fscanf(inter,"%X ",&locctr);
        fileread(inter,cmd,label,opcode,operand);
    }
    // not END
    while(type != 10) {
        line_number += 5;
        if(type == 4) {
            //erase '+' from opcode
            op_tmp = table[hash(opcode+1)];
            while(op_tmp) {
                if(!strcmp(op_tmp->mnemonic,opcode+1)) { //find mnemonic
                    op_num = op_tmp->opcode;
                    break;
                }
                op_tmp = op_tmp->next;
            }
        }
        else {// find opcode
            op_tmp = table[hash(opcode)]; //find hash
            while(op_tmp) {
                if(!strcmp(op_tmp->mnemonic,opcode)) { //find mnemonic
                    op_num = op_tmp->opcode;
                    break;
                }
                op_tmp = op_tmp->next;
            }
        }
        if(strcmp(opcode,"BASE"))
            fprintf(lst,"%3d\t\t%04X\t%-6s\t%-6s\t%-10s\t",line_number, locctr, label, opcode, operand);
        else fprintf(lst,"%3d\t\t\t\t%-6s\t%-6s\n",line_number, opcode, operand);
        if(type == 6) { // variable
            fprintf(tfp, "\n");
            is_line_first = 1;
            objectcode_size = 0;
            fprintf(lst,"\n");
        }
        else if(type == 1) { // format 1
            if (objectcode_size + 2 > 60) {
                objectcode_size = 0;
                is_line_first = 1;
                fprintf(tfp, "\n");
            }
            if (is_line_first) {
                is_line_first = 0;
                fprintf(tfp, "%X %02X", locctr, op_num);
            } else {
                fprintf(tfp, "%02X", op_num);
            }
            objectcode_size += 2;
            fprintf(lst,"%02X\n",op_num);
        }
        else if(type == 2) { //format 2
            if (objectcode_size + 4 > 60) {
                objectcode_size = 0;
                is_line_first = 1;
                fprintf(tfp, "\n");
            }
            memset(reg1, 0, sizeof(reg1));
            memset(reg2, 0, sizeof(reg2));
            sscanf(operand,"%[^,],%s",reg1,reg2);
            if (is_line_first) {
                is_line_first = 0;
                fprintf(tfp, "%X %02X%X%X",locctr, op_num, check_reg(reg1), check_reg(reg2));
            } else {
                fprintf(tfp, "%02X%X%X", op_num, check_reg(reg1), check_reg(reg2));
            }
            objectcode_size += 4;
            fprintf(lst,"%02X%X%X\n",op_num,check_reg(reg1),check_reg(reg2));
        }
        else if(type == 3) { //format 3
            //shift op_num
            op_num>>=2;
            op_num<<=18;
            len = strlen(operand);
            /* select addressing mode. ni = simple 11, indirect 10, immediate 01 */
            if(operand[0] == '#') { // immediate operand
                op_num|=(1<<16);
                //delete #
                for(i=0;i<len-1;++i)
                    operand[i] = operand[i+1];
                operand[i] = '\0';

            }
            else if(operand[0] == '@') {// indirect addressing
                op_num|=(1<<17);
                //delete @
                for(i=0;i<len-1;++i)
                    operand[i] = operand[i+1];
                operand[i] = '\0';
            }
            else { // simple addressing
                op_num|=(3<<16);
            }

            if(sscanf(operand,"%[^,], %s",symbol,reg1) == 2) { // index addressing
                if(check_reg(reg1) != 1) {
                    invalid_string(cmd);
                    printf("register must be X ***\n");
                    return 0;
                }
                op_num|=(1<<15); // set x bit 1.
            }

            pc_addr = locctr+3; //format 3 PC
            sym_tmp = symtab[hash(symbol)];
            while(sym_tmp) {
                if(!strcmp(sym_tmp->label,symbol)) {
                    sym_addr = sym_tmp->locctr;
                    break;
                }
                sym_tmp = sym_tmp->next;
            }
            if(sym_tmp == NULL) {// is decimal
                if(dec(symbol)<0) {
                    invalid_string(cmd);
                    printf("is not decimal ***\n");
                    return 0;
                }
                sym_addr = dec(operand);
                op_num|=sym_addr;
            }
            else {
                disp = sym_addr-pc_addr;
                if(disp <= 2047 && disp >= -2048) { // pc relative
                    op_num|=(1<<13); // set p bit 1
                } else {
                    sym_tmp = symtab[hash(base)];
                    while(sym_tmp) {
                        if(!strcmp(sym_tmp->label,base)) {
                            base_addr = sym_tmp->locctr;
                            break;
                        }
                        sym_tmp = sym_tmp->next;
                    }

                    disp = sym_addr-base_addr;
                    if(disp >=0 && disp <=4095) { //base relative
                        op_num|=(1<<14); // set b bit 1
                    } else {
                        invalid_string(cmd);
                        printf(" invalid range ***\n");
                        return 0;
                    }
                }
                disp&=((1<<12)-1);
                op_num|=disp;
            }
            if(strlen(operand) == 0) op_num&=16711680; // (FF0000)
            if (objectcode_size + 6 > 60) {
                fprintf(tfp, "\n");
                objectcode_size = 0;
                is_line_first = 1;
            }
            if (is_line_first) {
                is_line_first = 0;
                fprintf(tfp, "%X %06X", locctr, op_num);
            } else {
                fprintf(tfp, "%06X", op_num);
            }
            objectcode_size += 6;
            fprintf(lst,"%06X\n",op_num);
        }
        else if(type == 4) { // format 4
            //shift op_num
            op_num>>=2;
            op_num<<=26;
            op_num|=(1<<20); // set e bit 1
            len = strlen(operand);
            /* select addressing mode. ni = simple 11, indirect 10, immediate 01 */
            if(operand[0] == '#') { // immediate operand
                op_num|=(1<<24);
                //delete #
                for(i=0;i<len-1;++i)
                    operand[i] = operand[i+1];
                operand[i] = '\0';

            }
            else if(operand[0] == '@') {// indirect addressing
                op_num|=(1<<25);
                //delete @
                for(i=0;i<len-1;++i)
                    operand[i] = operand[i+1];
                operand[i] = '\0';
                fprintf(mfp, "M%06X05\n", locctr+1);
            }
            else { // simple addressing
                op_num|=(3<<24);
                fprintf(mfp, "M%06X05\n", locctr+1);
            }
            if(sscanf(operand,"%s,%s",symbol,reg1) == 2) { // index addressing
                if(check_reg(reg1) != 1) {
                    invalid_string(cmd);
                    printf("register must be X ***\n");
                    return 0;
                }
                op_num|=(1<<23); // set x bit 1.
            }
            pc_addr = locctr+4; //format 4 PC
            sym_tmp = symtab[hash(operand)];
            while(sym_tmp) {
                if(!strcmp(sym_tmp->label,operand)) {
                    sym_addr = sym_tmp->locctr;
                    break;
                }
                sym_tmp = sym_tmp->next;
            }
            if(sym_tmp == NULL) {// is decimal
                if(dec(operand)<0) {
                    invalid_string(cmd);
                    printf("is not decimal ***\n");
                    return 0;
                }
                sym_addr = dec(operand);
            }
            disp = sym_addr;
            op_num |= disp;
            if (objectcode_size + 8 > 60) {
                objectcode_size = 0;
                is_line_first = 1;
                fprintf(tfp, "\n");
            }
            if (is_line_first) {
                is_line_first = 0;
                fprintf(tfp, "%X %08X", locctr, op_num);
            } else {
                fprintf(tfp, "%08X", op_num);
            }
            objectcode_size += 8;
            fprintf(lst,"%08X\n",op_num);
        }
        else if(type == 7) { // opcode == WORD
            if (objectcode_size + 6 > 60) {
                objectcode_size = 0;
                is_line_first = 1;
                fprintf(tfp, "\n");
            }
            if (is_line_first) {
                is_line_first = 0;
                fprintf(tfp, "%X %06X", locctr, dec(operand));
            } else {
                fprintf(tfp, "%06X", dec(operand));
            }
            objectcode_size += 6;
            fprintf(lst,"%06X\n",dec(operand));
        }
        else if(type == 8) { // BYTE HEX
            if (objectcode_size + strlen(operand)-3 > 60) {
                objectcode_size = 0;
                is_line_first = 1;
                fprintf(tfp, "\n");
            }
            if(is_line_first) {
                fprintf(tfp,"%X ",locctr);
                is_line_first = 0;
            }
            for(i=2;operand[i]!='\'';++i) {
                fprintf(lst,"%c",operand[i]);
                fprintf(tfp,"%c",operand[i]);
            }
            objectcode_size += strlen(operand)-3;
            fprintf(lst,"\n");
        }
        else if(type == 9) { // BYTE Char
            if (objectcode_size + 2*(strlen(operand)-3) > 60) {
                objectcode_size = 0;
                is_line_first = 1;
                fprintf(tfp, "\n");
            }
            if (is_line_first) {
                fprintf(tfp,"%X ",locctr);
                is_line_first = 0;
            }
            for(i=2;operand[i]!='\'';++i) {
                fprintf(lst,"%02X",operand[i]);
                fprintf(tfp,"%02X",operand[i]);
            }
            objectcode_size += 2*(strlen(operand)-3);
            fprintf(lst,"\n");
        }
        fscanf(inter,"%d ",&type);
        if(type != 5) fscanf(inter,"%X ",&locctr);
        fileread(inter,cmd,label,opcode,operand);
    }
    fclose(tfp);
    fclose(mfp);
    tfp = fopen("temporary.txt","r");
    // make obj file complete
    while (fscanf(tfp, "%X %s", &locctr, object_code) != EOF) {
        fprintf(obj, "T%06X%02X%s\n", locctr, (int)strlen(object_code)/2, object_code);
    }
    fclose(tfp);
    mfp = fopen("temporary_modification.txt", "r");
    while (fscanf(mfp, "%s", object_code) != EOF) {
        fprintf(obj, "%s\n", object_code);
    }
    fclose(mfp);
    //delete temporary file
    remove("temporary_modification.txt");
    remove("temporary.txt");
    fprintf(obj,"E%06X\n",start_addr);
    fprintf(lst,"%3d\t\t\t%-6s\t%-6s\n",line_number+=5, opcode, operand);
    return 1;
}
/* assemble file and make .obj , .lst */
void assemble() {
    FILE *fp  = fopen(file,"r");
    FILE *inter = fopen("intermediate.txt","w");
    FILE *obj, *lst;
    char cmd[STR_MAX+1]={0,}, base[STR_MAX+1]={0,};
    char label[STR_MAX+1]={0,}, opcode[STR_MAX+1]={0,}, operand[STR_MAX+1]={0,};
    char obj_name[STR_MAX+1]={0,}, list_name[STR_MAX+1]={0,};
    int start_addr=0, locctr, i;
    int error_flag = 0, program_len;
    SYMBOL *sym_tmp, *erase;

    do {
        fileread(fp,cmd,label,opcode,operand);
    } while(cmd[0] == '.');
    //erase before symbol table
    for(i=0;i<TABLE_SIZE;++i) {
        sym_tmp = symtab[i];
        while(sym_tmp) {
            erase = sym_tmp;
            sym_tmp = sym_tmp->next;
            free(erase);
        }
    }
    memset(symtab,0,sizeof(symtab));
    //if the file is empty
    if(strlen(cmd) == 0) {
        //error
        printf("*** EMPTY FILE ***\n");
        return;
    }

    //***** pass 1 *****
    if(pass1(fp, inter, cmd, label, opcode, operand, base, &locctr, &start_addr) == 0) {
        error_flag = 1;
    }
    fclose(inter);
    program_len = locctr-start_addr;
    for(i=0;file[i] !='.';++i) {
        obj_name[i] = list_name[i] = file[i];
    }
    // open intermediate.txt
    inter = fopen("intermediate.txt","r");
    strncat(obj_name,".obj",4);
    strncat(list_name,".lst",4);
    obj = fopen(obj_name,"w");
    lst = fopen(list_name,"w");
    //***** pass 2 ******
    if(pass2(inter, obj, lst, base, program_len) == 0) { 
        error_flag = 1;
    }
    if(error_flag) {
        remove(obj_name);
        remove(list_name);
        //erase before symbol table
        for(i=0;i<TABLE_SIZE;++i) {
            sym_tmp = symtab[i];
            while(sym_tmp) {
                erase = sym_tmp;
                sym_tmp = sym_tmp->next;
                free(erase);
            }
        }
        memset(symtab,0,sizeof(symtab));
    }
    else printf("\toutput file : [%s], [%s]\n",list_name, obj_name);
    remove("intermediate.txt");
    fclose(fp);
    fclose(inter);
    fclose(obj);
    fclose(lst);
}
/* print symbol table descending order */
void print_symbol() {
    int i, j, idx=0;
    SYMBOL *sym_tmp, t[500], tmp;

    for(i=0;i<TABLE_SIZE;++i) {
        sym_tmp = symtab[i];
        while(sym_tmp != NULL) {
            strncpy(t[idx].label,sym_tmp->label,STR_MAX+1);
            t[idx].locctr = sym_tmp->locctr;
            sym_tmp = sym_tmp->next;
            idx++;
        }
    }
    if(idx == 0) return; // no symbol

    for(i=0;i<idx-1;++i) {
        for(j=i+1;j<idx;++j) {
            if(strcmp(t[i].label, t[j].label) < 0) { //descending order
                tmp = t[i];
                t[i] = t[j];
                t[j] = tmp;
            }
        }
    }
    for(i=0;i<idx;++i) {
        printf("\t%s\t%4X\n",t[i].label, t[i].locctr);
    }
}
/* check asyntax error and set program starting address */
int set_progaddr(char *str, char *cmd) { 
    int i=0, end; //command end
    int slen = strlen(str);

    pass_blank(str,&i);
    i+= strlen(cmd);
    pass_blank(str, &i);
    end = i;
    if(end == slen)
        return INVALID_CMD;
    for(;str[i];++i) {
        if(check_hex(&str[i]) == 0)  // not hex
            return INVALID_CMD;
    }
    if(check_range(str+end, 1) == -1) // not between address range
        return INVALID_RANGE;
    sscanf(str+end,"%X",&prog_addr);
    return CORRECT_CMD;
}
/* clear external symbol table */
void clear_estab() {
    int i;
    EXSYM *tmp, *del;
    for(i=0;i<TABLE_SIZE;++i) {
        for(tmp=estab[i];tmp;) {
            del=tmp;
            tmp=tmp->next;
            free(del);
        }
        estab[i]=NULL;
    }
}
/* check invalid parameter and do loader */
int loader(char *str, char *cmd) {
    char filename[STR_MAX+1];
    int start=0, temp = 0;
    int total_length = 0;
    int fail = 0, compare_addr, found;
    int i;
    int csaddr = prog_addr;
    EXSYM *head, *min = NULL;

    clear_estab(); // clear external symbol table
    pass_blank(str,&start);
    start+=strlen(cmd);
    pass_blank(str,&start);
    temp = start;
    //if filename object file is not exist 
    while (sscanf(str + start, "%s", filename) != EOF) {
        start += strlen(filename);
        pass_blank(str, &start);
        if (fopen(filename, "r") == NULL) {
            return INVALID_RANGE;
        }
    }
    // make external symbol table (call pass1)
    start = temp;
    while (sscanf(str + start, "%s", filename) != EOF) {
        if (filename[0] == 0) 
            break;
        start += strlen(filename);
        pass_blank(str, &start);
        fail +=  !loader_pass1(filename, &total_length, &csaddr);
        memset(filename, 0, sizeof filename);
    }
    // Performs the actual loading, relocation, and linking (call pass2)
    start = temp;
    if (fail == 0) {
        csaddr = prog_addr;
        exec_addr = prog_addr;
        while (sscanf(str + start, "%s", filename) != EOF) {
            start += strlen(filename);
            pass_blank(str, &start);
            fail += !loader_pass2(filename, &csaddr);
        }
    }
    else return EXECPTION; //duplication symbol
    // if no error, print external symbol table
    if (fail == 0) {
        printf("control\t\tsymbol\t    address\tlength\nsection\t\tname\n");
        printf("----------------------------------------------------\n");
        found = 1;
        compare_addr = prog_addr-1;
        while(found) {
            found = 0;
            for (i=0;i<TABLE_SIZE;++i) {
                for (head = estab[i]; head; head = head->next) {
                    if (head->address > compare_addr) {
                        if (min == NULL) {
                            min = head;
                            found = 1;
                        } else if (min->address > head->address) {
                            min = head;
                            found = 1;
                        }
                    }
                }
            }
            if (found) {
                compare_addr = min->address;
                if (min->length != 0)
                    printf("%-6s\t\t\t    %04X\t%04X\n", min->label, min->address, min->length);
                else
                    printf("\t\t%-6s\t    %04X\n", min->label, min->address);
                min = NULL;
            }
        }
        printf("----------------------------------------------------\n");
        printf("\t\t\t    total length %04X\n", total_length);
        return CORRECT_CMD;
    }
    else {
        printf("*** undefined symbol ***\n");
        return EXECPTION;
    }
}
/* pass 1 linking */
int loader_pass1(char* filename, int* total_length, int* csaddr) {
    FILE* fp = NULL;
    char control_sec[7], symbol[7]; // control section is less than or equal to 6
    char str[STR_MAX+1];
    int cslth, error_flag = 0, addr;
    int start = 1;
    EXSYM *tmp, *newnode;

    // read header record
    fp = fopen(filename, "r");
    fscanf(fp,"H%6s%*6X%6X", control_sec, &cslth);
    tmp = estab[hash(control_sec)];
    while(tmp) {
        if(!strcmp(tmp->label, control_sec)) {  // duplicate external symbol
            error_flag = 1;
            printf("*** duplicate external symbol ***\n");
            break;
        }
        tmp = tmp->next;
    }
    if (!error_flag) {  // store control section name
        newnode = mkexsym(*csaddr, cslth, control_sec);
        for(tmp = estab[hash(control_sec)];tmp && tmp->next;tmp=tmp->next);
        if (tmp)
            tmp->next = newnode;
        else
            estab[hash(control_sec)] = newnode;
    }
    else return !error_flag;

    while(fgets(str, STR_MAX, fp)) {
        start = 1;
        if(str[0] == 'D') { // if D record
            while(sscanf(str+start,"%6s%6X",symbol, &addr) != EOF) {
                start += 12;    //next command start +12 char(6 symbol, 6 address)
                tmp = estab[hash(symbol)];
                while(tmp) {
                    if(!strcmp(tmp->label, symbol)) {  // duplicate external symbol
                        error_flag = 1;
                        printf("*** duplicate external symbol ***\n");
                        break;
                    }
                    tmp = tmp->next;
                } // Assigns addresses to all external symbols
                if(!error_flag) {
                    newnode = mkexsym((*csaddr)+addr,0,symbol);
                    for(tmp = estab[hash(symbol)];tmp && tmp->next;tmp=tmp->next);
                    if (tmp)
                        tmp->next = newnode;
                    else
                        estab[hash(symbol)] = newnode;
                }
            }
        }
    }
    *csaddr += cslth;
    *total_length += cslth;
    fclose(fp);
    return !error_flag;
}
/* pass2 loading loading, relocation, and linking */
int loader_pass2(char *filename, int *csaddr) {
    FILE* fp = NULL;
    char control_sec[7]={0,}, symbol[7]={0,}, // control section is less than or equal to 6
         reference[100][7]={{0}}; // convert reference number -> external symbol
    char str[STR_MAX+1];
    char reference_type;
    int cslth, addr;
    int start = 1, reference_number;
    int found, error_flag = 0; // error_flag 1: undefined external symbol
    int modifying_addr, original_addr, modifying_length;
    int i, j, t, size;
    EXSYM *tmp;

    fp = fopen(filename, "r");
    fscanf(fp,"H%6s%*6X%6X", control_sec, &cslth);
    strncpy(reference[1], control_sec, sizeof(control_sec));
    while(fgets(str, STR_MAX, fp)) {
        start = 1;  //1 = T, 6 = address, 2 = length
        if (str[0] == 'T') {
            sscanf(str+start, "%6X", &addr);
            start+=6;
            sscanf(str+start,"%2X", &size);
            start+=2;
            for(i=addr+(*csaddr), j=0; j<size*2; ++i, j+=2) {
                sscanf(str+start+j,"%02X",&t);
                d[i] = t;
            }
        }
        else if (str[0] == 'E') {
            sscanf(str+1, "%6X", &addr);
            if (addr != 0) {
                exec_addr = (*csaddr) + addr;
            }
        }
        else if(str[0] == 'R') {
            while (sscanf(str+start, "%2X%6s", &reference_number, symbol) != EOF) {
                strncpy(reference[reference_number], symbol, sizeof(symbol));
                start += 2+6; // 2:reference number, 6:external symbol length
            }
        }
        else if(str[0] == 'M') {
            sscanf(str+1,"%6X%2X%c%02X",&addr, &modifying_length, &reference_type, &reference_number);
            found = 0;
            for (tmp = estab[hash(reference[reference_number])];tmp;tmp=tmp->next) {
                if (!strcmp(tmp->label, reference[reference_number])) {
                    found = 1;
                    modifying_addr = tmp->address;
                    break;
                }
            }
            if(reference[reference_number] == 0 || found == 0) // external symbol not exist
                error_flag = 1;
            else { // symbol exist
                original_addr = 0;
                if (modifying_length % 2 == 1) { //odd number (save half byte)
                    original_addr += d[(*csaddr)+addr] % 16;
                }
                for (i = 0; i < modifying_length / 2; ++i) { // save one byte
                    original_addr *= 256;
                    original_addr += d[(*csaddr)+addr+i+(modifying_length % 2 == 1)];
                }
                if (reference_type == '+') { //modify
                    original_addr += modifying_addr;
                } else {
                    original_addr -= modifying_addr;
                }

                original_addr &= (1<<(4*modifying_length))-1; // 2's complement(4*m bits)
                /* store byte reverse direction */
                for (i=modifying_length/2-1; i>=0; --i) {
                    d[(*csaddr)+addr+i+(modifying_length %2 == 1)] = original_addr % 256;
                    original_addr /= 256;
                }
                if (modifying_length % 2 == 1) {
                    d[(*csaddr)+addr] >>= 4;
                    d[(*csaddr)+addr] <<= 4;
                    d[(*csaddr)+addr] += original_addr;
                }
            }
        }
        memset(str,0,sizeof(str));
    }
    *csaddr += cslth;
    fclose(fp);
    return CORRECT_CMD;
}
/* execute breakpoint command */
int check_bp(char *str, char *cmd) {
    int i=0, j=0, slen = strlen(str);
    int addr;
    char tmp[STR_MAX+1]={0,};
    BP *bp_tmp, *bp_del, *bp_prev, *newnode;
    pass_blank(str,&i);
    i+=strlen(cmd);
    pass_blank(str,&i);

    if(slen == i) { // command is "bp"
        // print bp list
        printf("breakpoint\n");
        printf("----------\n");
        for(bp_tmp=bp_head;bp_tmp;bp_tmp=bp_tmp->next)
            printf("%04X\n",bp_tmp->address);
        return CORRECT_CMD;
    }

    sscanf(str+i,"%s",tmp);
    i+=strlen(tmp);
    pass_blank(str,&i);
    if(i < slen)
        return INVALID_CMD;

    if(!strcmp(tmp,"clear")) {
        //clear bp list
        printf("\t[ok] clear all breakpoints\n");
        for(bp_tmp=bp_head;bp_tmp;bp_tmp=bp_tmp->next) {
            bp_del = bp_tmp;
            free(bp_del);
        }
        bp_head = NULL;
        return CORRECT_CMD;
    }
    for(j=0;tmp[j];++j) {
        if(check_hex(&tmp[j]) == 0) // not hex
            return INVALID_CMD;
    }
    if((addr=check_range(tmp,1)) == -1) //invalid range
        return INVALID_RANGE;
    for(bp_tmp=bp_head;bp_tmp;bp_tmp=bp_tmp->next) {
        if(bp_tmp->address == addr) {
            printf("*** duplicate breakpoint ***\n");
            return EXECPTION;
        }
    }
    printf("\t[ok] create breakpoint %04X\n",addr);
    // make break point
    newnode = mkbp(addr);
    if(bp_head == NULL) {
        bp_head = newnode;
    } else {
        bp_tmp = bp_head;
        for(bp_tmp=bp_prev=bp_head; bp_tmp && bp_tmp->address < addr; bp_prev=bp_tmp, bp_tmp=bp_tmp->next);
        if(bp_tmp == bp_head) {
            newnode->next = bp_head;
            bp_head = newnode;
        } else {
            newnode->next = bp_prev->next;
            bp_prev->next = newnode;
        }
    }
    return CORRECT_CMD;
}
/* execute program */
void run() {
    int cur_addr = prog_addr;
    while(cur_addr 
}
