#include "hfiles/address.h"
#include <stdio.h>
#include "hfiles/ini.h"
#include <string.h>
#include <stdlib.h>

// parse ini config file


typedef struct {
    char* name;
    int age;
} USER;


/*
    @param
        user: user value
    @param
        section: section name
    @param
        name: element name
    @param
        value: used in function automatically
        ,the value of element
    @brief
        A handler funtion to parse ini file
    @return
        0: success
        1: error

*/
static int handler(void* user,char* section,char* name,char* value){
    
    USER* USERCONFIG = (USER*) user;
    #define MATCH(s,e) strcmp(section,s) == 0 && strcmp(name,e) == 0
    if (MATCH("user","name"))
        USERCONFIG->name = strdup(value);
    else if (MATCH("user","age"))
        USERCONFIG->age = atoi(value);
    else
        printf("Unknown section %s or name %s\n",section,name);
        return 1;
    return 0;

}


int main(int argc,char* argv[]){
    if (argc != 2){
        printf("Usage: %s <ini file>\n",argv[0]);
        return 1;
    }
    FILE *fp = fopen(argv[1],"r");
    if (fp == NULL) 
        printf("Error opening file");
    USER user;
    user.name = NULL;
    user.age = 0;
    if (ini_parse_file(fp,handler,&user)==1){
        printf("Error parsing file\n");
        return 1;
    }
    printf("Name: %s\n",user.name);
    printf("Age: %d\n",user.age);
    free(user.name);
    fclose(fp);
    return 0;
}


