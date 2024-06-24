#ifndef CARREGADOR_H
#define CARREGADOR_H

#include "leitor.h"
#include "area_metodos.h"
#include <stdbool.h>

extern char* classpath;
extern bool carregado;

typedef struct {
    Method *metodo;
    ClassFile *classe;
} MethodRef;

ClassFile *carrega_classe(char* classe);
MethodRef *busca_metodo(ClassFile *classe, char *nome, char *descritor);
ClassFile *carrega_classe_inicial(char *classe);
ClassFile *busca_classe(char *nome_classe);
void inicializa_carregador(char *cp);
ClassFile *busca_super_classe(ClassFile *classe);

#endif
