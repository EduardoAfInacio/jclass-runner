#ifndef CARREGADOR_H
#define CARREGADOR_H

#include "leitor.h"
#include "area_metodos.h"

extern char* classpath;

ClassFile *carrega_classe(char* classe);
Method *busca_metodo(ClassFile *classe, char *nome, char *descritor);
ClassFile *carrega_classe_inicial(char *classe);
ClassFile *busca_classe(char *nome_classe);
void inicializa_carregador(char *cp);

#endif
