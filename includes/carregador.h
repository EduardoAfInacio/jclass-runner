#ifndef CARREGADOR_H
#define CARREGADOR_H

#include "leitor.h"
#include "area_metodos.h"

ClassFile *carrega_classe(char* classe);
Method *busca_metodo(ClassFile *classe, char *nome, char *descritor);
ClassFile *carrega_classe_fora_classpath(char *classe);

#endif
