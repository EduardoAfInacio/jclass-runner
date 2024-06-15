#ifndef CARREGADOR_H
#define CARREGADOR_H

#include "leitor.h"

typedef struct
{
    ClassFile** classes; 
    int length;
} ListaClasse;

extern ListaClasse classes;

void inicializa_lista_classes();

#endif
