#include "includes/carregador.h"

#include <stdlib.h>

ListaClasse lista_classes;

void inicializa_lista_classes()
{
    lista_classes.classes = (ClassFile **)calloc(1, sizeof(ClassFile *));
    lista_classes.classes[0] = class_reader("classpath/Object.class");
    lista_classes.length = 1;
}
