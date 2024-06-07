#include "includes/carregador.h"

Classes classes;

void carrega_object() {
    classes.content = (ClassFile**) calloc(1, sizeof(ClassFile*));
    classes.content[0] = class_reader("classpath/Object.class");

    classes.length = 1;
}