#include "includes/frame.h"

PilhaFrame pilha_frame = {
    .length = 0,
    .frame = NULL
};


void add_frame(ClassFile* classe, uint16_t method_index){
    
	// //Aloca espaço para o novo frame.
	// struct stackFrame* sf = NULL;
	// sf =(struct stackFrame*) calloc(sizeof(struct stackFrame),1);

	// if(sf == NULL){
	// 	printf("Problema na alocação do frame\n");
	// }

	// sf->refFrame = (struct frame*) calloc(sizeof(struct frame),1);

	// //Empilha o frame na pilha de frames.
	// pushFrame(cp,classe,code,sf);
}