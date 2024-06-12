#ifndef FRAME_H
#define FRAME_H

#include "leitor.h"

typedef struct {
	int32_t* fields;
	ConstantPool* constant_pool;
	uint16_t max_stack;
	uint16_t max_locals;
	uint32_t code_length;
	uint8_t* code;
	uint32_t pc;
    int32_t* operandos;
    uint32_t operandos_length;
} Frame;

typedef struct {
    uint32_t length;
    Frame* frames;
} PilhaFrame;

extern PilhaFrame* pilha_frame;

void inicializa_pilha_frames();
void add_frame(ClassFile* classe, uint16_t method_index);
Frame* get_frame_atual();
void executa_frame_atual();
void push_pilha_operandos(int32_t valor);
void atualiza_pc();

#endif