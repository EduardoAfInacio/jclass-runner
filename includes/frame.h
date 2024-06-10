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
    int32_t* operandos_length;
} Frame;

typedef struct {
    uint32_t length;
    Frame* frame;
} PilhaFrame;

PilhaFrame pilha_frame;

void add_frame(ClassFile* classe, uint16_t method_index);