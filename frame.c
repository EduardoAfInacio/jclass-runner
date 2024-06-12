#include "includes/frame.h"

#include <stdlib.h>

PilhaFrame *pilha_frame;

void inicializa_pilha_frames()
{
    pilha_frame = calloc(1, sizeof(pilha_frame));
    pilha_frame->frames = NULL;
    pilha_frame->length = 0;
}

void add_frame(ClassFile *classe, uint16_t method_index)
{
    CodeAttribute* code = classe->methods[method_index].code_attribute;

    pilha_frame->frames = realloc(pilha_frame->frames, (pilha_frame->length + 1) * sizeof(Frame));
    pilha_frame->frames[pilha_frame->length].pc = 0;
    pilha_frame->frames[pilha_frame->length].constant_pool = classe->constant_pool;
    pilha_frame->frames[pilha_frame->length].max_stack = code->max_stack;
    pilha_frame->frames[pilha_frame->length].max_locals = code->max_locals;
    pilha_frame->frames[pilha_frame->length].code_length = code->code_length;
    pilha_frame->frames[pilha_frame->length].code = code->code;
    pilha_frame->frames[pilha_frame->length].fields = calloc(1, sizeof(uint32_t) * pilha_frame->frames[pilha_frame->length].max_locals);
    pilha_frame->frames[pilha_frame->length].operandos = NULL;
    pilha_frame->frames[pilha_frame->length].operandos_length = 0;

    pilha_frame->length++;
}

Frame* get_frame_atual()
{
    if (!pilha_frame->length)
    {
        printf("ERRO: Pilha de frames vazia!");
        exit(0);
    }

    return &(pilha_frame->frames[pilha_frame->length - 1]);
}

void executa_frame_atual()
{
    Frame* frame_atual = get_frame_atual();
}

void push(int32_t valor)
{
    Frame* frame_atual = get_frame_atual();

    if(frame_atual->operandos_length >= frame_atual->max_stack){
		printf("ERRO: Pilha de operandos excedida!\n");
		exit(0);
	}

    frame_atual->operandos = realloc(frame_atual->operandos, sizeof(int32_t) * (frame_atual->operandos_length + 1));
    frame_atual->operandos_length++;
}

void atualiza_pc()
{
    Frame* frame_atual = get_frame_atual();
    frame_atual->pc = instrucoes[frame_atual->pc].bytes + 1;
}