#include "includes/instrucao.h"
#include "includes/frame.h"

Instrucao instrucoes[NUM_INSTRUCOES];

void inicializa_instrucoes()
{
    instrucoes[0].nome = "nop";
    instrucoes[0].bytes = 0;
    instrucoes[0].exec = &nop;

    instrucoes[1].nome = "aconst_null";
    instrucoes[1].bytes = 0;

    instrucoes[2].nome = "iconst_m1";
    instrucoes[2].bytes = 0;

    instrucoes[3].nome = "iconst_0";
    instrucoes[3].bytes = 0;

    instrucoes[4].nome = "iconst_1";
    instrucoes[4].bytes = 0;

    instrucoes[5].nome = "iconst_2";
    instrucoes[5].bytes = 0;

    instrucoes[6].nome = "iconst_3";
    instrucoes[6].bytes = 0;

    instrucoes[7].nome = "iconst_4";
    instrucoes[7].bytes = 0;

    instrucoes[8].nome = "iconst_5";
    instrucoes[8].bytes = 0;

    instrucoes[9].nome = "lconst_0";
    instrucoes[9].bytes = 0;

    instrucoes[10].nome = "lconst_1";
    instrucoes[10].bytes = 0;

    instrucoes[11].nome = "fconst_0";
    instrucoes[11].bytes = 0;

    instrucoes[12].nome = "fconst_1";
    instrucoes[12].bytes = 0;

    instrucoes[13].nome = "fconst_2";
    instrucoes[13].bytes = 0;

    instrucoes[14].nome = "dconst_0";
    instrucoes[14].bytes = 0;

    instrucoes[15].nome = "dconst_1";
    instrucoes[15].bytes = 0;

    instrucoes[16].nome = "bipush";
    instrucoes[16].bytes = 1;

    instrucoes[17].nome = "sipush";
    instrucoes[17].bytes = 2;

    instrucoes[18].nome = "ldc";
    instrucoes[18].bytes = 1;

    instrucoes[19].nome = "ldc_w";
    instrucoes[19].bytes = 2;

    instrucoes[20].nome = "ldc2_w";
    instrucoes[20].bytes = 2;

    instrucoes[21].nome = "iload";
    instrucoes[21].bytes = 1;

    instrucoes[22].nome = "lload";
    instrucoes[22].bytes = 1;

    instrucoes[23].nome = "fload";
    instrucoes[23].bytes = 1;

    instrucoes[24].nome = "dload";
    instrucoes[24].bytes = 1;

    instrucoes[25].nome = "aload";
    instrucoes[25].bytes = 1;

    instrucoes[26].nome = "iload_0";
    instrucoes[26].bytes = 0;

    instrucoes[27].nome = "iload_1";
    instrucoes[27].bytes = 0;

    instrucoes[28].nome = "iload_2";
    instrucoes[28].bytes = 0;

    instrucoes[29].nome = "iload_3";
    instrucoes[29].bytes = 0;

    instrucoes[30].nome = "lload_0";
    instrucoes[30].bytes = 0;

    instrucoes[31].nome = "lload_1";
    instrucoes[31].bytes = 0;

    instrucoes[32].nome = "lload_2";
    instrucoes[32].bytes = 0;

    instrucoes[33].nome = "lload_3";
    instrucoes[33].bytes = 0;

    instrucoes[34].nome = "fload_0";
    instrucoes[34].bytes = 0;

    instrucoes[35].nome = "fload_1";
    instrucoes[35].bytes = 0;

    instrucoes[36].nome = "fload_2";
    instrucoes[36].bytes = 0;

    instrucoes[37].nome = "fload_3";
    instrucoes[37].bytes = 0;

    instrucoes[38].nome = "dload_0";
    instrucoes[38].bytes = 0;

    instrucoes[39].nome = "dload_1";
    instrucoes[39].bytes = 0;

    instrucoes[40].nome = "dload_2";
    instrucoes[40].bytes = 0;

    instrucoes[41].nome = "dload_3";
    instrucoes[41].bytes = 0;

    instrucoes[42].nome = "aload_0";
    instrucoes[42].bytes = 0;

    instrucoes[43].nome = "aload_1";
    instrucoes[43].bytes = 0;

    instrucoes[44].nome = "aload_2";
    instrucoes[44].bytes = 0;

    instrucoes[45].nome = "aload_3";
    instrucoes[45].bytes = 0;

    instrucoes[46].nome = "iaload";
    instrucoes[46].bytes = 0;

    instrucoes[47].nome = "laload";
    instrucoes[47].bytes = 0;

    instrucoes[48].nome = "faload";
    instrucoes[48].bytes = 0;

    instrucoes[49].nome = "daload";
    instrucoes[49].bytes = 0;

    instrucoes[50].nome = "aaload";
    instrucoes[50].bytes = 0;

    instrucoes[51].nome = "baload";
    instrucoes[51].bytes = 0;

    instrucoes[52].nome = "caload";
    instrucoes[52].bytes = 0;

    instrucoes[53].nome = "saload";
    instrucoes[53].bytes = 0;

    instrucoes[54].nome = "istore";
    instrucoes[54].bytes = 1;

    instrucoes[55].nome = "lstore";
    instrucoes[55].bytes = 1;

    instrucoes[56].nome = "fstore";
    instrucoes[56].bytes = 1;

    instrucoes[57].nome = "dstore";
    instrucoes[57].bytes = 1;

    instrucoes[58].nome = "astore";
    instrucoes[58].bytes = 1;

    instrucoes[59].nome = "istore_0";
    instrucoes[59].bytes = 0;

    instrucoes[60].nome = "istore_1";
    instrucoes[60].bytes = 0;

    instrucoes[61].nome = "istore_2";
    instrucoes[61].bytes = 0;

    instrucoes[62].nome = "istore_3";
    instrucoes[62].bytes = 0;

    instrucoes[63].nome = "lstore_0";
    instrucoes[63].bytes = 0;

    instrucoes[64].nome = "lstore_1";
    instrucoes[64].bytes = 0;

    instrucoes[65].nome = "lstore_2";
    instrucoes[65].bytes = 0;

    instrucoes[66].nome = "lstore_3";
    instrucoes[66].bytes = 0;

    instrucoes[67].nome = "fstore_0";
    instrucoes[67].bytes = 0;

    instrucoes[68].nome = "fstore_1";
    instrucoes[68].bytes = 0;

    instrucoes[69].nome = "fstore_2";
    instrucoes[69].bytes = 0;

    instrucoes[70].nome = "fstore_3";
    instrucoes[70].bytes = 0;

    instrucoes[71].nome = "dstore_0";
    instrucoes[71].bytes = 0;

    instrucoes[72].nome = "dstore_1";
    instrucoes[72].bytes = 0;

    instrucoes[73].nome = "dstore_2";
    instrucoes[73].bytes = 0;

    instrucoes[74].nome = "dstore_3";
    instrucoes[74].bytes = 0;

    instrucoes[75].nome = "astore_0";
    instrucoes[75].bytes = 0;

    instrucoes[76].nome = "astore_1";
    instrucoes[76].bytes = 0;

    instrucoes[77].nome = "astore_2";
    instrucoes[77].bytes = 0;

    instrucoes[78].nome = "astore_3";
    instrucoes[78].bytes = 0;

    instrucoes[79].nome = "iastore";
    instrucoes[79].bytes = 0;

    instrucoes[80].nome = "lastore";
    instrucoes[80].bytes = 0;

    instrucoes[81].nome = "fastore";
    instrucoes[81].bytes = 0;

    instrucoes[82].nome = "dastore";
    instrucoes[82].bytes = 0;

    instrucoes[83].nome = "aastore";
    instrucoes[83].bytes = 0;

    instrucoes[84].nome = "bastore";
    instrucoes[84].bytes = 0;

    instrucoes[85].nome = "castore";
    instrucoes[85].bytes = 0;

    instrucoes[86].nome = "sastore";
    instrucoes[86].bytes = 0;

    instrucoes[87].nome = "pop";
    instrucoes[87].bytes = 0;

    instrucoes[88].nome = "pop2";
    instrucoes[88].bytes = 0;

    instrucoes[89].nome = "dup";
    instrucoes[89].bytes = 0;

    instrucoes[90].nome = "dup_x1";
    instrucoes[90].bytes = 0;

    instrucoes[91].nome = "dup_x2";
    instrucoes[91].bytes = 0;

    instrucoes[92].nome = "dup2";
    instrucoes[92].bytes = 0;

    instrucoes[93].nome = "dup2_x1";
    instrucoes[93].bytes = 0;

    instrucoes[94].nome = "dup2_x2";
    instrucoes[94].bytes = 0;

    instrucoes[95].nome = "swap";
    instrucoes[95].bytes = 0;

    instrucoes[96].nome = "iadd";
    instrucoes[96].bytes = 0;

    instrucoes[97].nome = "ladd";
    instrucoes[97].bytes = 0;

    instrucoes[98].nome = "fadd";
    instrucoes[98].bytes = 0;

    instrucoes[99].nome = "dadd";
    instrucoes[99].bytes = 0;

    instrucoes[100].nome = "isub";
    instrucoes[100].bytes = 0;

    instrucoes[101].nome = "lsub";
    instrucoes[101].bytes = 0;

    instrucoes[102].nome = "fsub";
    instrucoes[102].bytes = 0;

    instrucoes[103].nome = "dsub";
    instrucoes[103].bytes = 0;

    instrucoes[104].nome = "imul";
    instrucoes[104].bytes = 0;

    instrucoes[105].nome = "lmul";
    instrucoes[105].bytes = 0;

    instrucoes[106].nome = "fmul";
    instrucoes[106].bytes = 0;

    instrucoes[107].nome = "dmul";
    instrucoes[107].bytes = 0;

    instrucoes[108].nome = "idiv";
    instrucoes[108].bytes = 0;

    instrucoes[109].nome = "ldiv";
    instrucoes[109].bytes = 0;

    instrucoes[110].nome = "fdiv";
    instrucoes[110].bytes = 0;

    instrucoes[111].nome = "ddiv";
    instrucoes[111].bytes = 0;

    instrucoes[112].nome = "irem";
    instrucoes[112].bytes = 0;

    instrucoes[113].nome = "lrem";
    instrucoes[113].bytes = 0;

    instrucoes[114].nome = "frem";
    instrucoes[114].bytes = 0;

    instrucoes[115].nome = "drem";
    instrucoes[115].bytes = 0;

    instrucoes[116].nome = "ineg";
    instrucoes[116].bytes = 0;

    instrucoes[117].nome = "lneg";
    instrucoes[117].bytes = 0;

    instrucoes[118].nome = "fneg";
    instrucoes[118].bytes = 0;

    instrucoes[119].nome = "dneg";
    instrucoes[119].bytes = 0;

    instrucoes[120].nome = "ishl";
    instrucoes[120].bytes = 0;

    instrucoes[121].nome = "lshl";
    instrucoes[121].bytes = 0;

    instrucoes[122].nome = "ishr";
    instrucoes[122].bytes = 0;

    instrucoes[123].nome = "lshr";
    instrucoes[123].bytes = 0;

    instrucoes[124].nome = "iushr";
    instrucoes[124].bytes = 0;

    instrucoes[125].nome = "lushr";
    instrucoes[125].bytes = 0;

    instrucoes[126].nome = "iand";
    instrucoes[126].bytes = 0;

    instrucoes[127].nome = "land";
    instrucoes[127].bytes = 0;

    instrucoes[128].nome = "ior";
    instrucoes[128].bytes = 0;

    instrucoes[129].nome = "lor";
    instrucoes[129].bytes = 0;

    instrucoes[130].nome = "ixor";
    instrucoes[130].bytes = 0;

    instrucoes[131].nome = "lxor";
    instrucoes[131].bytes = 0;

    instrucoes[132].nome = "iinc";
    instrucoes[132].bytes = 2;

    instrucoes[133].nome = "i2l";
    instrucoes[133].bytes = 0;

    instrucoes[134].nome = "i2f";
    instrucoes[134].bytes = 0;

    instrucoes[135].nome = "i2d";
    instrucoes[135].bytes = 0;

    instrucoes[136].nome = "l2i";
    instrucoes[136].bytes = 0;

    instrucoes[137].nome = "l2f";
    instrucoes[137].bytes = 0;

    instrucoes[138].nome = "l2d";
    instrucoes[138].bytes = 0;

    instrucoes[139].nome = "f2i";
    instrucoes[139].bytes = 0;

    instrucoes[140].nome = "f2l";
    instrucoes[140].bytes = 0;

    instrucoes[141].nome = "f2d";
    instrucoes[141].bytes = 0;

    instrucoes[142].nome = "d2i";
    instrucoes[142].bytes = 0;

    instrucoes[143].nome = "d2l";
    instrucoes[143].bytes = 0;

    instrucoes[144].nome = "d2f";
    instrucoes[144].bytes = 0;

    instrucoes[145].nome = "i2b";
    instrucoes[145].bytes = 0;

    instrucoes[146].nome = "i2c";
    instrucoes[146].bytes = 0;

    instrucoes[147].nome = "i2s";
    instrucoes[147].bytes = 0;

    instrucoes[148].nome = "lcmp";
    instrucoes[148].bytes = 0;

    instrucoes[149].nome = "fcmpl";
    instrucoes[149].bytes = 0;

    instrucoes[150].nome = "fcmpg";
    instrucoes[150].bytes = 0;

    instrucoes[151].nome = "dcmpl";
    instrucoes[151].bytes = 0;

    instrucoes[152].nome = "dcmpg";
    instrucoes[152].bytes = 0;

    instrucoes[153].nome = "ifeq";
    instrucoes[153].bytes = 2;

    instrucoes[154].nome = "ifne";
    instrucoes[154].bytes = 2;

    instrucoes[155].nome = "iflt";
    instrucoes[155].bytes = 2;

    instrucoes[156].nome = "ifge";
    instrucoes[156].bytes = 2;

    instrucoes[157].nome = "ifgt";
    instrucoes[157].bytes = 2;

    instrucoes[158].nome = "ifle";
    instrucoes[158].bytes = 2;

    instrucoes[159].nome = "if_icmpeq";
    instrucoes[159].bytes = 2;

    instrucoes[160].nome = "if_icmpne";
    instrucoes[160].bytes = 2;

    instrucoes[161].nome = "if_icmplt";
    instrucoes[161].bytes = 0;

    instrucoes[162].nome = "if_icmpge";
    instrucoes[162].bytes = 0;

    instrucoes[163].nome = "if_icmpgt";
    instrucoes[163].bytes = 0;

    instrucoes[164].nome = "if_icmple";
    instrucoes[164].bytes = 0;

    instrucoes[165].nome = "if_acmpeq";
    instrucoes[165].bytes = 2;

    instrucoes[166].nome = "if_acmpne";
    instrucoes[166].bytes = 2;

    instrucoes[167].nome = "goto";
    instrucoes[167].bytes = 2;

    instrucoes[168].nome = "jsr";
    instrucoes[168].bytes = 2;

    instrucoes[169].nome = "ret";
    instrucoes[169].bytes = 1;

    instrucoes[170].nome = "tableswitch";

    instrucoes[170].bytes = 14;

    instrucoes[171].nome = "lookupswitch";

    instrucoes[171].bytes = 10;

    instrucoes[172].nome = "ireturn";
    instrucoes[172].bytes = 0;

    instrucoes[173].nome = "lreturn";
    instrucoes[173].bytes = 0;

    instrucoes[174].nome = "freturn";
    instrucoes[174].bytes = 0;

    instrucoes[175].nome = "dreturn";
    instrucoes[176].bytes = 0;

    instrucoes[176].nome = "areturn";
    instrucoes[176].bytes = 0;

    instrucoes[177].nome = "return";
    instrucoes[177].bytes = 0;

    instrucoes[178].nome = "getstatic";
    instrucoes[178].bytes = 2;

    instrucoes[179].nome = "putstatic";
    instrucoes[179].bytes = 2;

    instrucoes[180].nome = "getfield";
    instrucoes[180].bytes = 2;

    instrucoes[181].nome = "putfield";
    instrucoes[181].bytes = 2;

    instrucoes[182].nome = "invokevirtual";
    instrucoes[182].bytes = 2;

    instrucoes[183].nome = "invokespecial";
    instrucoes[183].bytes = 2;

    instrucoes[184].nome = "invokestatic";
    instrucoes[184].bytes = 2;

    instrucoes[185].nome = "invokeinterface";
    instrucoes[185].bytes = 4;

    instrucoes[186].nome = "invokedynamic";
    instrucoes[186].bytes = 4;

    instrucoes[187].nome = "new";
    instrucoes[187].bytes = 2;

    instrucoes[188].nome = "newarray";
    instrucoes[188].bytes = 1;

    instrucoes[189].nome = "anewarray";
    instrucoes[189].bytes = 2;

    instrucoes[190].nome = "arraylength";
    instrucoes[190].bytes = 0;

    instrucoes[191].nome = "athrow";
    instrucoes[191].bytes = 0;

    instrucoes[192].nome = "checkcast";
    instrucoes[192].bytes = 2;

    instrucoes[193].nome = "instanceof";
    instrucoes[193].bytes = 2;

    instrucoes[194].nome = "monitorenter";
    instrucoes[194].bytes = 0;

    instrucoes[195].nome = "monitorexit";
    instrucoes[195].bytes = 0;

    instrucoes[196].nome = "wide";

    instrucoes[196].bytes = 3;

    instrucoes[197].nome = "multianewarray";
    instrucoes[197].bytes = 3;

    instrucoes[198].nome = "ifnull";
    instrucoes[198].bytes = 2;

    instrucoes[199].nome = "ifnonnull";
    instrucoes[199].bytes = 2;

    instrucoes[200].nome = "goto_w";
    instrucoes[200].bytes = 4;

    instrucoes[201].nome = "jsr_w";
    instrucoes[201].bytes = 4;

    instrucoes[202].nome = "breakpoint";
    instrucoes[202].bytes = 0;

    instrucoes[254].nome = "impdep1";
    instrucoes[254].bytes = 0;

    instrucoes[255].nome = "impdep2";
    instrucoes[255].bytes = 0;
}

void nop(){
    Frame* frame_atual = get_frame_atual();
    atualiza_pc();
}

void aconst_null(){
    Frame* frame_atual = get_frame_atual();

    push_pilha_operandos(0);

	atualiza_pc();
}

void iconst_m1(){
    Frame* frame_atual = get_frame_atual();

    push_pilha_operandos(-1);

    atualiza_pc();
}

void iconst_0(){
    Frame* frame_atual = get_frame_atual();

	push_pilha_operandos((int32_t) 0);

	atualiza_pc();
}

void iconst_1(){
    Frame* frame_atual = get_frame_atual();

    push_pilha_operandos(1);

    atualiza_pc();
}

void iconst_2(){
    Frame* frame_atual = get_frame_atual();

    push_pilha_operandos(2);

    atualiza_pc();
}

void iconst_3(){
    Frame* frame_atual = get_frame_atual();

    push_pilha_operandos(3);

    atualiza_pc();
}

void iconst_4(){
    Frame* frame_atual = get_frame_atual();

    push_pilha_operandos(4);

    atualiza_pc();
}

void iconst_5(){
    Frame* frame_atual = get_frame_atual();

    push_pilha_operandos(5);

    atualiza_pc();
}

void lconst_0(){
    push_pilha_operandos(0);
    push_pilha_operandos(0);

    atualiza_pc();
}

void lconst_1(){
    push_pilha_operandos(0);
    push_pilha_operandos(1);

    get_frame_atual()->pc++;
}

// void fconst_0(){
//     char* tipo = "F";
//     tipoGlobal = tipo;

// 	int32_t* valPilha;

// 	float valF = 0.0;

// 	valPilha = (int32_t*) malloc(sizeof(int32_t));

// 	memcpy(valPilha, &valF, sizeof(int32_t));

// 	push_pilha_operandos(*valPilha);

// 	atualizaPc();
// }

// void fconst_1(){
//     char* tipo = "F";
//     tipoGlobal = tipo;

// 	int32_t* valPilha;

// 	float valF = 1.0;

// 	valPilha = (int32_t*) malloc(sizeof(int32_t));

// 	memcpy(valPilha, &valF, sizeof(int32_t));

// 	push_pilha_operandos(*valPilha);

// 	atualizaPc();
// }

// void fconst_2(){
//     char* tipo = "F";
//     tipoGlobal = tipo;

// 	int32_t* valPilha;

// 	float valF = 2.0;

// 	valPilha = (int32_t*) malloc(sizeof(int32_t));

// 	memcpy(valPilha, &valF, sizeof(int32_t));

// 	push_pilha_operandos(*valPilha);

// 	atualizaPc();
// }

// void dconst_0(){
//     char* tipo = "D";
//     tipoGlobal = tipo;

//     double double0 = 0.0; 
//     int64_t temp; 
//     int32_t parte_alta;
//     int32_t parte_baixa;

// 	memcpy(&temp, &double0, sizeof(int64_t));

// 	parte_alta = temp >> 32;
// 	parte_baixa = temp & 0xffffffff;

//     push_pilha_operandos(parte_alta);
//     push_pilha_operandos(parte_baixa);

//     get_frame_atual()->pc++;
// }

// void dconst_1(){
//     char* tipo = "D";
//     tipoGlobal = tipo;

//     double double1 = 1.0; 
//     int64_t temp; 
//     int32_t parte_alta;
//     int32_t parte_baixa;

// 	memcpy(&temp, &double1, sizeof(int64_t));

// 	parte_alta = temp >> 32;
// 	parte_baixa = temp & 0xffffffff;

//     push_pilha_operandos(parte_alta);
//     push_pilha_operandos(parte_baixa);

//     get_frame_atual()->pc++;
// }

// void bipush_pilha_operandos(){
// 	int8_t argumento = (int8_t) get_frame_atual()->code[get_frame_atual()->pc + 1];

// 	push_pilha_operandos((int32_t)argumento);

// 	atualizaPc();
// }

// void sipush_pilha_operandos(){
//     int32_t byte1, byte2;
//     int32_t valor; 
//     int16_t short_temp;

// 	byte1 = get_frame_atual()->code[(get_frame_atual()->pc + 1)];

// 	byte2 = get_frame_atual()->code[(get_frame_atual()->pc + 2)];

//     short_temp = (byte1 << 8) + byte2;
//     valor = (int32_t) short_temp;

//     push_pilha_operandos(valor);
//     atualizaPc();
// }

// void ldc(){
//     uint32_t indice;
//     tipoGlobal = NULL;

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     if (get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_Float || \
//             get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_Integer)
//     {

//         if (get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_Float)
//         {
//             push_pilha_operandos(get_frame_atual()->constant_pool[indice - 1].info.Float.bytes);
//         }
//         else
//         {
//             push_pilha_operandos(get_frame_atual()->constant_pool[indice - 1].info.Integer.bytes);
//         }
//     }

//     else if (get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_String) 
//     {
//         uint32_t indice_utf;
//         indice_utf = obtem_utf_eq(get_frame_atual()->constant_pool, indice-1); 
//         push_pilha_operandos(indice_utf);
//     }

//     else if (get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_String) 
//     {

//         printf("a implementar\n");
//         exit(1);
//     }

//     else
//     {
//         printf("erro na instrucao ldc\n");
//         exit(1);
//     }

//     atualizaPc();
// }

// void ldc_w(){
//     uint32_t indice;

// 	inicializa_decodificador(dec); 
// 	int num_bytes = dec[get_frame_atual()->code[get_frame_atual()->pc]].bytes;

//     indice = (get_frame_atual()->code[get_frame_atual()->pc + 1] << 8 + get_frame_atual()->code[get_frame_atual()->pc + 2]);

//     if (get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_Float || \
//             get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_Integer)
//     {

//         if (get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_Float)
//         {
//             push_pilha_operandos(get_frame_atual()->constant_pool[indice - 1].info.Float.bytes);
//         }
//         else
//         {
//             push_pilha_operandos(get_frame_atual()->constant_pool[indice - 1].info.Integer.bytes);
//         }
//     }

//     else if (get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_String) 
//     {
//         uint32_t indice_utf;
//         indice_utf = obtem_utf_eq(get_frame_atual()->constant_pool, indice-1); 
//         push_pilha_operandos(indice_utf);
//     }

//     else if (get_frame_atual()->constant_pool[indice - 1].tag == CONSTANT_String) 
//     {

//     }

//     else
//     {
//         printf("erro na instrucao ldc\n");
//         exit(1);
//     }

// 	for(int8_t i = 0; i < num_bytes + 1; i++)
// 		get_frame_atual()->pc++;

// }

// void ldc2_w(){

// 	uint8_t indice = get_frame_atual()->code[get_frame_atual()->pc + 2];

// 	uint8_t tag = (get_frame_atual()->constant_pool[indice-1]).tag;

// 	if(tag == 5){
// 		uint32_t alta = get_frame_atual()->constant_pool[indice-1].info.Long.high_bytes;
// 		uint32_t baixa = get_frame_atual()->constant_pool[indice-1].info.Long.low_bytes;
// 		push_pilha_operandos(alta);
// 		push_pilha_operandos(baixa);
// 	}

// 	if(tag == 6){
// 		uint32_t alta = get_frame_atual()->constant_pool[indice-1].info.Double.high_bytes;
// 		uint32_t baixa = get_frame_atual()->constant_pool[indice-1].info.Double.low_bytes;
// 		push_pilha_operandos(alta);
// 		push_pilha_operandos(baixa);
// 	}

// 	atualizaPc();
//     foi_lneg = false;

// }

// void iload(){

//     char* tipo = "I";
//     tipoGlobal = tipo;

// 	int32_t argumento = (int32_t) get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	int32_t aux = get_frame_atual()->fields[argumento];
// 	push_pilha_operandos(aux);

// 	atualizaPc();

// }

// void lload(){
// 	char* tipo = "L";
//     tipoGlobal = tipo;

//     int32_t indice;
//     int32_t parte_alta, parte_baixa;

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();

// }

// void fload(){

// 	char* tipo = "F";
//     tipoGlobal = tipo;

//     int32_t indice, valor; 

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);

//     atualizaPc();
// }

// void dload(){

//     int32_t indice;
//     int32_t parte_alta, parte_baixa;
//     char* tipo = "D";
//     tipoGlobal = tipo;

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();
// }

// void aload(){

//     int32_t indice, valor; 

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);

//     atualizaPc();

// }

// void iload_0(){

// 	char* tipo = "I";
//     tipoGlobal = tipo;

//     int32_t valor;

//     valor = get_frame_atual()->fields[0];

//     push_pilha_operandos(valor);

// 	atualizaPc();
// }

// void iload_1(){
// 	char* tipo = "I";
//     tipoGlobal = tipo;

//     int32_t valor;

//     valor = get_frame_atual()->fields[1];

//     push_pilha_operandos(valor);
//     atualizaPc();
// }

// void iload_2(){

// 	char* tipo = "I";
//     tipoGlobal = tipo;

//     int32_t valor;

//     valor = get_frame_atual()->fields[2];

//     push_pilha_operandos(valor);

//     atualizaPc();
// }

// void iload_3(){

//     int32_t valor;
//     char* tipo = "I";
//     tipoGlobal = tipo;

//     valor = get_frame_atual()->fields[3];

//     push_pilha_operandos(valor);

//     atualizaPc();

// }

// void lload_0(){

// 	char* tipo = "L";
//     tipoGlobal = tipo;

//     int32_t indice;
//     int32_t parte_alta, parte_baixa;

//     indice = 0;

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

// 	atualizaPc();

// }

// void lload_1(){
//     int32_t indice;
//     int32_t parte_alta, parte_baixa;

//     char* tipo = "L";
//     tipoGlobal = tipo;

//     indice = 1;

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();

// }

// void lload_2(){

// 	char* tipo = "L";
//     tipoGlobal = tipo;

//     int32_t indice;
//     int32_t parte_alta, parte_baixa;

//     indice = 2;

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();

// }

// void lload_3(){

// 	char* tipo = "L";
//     tipoGlobal = tipo;

//     int32_t indice;
//     int32_t parte_alta, parte_baixa;

//     indice = 3;

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();

// }

// void fload_0(){

// 	char* tipo = "F";
//     tipoGlobal = tipo;

//     int32_t indice, valor; 

//     indice = 0; 

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);

//    atualizaPc();

// }

// void fload_1(){

// 	char* tipo = "F";
//     tipoGlobal = tipo;

//     int32_t indice, valor; 

//     indice = 1; 

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);

//     atualizaPc();

// }

// void fload_2(){

// 	char* tipo = "F";
//     tipoGlobal = tipo;

//     int32_t indice, valor; 

//     indice = 2; 

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);

//     atualizaPc();

// }

// void fload_3(){

// 	char* tipo = "F";
//     tipoGlobal = tipo;

//     int32_t indice, valor; 

//     indice = 3; 

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);

//     atualizaPc();

// }

// void dload_0(){

// 	char* tipo = "D";
//     tipoGlobal = tipo;

//     int32_t indice;
//     int32_t parte_alta, parte_baixa;

//     indice = 0; 

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();

// }

// void dload_1(){
//     int32_t indice;
//     int32_t parte_alta, parte_baixa;

//     char* tipo = "D";
//     tipoGlobal = tipo;

//     indice = 1; 

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();

// }

// void dload_2(){
//     int32_t indice;
//     int32_t parte_alta, parte_baixa;
//     char* tipo = "D";
//     tipoGlobal = tipo;

//     indice = 2; 

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();

// }

// void dload_3(){
//     int32_t indice;
//     int32_t parte_alta, parte_baixa;

//     char* tipo = "D";
//     tipoGlobal = tipo;

//     indice = 3; 

//     parte_alta = get_frame_atual()->fields[indice + POS_ALTA];
//     push_pilha_operandos(parte_alta);

//     parte_baixa = get_frame_atual()->fields[indice + POS_BAIXA];
//     push_pilha_operandos(parte_baixa);

//     atualizaPc();

// }

// void aload_0(){

// 	push_pilha_operandos(get_frame_atual()->fields[0]);
// 	atualizaPc();
// }

// void aload_1(){
//     int32_t indice, valor; 

//     indice = 1; 

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);
//     atualizaPc();
// }

// void aload_2(){
//     int32_t indice, valor; 

//     indice = 2; 

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);

//    atualizaPc();
// }

// void aload_3(){
//     int32_t indice, valor; 

//     indice = 3; 

//     valor = get_frame_atual()->fields[indice];
//     push_pilha_operandos(valor);

//     atualizaPc();

// }

// void iaload(){

// 	int32_t* referencia;

// 	int32_t indice = pop_op();

// 	referencia = (int32_t*)pop_op();

// 	push_pilha_operandos(referencia[indice]);

// 	atualizaPc();
// }

// void laload(){
// 	static int16_t countPos = 0;
// 	char* tipo = "L";
//     tipoGlobal = tipo;

// 	int32_t indice = pop_op();

// 	int32_t* referencia;
// 	referencia = (int32_t*)pop_op();

// 	push_pilha_operandos(referencia[countPos + indice+1]);
// 	push_pilha_operandos(referencia[countPos + indice]);
// 	countPos += 2;
// 	atualizaPc();
// }

// void faload(){
// 	char* tipo = "F";
//     tipoGlobal = tipo;

// 	int32_t* referencia;

// 	int32_t indice = pop_op();

// 	referencia = (int32_t*)pop_op();

// 	int32_t valPilha;
// 	memcpy(&valPilha, &((float *)referencia)[indice], sizeof(int32_t));
// 	push_pilha_operandos(valPilha);

// 	atualizaPc();
// }

// void daload(){
// 	static int16_t countPos = 0;
// 	char* tipo = "D";
//     tipoGlobal = tipo;

// 	int32_t indice = pop_op();

// 	int32_t* referencia;
// 	referencia = (int32_t*)pop_op();

// 	push_pilha_operandos(referencia[countPos + indice+1]);
// 	push_pilha_operandos(referencia[countPos + indice]);
// 	countPos += 2;
// 	atualizaPc();
// }

// void aaload(){

// 	int32_t* referencia;

// 	int32_t indice = pop_op();

// 	referencia = (int32_t*)pop_op();

// 	push_pilha_operandos(referencia[indice]);

// 	atualizaPc();
// }

// void baload(){

// 	int32_t* referencia;

// 	int32_t indice = pop_op();

// 	referencia = (int32_t*)pop_op();
// 	int8_t* binary = (int8_t*)referencia[indice];

// 	push_pilha_operandos((int32_t)binary);

// 	atualizaPc();
// }

// void caload(){
// 	char* tipo = "C";
//     tipoGlobal = tipo;

// 	int32_t* referencia;

// 	int32_t indice = pop_op();

// 	referencia = (int32_t*)pop_op();
// 	int16_t* binary = (int16_t*)referencia[indice];

// 	push_pilha_operandos((int32_t)binary);

// 	atualizaPc();
// }

// void saload(){

// 	int32_t* referencia;

// 	int32_t indice = pop_op();

// 	referencia = (int32_t*)pop_op();
// 	int16_t* binary = (int16_t*)referencia[indice];

// 	push_pilha_operandos((int32_t)binary);

// 	atualizaPc();
// }

// void istore(){

//     int32_t indice; 
//     int32_t valor; 

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();
// }

// void lstore(){

//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();
// }

// void fstore(){

//     int32_t indice; 
//     int32_t valor; 

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();
// }

// void dstore(){
//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();
// }

// void astore(){

//     int32_t indice; 
//     int32_t valor; 

//     indice = get_frame_atual()->code[get_frame_atual()->pc + 1];

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();
// }

// void istore_0(){

//     int32_t indice; 
//     int32_t valor; 

//     indice = 0;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();
// }

// void istore_1(){
//     uint32_t valor; 

//     valor = pop_op();

//     get_frame_atual()->fields[1] = valor;

//     atualizaPc();
// }

// void istore_2(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 2;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();
// }

// void istore_3(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 3;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();
// }

// void lstore_0(){

//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = 0;

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();
// }

// void lstore_1(){
//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = 1;

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();
// }

// void lstore_2(){
//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = 2;

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();
// }

// void lstore_3(){
//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = 3;

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();
// }

// void fstore_0(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 0;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();

// }

// void fstore_1(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 1;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();
// }

// void fstore_2(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 2;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();

// }

// void fstore_3(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 3;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();

// }

// void dstore_0(){
//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = 0;

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();
// }

// void dstore_1(){
//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = 1;

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();

// }

// void dstore_2(){
//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = 2;

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();

// }

// void dstore_3(){
//     int32_t indice; 
//     int32_t parte_alta, parte_baixa; 

//     indice = 3;

//     parte_baixa = pop_op();

//     parte_alta = pop_op();

//     get_frame_atual()->fields[indice + POS_ALTA] = parte_alta;
//     get_frame_atual()->fields[indice + POS_BAIXA] = parte_baixa;

//     atualizaPc();

// }

// void astore_0(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 0;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();

// }

// void astore_1(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 1;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();

// }

// void astore_2(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 2;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();

// }

// void astore_3(){
//     int32_t indice; 
//     int32_t valor; 

//     indice = 3;

//     valor = pop_op(); 

//     get_frame_atual()->fields[indice] = valor; 

//     atualizaPc();

// }

// void iastore(){

// 	int32_t* ref;
// 	int32_t indice,valor;

// 	valor = pop_op();

// 	indice = pop_op();

// 	ref = (int32_t*)pop_op();

// 	ref[indice] = valor;

// 	atualizaPc();
// }

// void lastore(){
// 	static int16_t countPos = 0;
// 	int32_t alta,baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int32_t indice = pop_op();

// 	int32_t* referencia;
// 	referencia = (int32_t*) pop_op();

// 	referencia[countPos + indice] = baixa;
// 	referencia[countPos + indice + 1] = alta;
// 	countPos += 2;
// 	atualizaPc();
// }

// void fastore(){
// 	char* tipo = "F";
//     tipoGlobal = tipo;

// 	int32_t* ref;
// 	int32_t indice,valor;

// 	valor = pop_op();

// 	indice = pop_op();

// 	ref = (int32_t*)pop_op();

// 	ref[indice] = valor;

// 	atualizaPc();
// }

// void dastore(){
// 	static int16_t countPos = 0;
// 	int32_t alta,baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int32_t indice = pop_op();

// 	int32_t* referencia;
// 	referencia = (int32_t*) pop_op();

// 	referencia[countPos + indice] = baixa;
// 	referencia[countPos + indice + 1] = alta;
// 	countPos += 2;
// 	atualizaPc();
// }

// void aastore(){

// 	int32_t* ref;
// 	int32_t indice,valor;

// 	valor = pop_op();

// 	indice = pop_op();

// 	ref = (int32_t*)pop_op();

// 	ref[indice] = valor;

// 	atualizaPc();
// }

// void bastore(){

// 	int32_t* ref;
// 	int32_t indice,valor;

// 	valor = pop_op();

// 	indice = pop_op();

// 	ref = (int32_t*)pop_op();

// 	ref[indice] = (int8_t)valor;

// 	atualizaPc();
// }

// void castore(){

// 	int32_t* ref;
// 	int32_t indice,valor;

// 	valor = pop_op();

// 	indice = pop_op();

// 	ref = (int32_t*)pop_op();

// 	ref[indice] = (int16_t)valor;

// 	atualizaPc();
// }

// void sastore(){

// 	int32_t* ref;
// 	int32_t indice,valor;

// 	valor = pop_op();

// 	indice = pop_op();

// 	ref = (int32_t*)pop_op();

// 	ref[indice] = (int16_t)valor;

// 	atualizaPc();
// }

// void pop(){
// 	pop_op();

// 	atualizaPc();
// }

// void pop2(){

// 	pop_op();
// 	pop_op();

// 	atualizaPc();
// }

// void dup(){
// 	int32_t retPilha;

// 	retPilha = pop_op();

// 	push_pilha_operandos(retPilha);
// 	push_pilha_operandos(retPilha);
// 	atualizaPc();
// }

// void dup_x1(){
// 	int32_t aux1, aux2;

// 	aux1 = pop_op();

// 	aux2 = pop_op();

// 	push_pilha_operandos(aux1);

// 	push_pilha_operandos(aux2);

// 	push_pilha_operandos(aux1);

// 	atualizaPc();
// }

// void dup_x2(){

// 	int32_t aux1, aux2, aux3;

// 	aux1 = pop_op();

// 	aux2 = pop_op();

// 	aux3 = pop_op();

// 	push_pilha_operandos(aux1);
// 	push_pilha_operandos(aux3);
// 	push_pilha_operandos(aux2);
// 	push_pilha_operandos(aux1);

// 	atualizaPc();

// }

// void dup2(){

// 	int32_t aux1, aux2, aux3;

// 	aux1 = pop_op();

// 	aux2 = pop_op();

// 	push_pilha_operandos(aux2);
// 	push_pilha_operandos(aux1);
// 	push_pilha_operandos(aux2);
// 	push_pilha_operandos(aux1);

// 	atualizaPc();
// }

// void dup2_x1(){

// 	int32_t aux1, aux2, aux3;

// 	aux1 = pop_op();

// 	aux2 = pop_op();

// 	aux3 = pop_op();

// 	push_pilha_operandos(aux2);
// 	push_pilha_operandos(aux1);
// 	push_pilha_operandos(aux3);
// 	push_pilha_operandos(aux2);
// 	push_pilha_operandos(aux1);

// 	atualizaPc();

// }

// void dup2_x2(){

// 	int32_t aux1, aux2, aux3, aux4;

// 	aux1 = pop_op();

// 	aux2 = pop_op();

// 	aux3 = pop_op();

// 	aux4 = pop_op();

// 	push_pilha_operandos(aux2);
// 	push_pilha_operandos(aux1);
// 	push_pilha_operandos(aux4);
// 	push_pilha_operandos(aux3);
// 	push_pilha_operandos(aux2);
// 	push_pilha_operandos(aux1);

// 	atualizaPc();
// }

// void swap(){
// 	int32_t val1,val2;

// 	val1 = pop_op();
// 	val2 = pop_op();

// 	push_pilha_operandos(val1);
// 	push_pilha_operandos(val2);

// 	atualizaPc();
// }

// void iadd(){
// 	int32_t v1,v2;
// 	v2 = pop_op();
// 	v1 = pop_op();

// 	push_pilha_operandos(v1+v2);

// 	atualizaPc();
// }

// void ladd(){
// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal1 = alta;

// 	lVal1 <<= 32;

// 	lVal1 = lVal1 + baixa;

// 	int64_t resultado = lVal1 + lVal;

// 	alta = resultado >> 32;
// 	baixa = resultado & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void fadd(){
// 	float fVal1,fVal2;

// 	int32_t aux1 = pop_op();
// 	int32_t aux2 = pop_op();

// 	memcpy(&fVal1, &aux1, sizeof(int32_t));
// 	memcpy(&fVal2, &aux2, sizeof(int32_t));

// 	float resultado = fVal1 + fVal2;

// 	int32_t retPilha;
// 	memcpy(&retPilha, &resultado, sizeof(int32_t));

// 	push_pilha_operandos(retPilha);

// 	atualizaPc();

// }

// void dadd(){

// 	int32_t alta;
// 	int32_t baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double valorDouble1;
// 	memcpy(&valorDouble1, &dVal, sizeof(int64_t));

// 	baixa = pop_op();
// 	alta = pop_op();

// 	dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double valorDouble2;
// 	memcpy(&valorDouble2, &dVal, sizeof(int64_t));

// 	double doubleSomado = valorDouble1 + valorDouble2;

// 	int64_t valorPilha;
// 	memcpy(&valorPilha, &doubleSomado, sizeof(int64_t));

// 	alta = valorPilha >> 32;
// 	baixa = valorPilha & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void isub(){
// 	int32_t v1,v2;
// 	v2 = pop_op();
// 	v1 = pop_op();

// 	push_pilha_operandos(v1-v2);

// 	atualizaPc();

// }

// void lsub(){
// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal1 = alta;

// 	lVal1 <<= 32;

// 	lVal1 = lVal1 + baixa;

// 	int64_t resultado = lVal1 - lVal;

// 	alta = resultado >> 32;
// 	baixa = resultado & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void fsub(){
// 	float fVal1,fVal2;

// 	int32_t aux2 = pop_op();
// 	int32_t aux1 = pop_op();

// 	memcpy(&fVal1, &aux1, sizeof(int32_t));
// 	memcpy(&fVal2, &aux2, sizeof(int32_t));

// 	float resultado = fVal1 - fVal2;

// 	int32_t retPilha;
// 	memcpy(&retPilha, &resultado, sizeof(int32_t));

// 	push_pilha_operandos(retPilha);

// 	atualizaPc();
// }

// void dsub(){

// 	int32_t alta;
// 	int32_t baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double valorDouble1;
// 	memcpy(&valorDouble1, &dVal, sizeof(int64_t));

// 	baixa = pop_op();
// 	alta = pop_op();

// 	dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double valorDouble2;
// 	memcpy(&valorDouble2, &dVal, sizeof(int64_t));

// 	double doubleSubtraido = valorDouble2 - valorDouble1;

// 	int64_t valorPilha;
// 	memcpy(&valorPilha, &doubleSubtraido, sizeof(int64_t));

// 	alta = valorPilha >> 32;
// 	baixa = valorPilha & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void imul(){
// 	int32_t v1 = pop_op();
// 	int32_t v2 = pop_op();

// 	push_pilha_operandos((int32_t)(v1 * v2));

// 	atualizaPc();
// }

// void lmul(){

// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal1 = alta;

// 	lVal1 <<= 32;

// 	lVal1 = lVal1 + baixa;

// 	int64_t resultado = lVal1 * lVal;

// 	alta = resultado >> 32;
// 	baixa = resultado & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void fmul(){
// 	float fVal1,fVal2;

// 	int32_t aux1 = pop_op();
// 	int32_t aux2 = pop_op();

// 	memcpy(&fVal1, &aux1, sizeof(int32_t));
// 	memcpy(&fVal2, &aux2, sizeof(int32_t));

// 	float resultado = fVal1 * fVal2;

// 	int32_t retPilha;
// 	memcpy(&retPilha, &resultado, sizeof(int32_t));

// 	push_pilha_operandos(retPilha);

// 	atualizaPc();
// }

// void dmul(){

// 	int32_t alta;
// 	int32_t baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double valorDouble1;
// 	memcpy(&valorDouble1, &dVal, sizeof(int64_t));

// 	baixa = pop_op();
// 	alta = pop_op();

// 	dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double valorDouble2;
// 	memcpy(&valorDouble2, &dVal, sizeof(int64_t));

// 	double doubleMultiplicado = valorDouble1 * valorDouble2;

// 	int64_t valorPilha;
// 	memcpy(&valorPilha, &doubleMultiplicado, sizeof(int64_t));

// 	alta = valorPilha >> 32;
// 	baixa = valorPilha & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void idiv(){

// 	int32_t v2 = pop_op();
// 	int32_t v1 = pop_op();

// 	push_pilha_operandos((int32_t)(v1 / v2));

// 	atualizaPc();
// }

// void ins_ldiv(){
// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal1 = alta;

// 	lVal1 <<= 32;

// 	lVal1 = lVal1 + baixa;

// 	int64_t resultado = lVal1 / lVal;

// 	alta = resultado >> 32;
// 	baixa = resultado & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void fdiv(){
// 	float fVal1,fVal2;

// 	int32_t aux2 = pop_op();
// 	int32_t aux1 = pop_op();

// 	memcpy(&fVal1, &aux1, sizeof(int32_t));
// 	memcpy(&fVal2, &aux2, sizeof(int32_t));

// 	float resultado = fVal1 / fVal2;

// 	int32_t retPilha;
// 	memcpy(&retPilha, &resultado, sizeof(int32_t));

// 	push_pilha_operandos(retPilha);

// 	atualizaPc();
// }

// void ddiv(){

// 	int32_t alta,baixa,alta1,baixa1;

// 	baixa1 = pop_op();
// 	alta1 = pop_op();

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta1;

// 	dVal <<= 32;

// 	dVal = dVal + baixa1;

// 	double v1;
// 	memcpy(&v1, &dVal, sizeof(double));

// 	dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double v2;
// 	memcpy(&v2, &dVal, sizeof(double));

// 	double resultado = v2 / v1;

// 	int64_t pilhaVal;
// 	memcpy(&pilhaVal, &resultado, sizeof(int64_t));

// 	alta = pilhaVal >> 32;
// 	baixa = pilhaVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void irem(){

// 	int32_t v2 = pop_op();
// 	int32_t v1 = pop_op();

// 	push_pilha_operandos((int32_t)(v1 % v2));

// 	atualizaPc();
// }

// void lrem(){
// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal1 = alta;

// 	lVal1 <<= 32;

// 	lVal1 = lVal1 + baixa;

// 	int64_t resultado = lVal1 % lVal;

// 	alta = resultado >> 32;
// 	baixa = resultado & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void frem(){
// 	float fVal1,fVal2;

// 	int32_t aux2 = pop_op();
// 	int32_t aux1 = pop_op();

// 	memcpy(&fVal1, &aux1, sizeof(int32_t));
// 	memcpy(&fVal2, &aux2, sizeof(int32_t));

// 	float resultado = fmodf(fVal1,fVal2);

// 	int32_t retPilha;
// 	memcpy(&retPilha, &resultado, sizeof(int32_t));

// 	push_pilha_operandos(retPilha);

// 	atualizaPc();
// }

// void _drem(){

// 	int32_t alta,baixa,alta1,baixa1;

// 	baixa1 = pop_op();
// 	alta1 = pop_op();

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta1;

// 	dVal <<= 32;

// 	dVal = dVal + baixa1;

// 	double v1;
// 	memcpy(&v1, &dVal, sizeof(double));

// 	dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double v2;
// 	memcpy(&v2, &dVal, sizeof(double));

// 	double resultado = fmod(v2,v1);

// 	int64_t pilhaVal;
// 	memcpy(&pilhaVal, &resultado, sizeof(int64_t));

// 	alta = pilhaVal >> 32;
// 	baixa = pilhaVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();

// }

// void ineg(){

// 	int32_t retPilha = pop_op();

// 	int32_t aux = -retPilha;

// 	push_pilha_operandos(aux);

// 	atualizaPc();
// }

// void lneg(){
// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal | baixa;

// 	lVal = - lVal;

// 	alta = lVal >> 32;
// 	baixa = lVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
//     foi_lneg = true;
// }

// void fneg(){
// 	float fVal;

// 	int32_t retPilha = pop_op();

// 	memcpy(&fVal,&retPilha,sizeof(float));

// 	fVal = - fVal;

// 	memcpy(&retPilha,&fVal,sizeof(int32_t));

// 	push_pilha_operandos(retPilha);

// 	atualizaPc();
// }

// void dneg(){

// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double valorDouble1;
// 	memcpy(&valorDouble1, &dVal, sizeof(int64_t));

// 	valorDouble1 = - valorDouble1;

// 	memcpy(&dVal, &valorDouble1, sizeof(int64_t));

// 	alta = dVal >> 32;
// 	baixa = dVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void ishl(){

// 	int32_t shift = pop_op();
// 	shift = shift & 0x1f;

// 	int32_t sVal = pop_op();
// 	sVal = sVal << shift;
// 	push_pilha_operandos(sVal);

// 	atualizaPc();
// }

// void lshl(){

// 	int32_t shift = pop_op();
// 	shift = shift & 0x3f;

// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	lVal = lVal << shift;

// 	alta = lVal >> 32;
// 	baixa = lVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void ishr(){

// 	int32_t shift = pop_op();
// 	shift = shift & 0x1f;

// 	int32_t sVal = pop_op();

// 	int32_t i = 0;
// 	while(i < shift){
// 		sVal = sVal / 2;
// 		i += 1;
// 	}

// 	push_pilha_operandos(sVal);

// 	atualizaPc();
// }

// void lshr(){

//     int32_t v2 = pop_op();

// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();
// 	int64_t lVal = alta;
// 	lVal <<= 32;
// 	lVal = lVal + baixa;

//     lVal = lVal << v2;

// 	alta = lVal >> 32;
// 	baixa = lVal & 0xffffffff;
// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void iushr(){

// 	int32_t shift = pop_op();
// 	shift = shift & 0x1f;

// 	int32_t sVal = pop_op();
// 	sVal = sVal >> shift;
// 	push_pilha_operandos(sVal);

// 	atualizaPc();
// }

// void lushr(){

// 	int32_t shift = pop_op();
// 	shift = shift & 0x3f;

// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	lVal = lVal >> shift;

// 	alta = lVal >> 32;
// 	baixa = lVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void iand(){
// 	int32_t pop1 = pop_op();

// 	int32_t pop2 = pop_op();

// 	int32_t aux = pop1 & pop2;

// 	push_pilha_operandos(aux);

// 	get_frame_atual()->pc++;
// }

// void land(){
// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal1 = alta;

// 	lVal1 <<= 32;

// 	lVal1 = lVal1 + baixa;

// 	int64_t resultado = lVal1 & lVal;

// 	alta = resultado >> 32;
// 	baixa = resultado & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void ior(){
// 	int32_t pop1 = pop_op();

// 	int32_t pop2 = pop_op();

// 	int32_t aux = pop1 | pop2;

// 	push_pilha_operandos(aux);

// 	get_frame_atual()->pc++;

// }

// void lor(){
// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal1 = alta;

// 	lVal1 <<= 32;

// 	lVal1 = lVal1 + baixa;

// 	int64_t resultado = lVal1 | lVal;

// 	alta = resultado >> 32;
// 	baixa = resultado & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	inicializa_decodificador(dec);
// 	int num_bytes = dec[get_frame_atual()->code[get_frame_atual()->pc]].bytes;

// 	atualizaPc();
// }

// void ixor(){
// 	int32_t pop1 = pop_op();

// 	int32_t pop2 = pop_op();

// 	int32_t aux = pop1 ^ pop2;

// 	push_pilha_operandos(aux);

// 	get_frame_atual()->pc++;

// }

// void lxor(){
// 	int32_t baixa,alta;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal1 = alta;

// 	lVal1 <<= 32;

// 	lVal1 = lVal1 + baixa;

// 	int64_t resultado = lVal1 ^ lVal;

// 	alta = resultado >> 32;
// 	baixa = resultado & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void iinc(){

// 	int8_t field = get_frame_atual()->code[get_frame_atual()->pc + 1];

// 	int32_t value = get_frame_atual()->fields[field];

// 	int8_t constant = get_frame_atual()->code[get_frame_atual()->pc + 2];

// 	int8_t sumVal = (int8_t) value;
// 	sumVal = sumVal + constant;

// 	get_frame_atual()->fields[field] = (int32_t) sumVal;

// 	atualizaPc();
// }

// void i2l(){
//     char* tipo = "L";
//     tipoGlobal = tipo;
//     int32_t alta, baixa;

//     int32_t val = pop_op();

//     int64_t long_num = (int64_t) val;
// 	alta = long_num >> 32;
// 	baixa = long_num & 0xffffffff;

//     push_pilha_operandos(alta);
//     push_pilha_operandos(baixa);

//     atualizaPc();
// }

// void i2f(){
//     char* tipo = "F";
//     tipoGlobal = tipo;

// 	int32_t val = (int32_t) pop_op();

// 	float valF = (float) val;

// 	int32_t valPilha;
// 	memcpy(&valPilha, &valF, sizeof(int32_t));

// 	push_pilha_operandos(valPilha);

// 	atualizaPc();
// }

// void i2d(){
//     char* tipo = "D";
//     tipoGlobal = tipo;

// 	int32_t retPilha = pop_op();

// 	double dVal = (double) retPilha;

// 	int64_t pilhaVal;

// 	memcpy(&pilhaVal, &dVal, sizeof(int64_t));

// 	int32_t alta;
// 	int32_t baixa;

// 	alta = pilhaVal >> 32;

// 	baixa = pilhaVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void l2i(){
//     char* tipo = "I";
//     tipoGlobal = tipo;
// 	int32_t alta,baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	push_pilha_operandos(baixa);
// 	atualizaPc();
// }

// void l2f(){
//     char* tipo = "F";
//     tipoGlobal = tipo;

// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal | baixa;

// 	float fVal;
//     fVal = (float) lVal; 

// 	int32_t valPilha;
// 	memcpy(&valPilha, &fVal, sizeof(int32_t));

// 	push_pilha_operandos(valPilha);

// 	atualizaPc();
// }

// void l2d(){
//     char* tipo = "D";
//     tipoGlobal = tipo;

// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	double dVal;
// 	memcpy(&dVal, &lVal, sizeof(double));

// 	int64_t valorPilha;
// 	memcpy(&valorPilha, &dVal, sizeof(int64_t));

// 	alta = valorPilha >> 32;
// 	baixa = valorPilha & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void f2i(){
//     char* tipo = "I";
//     tipoGlobal = tipo;

// 	int32_t retPilha = pop_op();

// 	float fVal;
// 	memcpy(&fVal, &retPilha, sizeof(int32_t));
// 	push_pilha_operandos((int32_t)fVal);
// 	atualizaPc();
// }

// void f2l(){
//     char* tipo = "L";
//     tipoGlobal = tipo;

// 	int32_t retPilha = pop_op();
// 	float fVal;

// 	memcpy(&fVal, &retPilha, sizeof(int32_t));

// 	int64_t lVal = (int64_t) fVal;

// 	int32_t alta;
// 	int32_t baixa;

// 	alta = lVal >> 32;

// 	baixa = lVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void f2d(){
//     char* tipo = "D";
//     tipoGlobal = tipo;

// 	int32_t retPilha = pop_op();
// 	float fVal;

// 	memcpy(&fVal, &retPilha, sizeof(int32_t));

// 	double dVal = (double) fVal;

// 	int64_t pilhaVal;
// 	memcpy(&pilhaVal, &dVal, 2*sizeof(int32_t));

// 	int32_t alta;
// 	int32_t baixa;

// 	alta = pilhaVal >> 32;

// 	baixa = pilhaVal & 0xffffffff;

// 	push_pilha_operandos(alta);
// 	push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void d2i(){
//     char* tipo = "I";
//     tipoGlobal = tipo;

// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double v1;
// 	memcpy(&v1, &dVal, sizeof(double));

// 	push_pilha_operandos((int32_t)v1);
// 	atualizaPc();
// }

// void d2l(){
//     char* tipo = "L";
//     tipoGlobal = tipo;

// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double v1;
// 	memcpy(&v1, &dVal, sizeof(double));

//     int64_t long_num = (int64_t) v1;
// 	alta = long_num >> 32;
// 	baixa = long_num & 0xffffffff;

//     push_pilha_operandos(alta);
//     push_pilha_operandos(baixa);

// 	atualizaPc();
// }

// void d2f(){
//     char* tipo = "F";
//     tipoGlobal = tipo;

// 	int32_t alta,baixa;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double v1;
// 	memcpy(&v1, &dVal, sizeof(double));

// 	float fVal = (float) v1;

// 	int32_t pilhaVal;
// 	memcpy(&pilhaVal,&fVal,sizeof(float));

// 	push_pilha_operandos(pilhaVal);

// 	atualizaPc();
// }

// void i2b(){

// 	int32_t valPilha = pop_op();

// 	int8_t bVal = (int8_t) valPilha;

// 	push_pilha_operandos((int32_t) bVal);
// 	atualizaPc();
// }

// void i2c(){
//     char* tipo = "C";
//     tipoGlobal = tipo;

// 	int32_t valPilha = pop_op();

// 	int16_t cVal = (int16_t) valPilha;

// 	push_pilha_operandos((int32_t) cVal);
// 	atualizaPc();
// }

// void i2s(){

// 	int32_t valPilha = pop_op();

// 	int16_t cVal = (int16_t) valPilha;

// 	push_pilha_operandos((int32_t) cVal);
// 	atualizaPc();
// }

// void lcmp(){
// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal = alta;

// 	lVal <<= 32;

// 	lVal = lVal + baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t lVal2 = alta;

// 	lVal2 <<= 32;

// 	lVal2 = lVal2 + baixa;

// 	if(lVal2 == lVal){
// 		push_pilha_operandos((int32_t)0);
// 	}
// 	else if(lVal2 > lVal){
// 		push_pilha_operandos((int32_t)1);
// 	}
// 	else if(lVal2 < lVal){
// 		push_pilha_operandos((int32_t)-1);
// 	}

// 	atualizaPc();
// }

// void fcmpl(){

// 	float val1,val2;

// 	int32_t retPilha;

// 	retPilha = pop_op();

// 	memcpy(&val2,&retPilha,sizeof(float));

// 	retPilha = pop_op();

// 	memcpy(&val1,&retPilha,sizeof(float));

// 	if(val1 == val2){
// 		push_pilha_operandos((int32_t)0);
// 	}
// 	else if(val1 > val2){
// 		push_pilha_operandos((int32_t)1);
// 	}
// 	else if(val1 < val2){
// 		push_pilha_operandos((int32_t)-1);
// 	}
// 	else{
// 		printf("NaN!!\n");
// 		push_pilha_operandos((int32_t)-1);
// 	}

// 	atualizaPc();
// }

// void fcmpg(){

// 	float val1,val2;

// 	int32_t retPilha;

// 	retPilha = pop_op();

// 	memcpy(&val2,&retPilha,sizeof(float));

// 	retPilha = pop_op();

// 	memcpy(&val1,&retPilha,sizeof(float));

// 	if(val1 == val2){
// 		push_pilha_operandos((int32_t)0);
// 	}
// 	else if(val1 > val2){
// 		push_pilha_operandos((int32_t)1);
// 	}
// 	else if(val1 < val2){
// 		push_pilha_operandos((int32_t)-1);
// 	}
// 	else{
// 		printf("NaN!!\n");
// 		push_pilha_operandos((int32_t)1);
// 	}

// 	atualizaPc();
// }

// void dcmpl(){
// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double doubleCmpl;
// 	memcpy(&doubleCmpl, &dVal, sizeof(double));

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal2 = alta;

// 	dVal2 <<= 32;

// 	dVal2 = dVal2 + baixa;

// 	double doubleCmpl2;
// 	memcpy(&doubleCmpl2, &dVal2, sizeof(double));

// 	if(doubleCmpl2 > doubleCmpl){
// 		push_pilha_operandos((int32_t)1);
// 	}
// 	else if(doubleCmpl2 == doubleCmpl){
// 		push_pilha_operandos((int32_t)0);
// 	}
// 	else if(doubleCmpl2 < doubleCmpl){
// 		push_pilha_operandos((int32_t)-1);
// 	}
// 	else{
// 		printf("NaN!\n");
// 		push_pilha_operandos((int32_t) -1);
// 	}

// 	atualizaPc();
// }

// void dcmpg(){
// 	int32_t baixa,alta;
// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal = alta;

// 	dVal <<= 32;

// 	dVal = dVal + baixa;

// 	double doubleCmpl;
// 	memcpy(&doubleCmpl, &dVal, sizeof(double));

// 	baixa = pop_op();
// 	alta = pop_op();

// 	int64_t dVal2 = alta;

// 	dVal2 <<= 32;

// 	dVal2 = dVal2 + baixa;

// 	double doubleCmpl2;
// 	memcpy(&doubleCmpl2, &dVal2, sizeof(double));

// 	if(doubleCmpl2 > doubleCmpl){
// 		push_pilha_operandos((int32_t)1);
// 	}
// 	else if(doubleCmpl2 == doubleCmpl){
// 		push_pilha_operandos((int32_t)0);
// 	}
// 	else if(doubleCmpl2 < doubleCmpl){
// 		push_pilha_operandos((int32_t)-1);
// 	}
// 	else{
// 		printf("NaN!\n");
// 		push_pilha_operandos((int32_t) 1);
// 	}

// 	atualizaPc();
// }

// void ifeq(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha = pop_op();

// 	if(retPilha == 0){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void ifne(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha = pop_op();

// 	if(retPilha != 0){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void iflt(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha = pop_op();

// 	if(retPilha < 0){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void ifge(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha = pop_op();

// 	if(retPilha >= 0){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void ifgt(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha = pop_op();

// 	if(retPilha > 0){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void ifle(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha = pop_op();

// 	if(retPilha <= 0){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void if_icmpeq(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha1 = pop_op();
// 	int32_t retPilha2 = pop_op();

// 	if(retPilha1 == retPilha2){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void if_icmpne(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha1 = pop_op();
// 	int32_t retPilha2 = pop_op();

// 	if(retPilha1 != retPilha2){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void if_icmplt(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha1 = pop_op();
// 	int32_t retPilha2 = pop_op();

// 	if(retPilha2 < retPilha1){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void if_icmpge(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha1 = pop_op();
// 	int32_t retPilha2 = pop_op();

// 	if(retPilha2 >= retPilha1){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void if_icmpgt(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha1 = pop_op();
// 	int32_t retPilha2 = pop_op();

// 	if(retPilha2 > retPilha1){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void if_icmple(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha1 = pop_op();
// 	int32_t retPilha2 = pop_op();

// 	if(retPilha2 <= retPilha1){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void if_acmpeq(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha1 = pop_op();
// 	int32_t retPilha2 = pop_op();

// 	if(retPilha2 == retPilha1){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void if_acmpne(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha1 = pop_op();
// 	int32_t retPilha2 = pop_op();

// 	if(retPilha2 != retPilha1){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void ins_goto(){

// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	get_frame_atual()->pc += offset;
// }

// void jsr(){

// 	push_pilha_operandos(get_frame_atual()->pc+3);

// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	get_frame_atual()->pc += offset;
// }

// void ret(){

// }

// void tableswitch(){
//     uint32_t bytes_preench; 
//     int32_t indice;
//     int32_t default_v, low, high, npairs; 
//     uint32_t pc_novo, pc_aux;
//     int32_t qtd_offset, offset, posicao;
//     uint32_t temp;

//     bool definido = false; 

//     pc_aux = get_frame_atual()->pc; 

//     indice = pop_op(); 

//     bytes_preench = (4 - ((pc_aux + 1) % 4) ) % 4;  
//     pc_aux += bytes_preench;
//     pc_aux++;

//     default_v = 0;
//     for (int l = 0; l < 4; l++)
//     {
//         default_v = (default_v << 8) + get_frame_atual()->code[pc_aux];   
//         pc_aux++;
//     }       

//     low = 0;
//     for (int l = 0; l < 4; l++)
//     {
//         low = (low << 8) + get_frame_atual()->code[pc_aux];   
//         pc_aux++; 
//     }       

//     if (indice < low && !definido)
//     {
//         definido = true;
//         pc_novo = get_frame_atual()->pc + default_v; 
//     }

//     high = 0;
//     for (int l = 0; l < 4; l++)
//     {
//         high = (high << 8) + get_frame_atual()->code[pc_aux];   
//         pc_aux++; 
//     }       

//     if (indice > high && !definido)
//     {
//         definido = true;
//         pc_novo = get_frame_atual()->pc + default_v; 
//     }

//     qtd_offset = 1 + high - low; 
//     posicao = indice - low; 
//     for (int32_t l = 0; l < qtd_offset; l++)
//     {

//         if (l == posicao)
//         {

//             offset = 0;
//             for (int i = 0; i < 4; i++)
//             {
//                 offset = (offset << 8) + get_frame_atual()->code[pc_aux];   
//                 pc_aux++; 
//             }       

//             pc_novo = get_frame_atual()->pc + offset; 
//             definido = true;

//             break;
//         }

//         else
//         {
//             for (int i = 0; i < 4; i++)
//             {
//                 pc_aux++; 
//             }       
//         }
//     }

//     get_frame_atual()->pc = pc_novo; 
// }

// void lookupswitch(){
//     uint32_t pc_aux, pc_novo; 
//     uint32_t bytes_preench;
//     uint32_t offset;
//     int32_t default_v, npairs; 
//     int32_t match; 
//     int32_t key;

//     bool definido = false; 

//     pc_aux = get_frame_atual()->pc; 

//     key = pop_op(); 

//     bytes_preench = (4 - ((pc_aux + 1) % 4) ) % 4;  

//     pc_aux += bytes_preench;
//     pc_aux++;

//     default_v = 0;
//     for (int l = 0; l < 4; l++)
//     {
//         default_v = (default_v << 8) + get_frame_atual()->code[pc_aux];   
//         pc_aux++;
//     }       

//     npairs = 0;
//     for (int l = 0; l < 4; l++)
//     {
//         npairs = (npairs << 8) + get_frame_atual()->code[pc_aux];   
//         pc_aux++;
//     }       

//     for (int32_t l = 0; l < npairs; l++)
//     {

//         match = 0;
//         for (int l = 0; l < 4; l++)
//         {
//             match = (match << 8) + get_frame_atual()->code[pc_aux];   
//             pc_aux++;
//         }       

//         if (key == match)
//         {

//             offset = 0;
//             for (int l = 0; l < 4; l++)
//             {
//                 offset = (offset << 8) + get_frame_atual()->code[pc_aux];   
//                 pc_aux++;
//             }       

//             pc_novo = get_frame_atual()->pc + offset; 

//             definido = true;
//         }

//         else
//         {

//             for(int i = 0; i < 4; i++)
//             {
//                 pc_aux++;
//             }
//         }
//      }

//     if (!definido)
//     {
//         pc_novo = get_frame_atual()->pc + default_v;
//     }

//     get_frame_atual()->pc = pc_novo; 
// }

// void ireturn(){
//     retorno = pop_op();
// 	flagRet = 1;

//     get_frame_atual()->pc = get_frame_atual()->code_length + 1;
// }

// void lreturn(){
// 	int32_t alta,baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	flagRet = 2;

// 	retAlta = alta;
// 	retBaixa = baixa;

//     get_frame_atual()->pc = get_frame_atual()->code_length + 1;
// }

// void freturn(){
// 	retorno = pop_op();
// 	flagRet = 1;

//     get_frame_atual()->pc = get_frame_atual()->code_length + 1;
// }

// void dreturn(){
// 	int32_t alta,baixa;

// 	baixa = pop_op();
// 	alta = pop_op();

// 	flagRet = 2;

// 	retAlta = alta;
// 	retBaixa = baixa;

//     get_frame_atual()->pc = get_frame_atual()->code_length + 1;
// }

// void areturn(){
// 	retorno = pop_op();
// 	flagRet = 1;

//     get_frame_atual()->pc = get_frame_atual()->code_length + 1;
// }

// void ins_return(){

// 	retorno = 0;
// 	flagRet = 0;

// 	atualizaPc();
// }

// void getstatic(){

//     get_frame_atual()->pilha_op->depth += 1;

// 	atualizaPc();
// }

// void putstatic(){

// }

// void getfield(){

// 	uint32_t indice = get_frame_atual()->code[get_frame_atual()->pc + 2];

// 	int32_t indiceClasse = get_frame_atual()->constant_pool[indice-1].info.Fieldref.class_index;

// 	char* nomeClasse = retornaNome(get_frame_atual()->classe, get_frame_atual()->constant_pool[indiceClasse-1].info.Class.name_index);

// 	uint16_t nomeTipoIndice = get_frame_atual()->constant_pool[indice-1].info.Fieldref.name_and_type_index;

// 	char* nome = retornaNome(get_frame_atual()->classe, get_frame_atual()->constant_pool[nomeTipoIndice-1].info.NameAndType.name_index);
// 	char* tipo = retornaNome(get_frame_atual()->classe, get_frame_atual()->constant_pool[nomeTipoIndice-1].info.NameAndType.descriptor_index);
// 	tipoGlobal = tipo;

//  	if((strcmp(tipo, "Ljava/util/Scanner;") == 0)){
//  		atualizaPc();
// 		return;
//  	}

//  	objeto* obj = (objeto*) pop_op();

//  	int32_t indiceField = buscaCampo(nomeClasse,nome,tipo);

//  	uint32_t indiceNome = get_frame_atual()->classe->fields[indiceField].name_index;

//  	if(tipo[0] == 'J' || tipo[0] == 'D') {
//  		int32_t i;
// 		for(i = 0;obj->indiceCampos[i] != indiceNome; i++);

// 		int32_t baixa = obj->campos[i];
// 		int32_t alta = obj->campos[i+1];

// 		push_pilha_operandos(alta);
// 		push_pilha_operandos(baixa);
// 		atualizaPc();
//  	}
//  	else{

// 	 	int32_t i;
// 		for(i = 0;obj->indiceCampos[i] != indiceNome; i++);

// 	 	uint32_t val = obj->campos[i];

// 	 	push_pilha_operandos(val);

// 		atualizaPc();
// 	}
// }

// void putfield(){

// 	uint32_t indice = get_frame_atual()->code[get_frame_atual()->pc + 2];

// 	int32_t indiceClasse = get_frame_atual()->constant_pool[indice-1].info.Fieldref.class_index;

// 	char* nomeClasse = retornaNome(get_frame_atual()->classe, get_frame_atual()->constant_pool[indiceClasse-1].info.Class.name_index);

// 	uint16_t nomeTipoIndice = get_frame_atual()->constant_pool[indice-1].info.Fieldref.name_and_type_index;

// 	char* nome = retornaNome(get_frame_atual()->classe, get_frame_atual()->constant_pool[nomeTipoIndice-1].info.NameAndType.name_index);
// 	char* tipo = retornaNome(get_frame_atual()->classe, get_frame_atual()->constant_pool[nomeTipoIndice-1].info.NameAndType.descriptor_index);

//  	int32_t indiceField = buscaCampo(nomeClasse,nome,tipo);

//  	uint32_t indiceNome = get_frame_atual()->classe->fields[indiceField].name_index;

//  	if(tipo[0] == 'J' || tipo[0] == 'D') {
//  		int32_t alta,baixa;
//  		int32_t val1 = pop_op();
//  		int32_t val2 = pop_op();
//  		objeto* obj = (objeto*)pop_op();

// 		int64_t dVal = val2;

// 		dVal <<= 32;

// 		dVal = dVal + val1;

// 		double valorDouble1;
// 		memcpy(&valorDouble1, &dVal, sizeof(int64_t));

// 		int i;
// 		for(i = 0; obj->indiceCampos[i] != indiceNome; i++);

// 		int64_t valorPilha;
// 		memcpy(&valorPilha, &valorDouble1, sizeof(int64_t));

// 		alta = valorPilha >> 32;
// 		baixa = valorPilha & 0xffffffff;
// 		obj->campos[i] = baixa;
// 		obj->campos[i+1] = alta;
//  	}
//  	else{
// 	 	int32_t val = pop_op();
// 	 	objeto* obj = (objeto*)pop_op();
// 	 	int i;
// 	 	for(i = 0; obj->indiceCampos[i] != indiceNome; i++);
// 		obj->campos[i] = val;
// 	}

// 	atualizaPc();
// }

// void invokevirtual(){
// 	method_info* metodoInvocado;
//     char* nomeClasse;
//     char* nomeMetodo;
//     char* descricaoMetodo;
//     uint16_t nomeMetodoAux, descricaoMetodoAux,nomeTipoAux,stringAux;
//     int32_t resultado,resultado2, resultado_string;
//     int32_t classeIndice;
//     uint8_t* string = NULL;
//     static int8_t flagAppend = 0;

//     uint32_t pcAux = get_frame_atual()->code[get_frame_atual()->pc + 2];

//     classeIndice = get_frame_atual()->constant_pool[pcAux - 1].info.Methodref.class_index;

//     nomeClasse = retornaNome(get_frame_atual()->classe, get_frame_atual()->constant_pool[classeIndice - 1].info.Class.name_index);
//     nomeTipoAux = get_frame_atual()->constant_pool[pcAux - 1].info.Methodref.name_and_type_index;

//     nomeMetodoAux = get_frame_atual()->constant_pool[nomeTipoAux - 1].info.NameAndType.name_index;

// 	descricaoMetodoAux = get_frame_atual()->constant_pool[nomeTipoAux - 1].info.NameAndType.descriptor_index;

//     nomeMetodo = retornaNome(get_frame_atual()->classe, nomeMetodoAux);

//     descricaoMetodo = retornaNome(get_frame_atual()->classe, descricaoMetodoAux);

//     if((strcmp(nomeClasse, "java/lang/StringBuffer") == 0) && (strcmp(nomeMetodo,"append") == 0)){
// 			flagAppend++;
// 		    foi_lneg = false;
// 			atualizaPc();
// 			return;
// 	}

// 	if((strcmp(nomeClasse, "java/lang/StringBuffer") == 0) && (strcmp(nomeMetodo,"toString") == 0)){
// 		    foi_lneg = false;
// 			atualizaPc();
// 			return;
// 	}

// 	if((strcmp(nomeClasse, "java/util/Scanner") == 0) && (strcmp(nomeMetodo,"next") == 0)){
// 		int32_t aux;
// 		scanf("%d",&aux);
// 		push_pilha_operandos(aux);
// 		foi_lneg = false;
// 		atualizaPc();
// 		return;
// 	}

// 	if((strcmp(nomeClasse, "java/io/PrintStream") == 0) && (strcmp(nomeMetodo,"println") == 0)){
//         if (strcmp(descricaoMetodo, "()V") == 0)
//         {
//             printf("\n");
//         }

//         else if (flagAppend == 0)
//         {
//             resultado = pop_op();

//             if (tipoGlobal == NULL)
//             {
//                 string = get_frame_atual()->constant_pool[resultado].info.Utf8.bytes;
//             }

//             if (string != NULL) {
//                 printf("%s\n",string);
//             }
//             else if(strcmp(tipoGlobal, "Z") == 0)
//             {
//                 if(resultado){
//                 	printf("TRUE\n");
//                 }else{
//                 	printf("FALSE\n");
//                 }
//             }
//             else if(strcmp(tipoGlobal, "F") == 0)
//             {
//                 float valDesemp;
//                 memcpy(&valDesemp, &resultado, sizeof(float));
//                 printf("%f\n",valDesemp);
//             }

//             else if(strcmp(tipoGlobal, "D") == 0)
//             {
//                 resultado2 = pop_op();
//                 double resultado_double; 
//                 int64_t temp; 

//                 temp = resultado2;
//                 temp <<= 32;
//                 temp += resultado; 
//                 memcpy(&resultado_double, &temp, sizeof(int64_t));
//                 printf("%f\n", resultado_double);
//             }

//             else if(strcmp(tipoGlobal, "L") == 0)
//             {
//                 resultado2 = pop_op();
//                 int64_t long_num; 
//                 long long result;

//                 long_num= resultado2;
//                 long_num <<= 32;
//                 long_num |= resultado; 

//                 memcpy(&result, &long_num, sizeof(long));
//                 foi_lneg = false;
//                 if (!foi_lneg)
//                 {
//                     printf("%" PRId64 "\n", long_num);
//                 }
//                 else
//                 {
//                     printf("%" PRId64 "\n", result);
//                 }
//             }

//             else if (strcmp(tipoGlobal, "I") == 0)
//             {
//                 printf("%d\n", resultado);
//             }

//             else if (strcmp(tipoGlobal, "C") == 0)
//             {
//                 printf("%c\n", resultado);
//             }

//             else
//             {
//                 printf("erro no invoke_virtual, tipoGlobal ainda nao setado");
//                 exit(1);
//             }
//         }

//         else if (flagAppend == 2)
//         {
//             if(strcmp(tipoGlobal, "F") == 0)
//             {
//                 resultado = pop_op();
//                 resultado_string = pop_op();

//                 string = get_frame_atual()->constant_pool[resultado_string].info.Utf8.bytes;
//                 if (string != NULL)
//                 {
//                     printf("%s",string);
//                 }

//                 float valDesemp;
//                 memcpy(&valDesemp,&resultado, sizeof(float));
//                 printf("%f\n",valDesemp);
//             }

//             else if(strcmp(tipoGlobal, "I") == 0)
//             {
//                 resultado = pop_op();
//                 resultado_string = pop_op();

//                 string = get_frame_atual()->constant_pool[resultado_string].info.Utf8.bytes;
//                 if (string != NULL)
//                 {
//                     printf("%s",string);
//                 }
//                 printf("%d\n", resultado);
//             }

//             else if(strcmp(tipoGlobal, "D") == 0)
//             {
//                 resultado = pop_op();
//                 resultado2 = pop_op();
//                 resultado_string = pop_op();

//                 double resultado_double; 
//                 int64_t temp; 

//                 temp = resultado2;
//                 temp <<= 32;
//                 temp += resultado; 

//                 if (string != NULL)
//                 {
//                     printf("%s",string);
//                 }

//                 memcpy(&resultado_double, &temp, sizeof(int64_t));
//                 printf("%lf\n", resultado_double);
//             }

//             else
//             {
//                 printf("tipoGlobal ainda nao reconhecido");
//                 exit(1);
//             }

//             flagAppend = 0;
//         }
//         else{
//         	return;
//         }

//         foi_lneg = false;
// 		atualizaPc();
// 		return;
// 	}

// 	classeIndice = carregaMemClasse(nomeClasse);
// 	classFile* classe = buscaClasseIndice(classeIndice);

// 	metodoInvocado = buscaMetodo(get_frame_atual()->classe,classe,nomeTipoAux);
// 	if(metodoInvocado == NULL){
// 		printf("Método não Encontrado!\n");
// 		exit(0);
// 	}

// 	int32_t numeroParametros = retornaNumeroParametros(classe,metodoInvocado);

// 	uint32_t* fields = calloc(sizeof(uint32_t),numeroParametros + 1);

// 	for(int32_t i = 0; i <= numeroParametros; i++){
// 		fields[i] = pop_op();
// 	}

// 	empilhaMetodo(metodoInvocado, classe);

// 	for(int32_t i = 0; i <= numeroParametros; i++) {
// 			get_frame_atual()->fields[i] = fields[numeroParametros - i];
// 	}

// 	executaget_frame_atual()();

// 	foi_lneg = false;
// 	atualizaPc();
// 	return;
// }

// void invokespecial(){
// 	method_info* metodoInvocado;

// 	uint32_t indice = get_frame_atual()->code[get_frame_atual()->pc + 2];

// 	uint32_t indiceClasse = (get_frame_atual()->constant_pool[indice-1]).info.Methodref.class_index;

// 	char* nomeClasse = retornaNome(get_frame_atual()->classe,(get_frame_atual()->constant_pool[indiceClasse-1]).info.Class.name_index);

//     if(strcmp("java/lang/Object",nomeClasse) == 0){

// 		carregaMemClasse(nomeClasse);

// 		atualizaPc();
// 		return;
// 	}

// 	if(strcmp("java/lang/StringBuffer",nomeClasse) == 0){

// 		atualizaPc();
// 		return;
// 	}

// 	if(strcmp("java/util/Scanner",nomeClasse) == 0){

// 		atualizaPc();
// 		return;
// 	}

// 	int32_t indexClasse = carregaMemClasse(nomeClasse);

// 	classFile* classe = buscaClasseIndice(indexClasse);

// 	uint16_t nomeTipoIndice = get_frame_atual()->constant_pool[indice-1].info.Methodref.name_and_type_index;

// 	metodoInvocado = buscaMetodo(get_frame_atual()->classe,classe,nomeTipoIndice);

// 	int32_t numeroParametros = retornaNumeroParametros(classe,metodoInvocado);

// 	uint32_t* fields = calloc(sizeof(uint32_t),numeroParametros + 1);

// 	for(int32_t i = 0; i <= numeroParametros; i++){
// 		fields[i] = pop_op();
// 	}

// 	empilhaMetodo(metodoInvocado, classe);

// 	for(int32_t i = 0; i <= numeroParametros; i++) {
// 			get_frame_atual()->fields[i] = fields[numeroParametros - i];
// 	}

// 	executaget_frame_atual()();

// 	atualizaPc();
// }

// void invokestatic(){

// 	method_info* metodoInvocado;

//     char* nomeMetodo;
//     char* descricaoMetodo;
//     uint16_t nomeMetodoAux, descricaoMetodoAux,nomeTipoAux,stringAux;

// 	uint32_t indice = get_frame_atual()->code[get_frame_atual()->pc + 2];

// 	uint32_t indiceClasse = (get_frame_atual()->constant_pool[indice-1]).info.Methodref.class_index;

// 	char* nomeClasse = retornaNome(get_frame_atual()->classe,(get_frame_atual()->constant_pool[indiceClasse-1]).info.Class.name_index);

// 	nomeTipoAux = get_frame_atual()->constant_pool[indice - 1].info.Methodref.name_and_type_index;

//     nomeMetodoAux = get_frame_atual()->constant_pool[nomeTipoAux - 1].info.NameAndType.name_index;

// 	descricaoMetodoAux = get_frame_atual()->constant_pool[nomeTipoAux - 1].info.NameAndType.descriptor_index;

//     nomeMetodo = retornaNome(get_frame_atual()->classe, nomeMetodoAux);

//     descricaoMetodo = retornaNome(get_frame_atual()->classe, descricaoMetodoAux);

// 	if((strcmp(nomeClasse, "java/lang/System") == 0) && (strcmp(nomeMetodo,"exit") == 0)){
// 		if(strstr(descricaoMetodo, "(I)V") != NULL) {
// 			int32_t retPilha = pop_op();
// 			exit(retPilha);

//             atualizaPc();
//             return; 
// 		}
// 	}

// 	if((strcmp(nomeClasse, "java/lang/Integer") == 0) && (strcmp(nomeMetodo,"parseInt") == 0)){

// 			int32_t retPilha = pop_op();
// 			pop_op();
// 			push_pilha_operandos(retPilha);

//             atualizaPc();
//             return; 
// 	}

// 	if((strcmp(nomeClasse, "java/lang/Math") == 0) && (strcmp(nomeMetodo,"sqrt") == 0)){
// 		if(strstr(descricaoMetodo, "(D)D") != NULL) {
// 			int32_t baixa = pop_op();
// 			int32_t alta = pop_op();

// 			int64_t dVal = alta;

// 			dVal <<= 32;

// 			dVal = dVal + baixa;

// 			double valorDouble1;
// 			memcpy(&valorDouble1, &dVal, sizeof(int64_t));

// 			valorDouble1 = sqrt (valorDouble1);

// 			int64_t aux;
// 			memcpy(&aux, &valorDouble1, sizeof(int64_t));

// 			alta = aux >> 32;
// 			baixa = aux & 0xffffffff;

// 			push_pilha_operandos(alta);
// 			push_pilha_operandos(baixa);

//             atualizaPc();
//             return; 
// 		}
// 	}

// 	int32_t indexClasse = carregaMemClasse(nomeClasse);

// 	classFile* classe = buscaClasseIndice(indexClasse);

// 	uint16_t nomeTipoIndice = get_frame_atual()->constant_pool[indice-1].info.Methodref.name_and_type_index;

// 	metodoInvocado = buscaMetodo(get_frame_atual()->classe,classe,nomeTipoIndice);

// 	int32_t numeroParametros = retornaNumeroParametros(classe,metodoInvocado);

// 	uint32_t* fields = calloc(sizeof(uint32_t),numeroParametros + 1);

// 	for(int32_t i = 0; i < numeroParametros; i++)
// 		fields[i] = pop_op();

// 	empilhaMetodo(metodoInvocado, classe);

// 	for(int32_t i = 0; i < numeroParametros; i++) {
// 			get_frame_atual()->fields[i] = fields[numeroParametros - i - 1];
// 	}

// 	executaget_frame_atual()();
// 	atualizaPc();
// }

// void invokeinterface(){
// 	method_info* metodoInvocado;

//     char* nomeMetodo;
//     char* descricaoMetodo;
//     uint16_t nomeMetodoAux, descricaoMetodoAux,nomeTipoAux,stringAux;

// 	uint32_t indice = get_frame_atual()->code[get_frame_atual()->pc + 2];

// 	uint32_t indiceClasse = (get_frame_atual()->constant_pool[indice-1]).info.Methodref.class_index;

// 	char* nomeClasse = retornaNome(get_frame_atual()->classe,(get_frame_atual()->constant_pool[indiceClasse-1]).info.Class.name_index);

// 	nomeTipoAux = get_frame_atual()->constant_pool[indice - 1].info.Methodref.name_and_type_index;

//     nomeMetodoAux = get_frame_atual()->constant_pool[nomeTipoAux - 1].info.NameAndType.name_index;

// 	descricaoMetodoAux = get_frame_atual()->constant_pool[nomeTipoAux - 1].info.NameAndType.descriptor_index;

//     nomeMetodo = retornaNome(get_frame_atual()->classe, nomeMetodoAux);

//     descricaoMetodo = retornaNome(get_frame_atual()->classe, descricaoMetodoAux);

// 	int32_t indexClasse = carregaMemClasse(nomeClasse);

// 	classFile* classe = buscaClasseIndice(indexClasse);

// 	uint16_t nomeTipoIndice = get_frame_atual()->constant_pool[indice-1].info.Methodref.name_and_type_index;

// 	metodoInvocado = buscaMetodo(get_frame_atual()->classe,classe,nomeTipoIndice);

// 	int32_t numeroParametros = retornaNumeroParametros(classe,metodoInvocado);

// 	uint32_t* fields = calloc(sizeof(uint32_t),numeroParametros + 1);

// 	for(int32_t i = 0; i < numeroParametros; i++)
// 		fields[i] = pop_op();

// 	empilhaMetodo(metodoInvocado, classe);

// 	for(int32_t i = 0; i < numeroParametros; i++) {
// 			get_frame_atual()->fields[i] = fields[numeroParametros - i - 1];
// 	}

// 	executaget_frame_atual()();
// 	atualizaPc();

// }

// void ins_new(){
// 	uint32_t indice;
// 	int32_t aux;
// 	char* nomeClasse;
// 	classFile* classe;
// 	objeto* objeto;

// 	indice = get_frame_atual()->code[2+(get_frame_atual()->pc)];

// 	nomeClasse = retornaNome(get_frame_atual()->classe, get_frame_atual()->constant_pool[indice-1].info.Class.name_index);

// 	if(strcmp("java/util/Scanner",nomeClasse) == 0){
// 		naoEmpilhaFlag = 1;

// 		atualizaPc();
// 		return;
// 	}

// 	if(strcmp("java/lang/StringBuffer",nomeClasse) == 0){
// 		naoEmpilhaFlag = 1;

// 		atualizaPc();
// 		return;
// 	}

// 	aux = carregaMemClasse(nomeClasse);

// 	classe = buscaClasseIndice(aux);

// 	objeto = criaObjeto(classe);

// 	if(objeto == NULL){
// 		printf("Objeto não foi corretamente alocado\n");
// 	}

// 	push_pilha_operandos((int32_t) objeto);
// 	atualizaPc();
// }

// void newarray(){

// 	int32_t tamanhoBytes;

// 	int32_t tamanhoArray = pop_op();

// 	int8_t tipoArray = get_frame_atual()->code[(get_frame_atual()->pc)+1];

// 	if(tipoArray == 11){
// 		tamanhoBytes = 8;
// 	}

// 	if(tipoArray == 7){
// 		tamanhoBytes = 8;
// 	}

// 	if(tipoArray == 6){
// 		tamanhoBytes = 4;
// 	}

// 	if(tipoArray == 0){
// 		tamanhoBytes = 4;
// 	}

// 	if(tipoArray == 10){
// 		tamanhoBytes = 4;
// 	}

// 	if(tipoArray == 5){
// 		tamanhoBytes = 2;
// 	}

// 	if(tipoArray == 9){
// 		tamanhoBytes = 2;
// 	}

// 	if(tipoArray == 4){
// 		tamanhoBytes = 1;
// 	}

// 	if(tipoArray == 8){
// 		tamanhoBytes = 1;
// 	}

// 	int32_t* vetor = calloc(tamanhoBytes,tamanhoArray);

// 	qtdArrays++;
// 	arrayVetores = realloc (arrayVetores, sizeof(struct array)*qtdArrays);
// 	arrayVetores[qtdArrays-1].tamanho = tamanhoArray;
// 	arrayVetores[qtdArrays-1].referencia = (int32_t)vetor;
// 	arrayVetores[qtdArrays-1].tipo = tipoArray;

// 	push_pilha_operandos((int32_t)vetor);

//     atualizaPc();

// }

// void anewarray(){

// 	int32_t tamanhoBytes;

// 	int32_t tamanhoArray = pop_op();

// 	int8_t tipoArray = get_frame_atual()->code[(get_frame_atual()->pc)+1];

// 	if(tipoArray == 11){
// 		tamanhoBytes = 8;
// 	}

// 	if(tipoArray == 7){
// 		tamanhoBytes = 8;
// 	}

// 	if(tipoArray == 6){
// 		tamanhoBytes = 4;
// 	}

// 	if(tipoArray == 0){
// 		tamanhoBytes = 4;
// 	}

// 	if(tipoArray == 10){
// 		tamanhoBytes = 4;
// 	}

// 	if(tipoArray == 5){
// 		tamanhoBytes = 2;
// 	}

// 	if(tipoArray == 9){
// 		tamanhoBytes = 2;
// 	}

// 	if(tipoArray == 4){
// 		tamanhoBytes = 1;
// 	}

// 	if(tipoArray == 8){
// 		tamanhoBytes = 1;
// 	}

// 	int32_t* vetor = calloc(tamanhoBytes,tamanhoArray);

// 	qtdArrays++;
// 	arrayVetores = realloc (arrayVetores, sizeof(struct array)*qtdArrays);
// 	arrayVetores[qtdArrays-1].tamanho = tamanhoArray;
// 	arrayVetores[qtdArrays-1].referencia = (int32_t)vetor;
// 	arrayVetores[qtdArrays-1].tipo = tipoArray;

// 	push_pilha_operandos((int32_t)vetor);

//     atualizaPc();
// }

// void arraylength(){

// 	int32_t arrayRef = pop_op();
// 	int i = 0;

// 	while(i  < qtdArrays){

// 		if(arrayVetores[i].referencia == arrayRef){

// 			int32_t length = arrayVetores[i].tamanho;
// 			push_pilha_operandos(length);
// 			atualizaPc();
// 			return;
// 		}
// 		i++;
// 	}

// 	push_pilha_operandos(0);
// 	atualizaPc();
// }

// void checkcast(){
// 	int16_t indice;
// 	int8_t offset1,offset2;

// 	offset1 =  get_frame_atual()->code[(get_frame_atual()->pc)+1];
// 	offset2 =  get_frame_atual()->code[(get_frame_atual()->pc)+2];

// 	indice = (offset1 << 8) | offset2;

// 	objeto* objeto = (struct objeto*) pop_op();

// 	if(objeto == NULL){
// 		printf("Objeto nulo!\n");
// 	}

// 	char* nomeClasse = retornaNomeClasse(objeto->classe);

// 	char* nomeIndice = retornaNome(get_frame_atual()->classe,indice);

// 	if(strcmp(nomeClasse,nomeIndice) == 0){
// 		printf("Objeto é do tipo: %s\n",nomeIndice);
// 	}

// 	push_pilha_operandos((int32_t)objeto);
// 	atualizaPc();
// }

// void instanceof(){
// 	int16_t indice;
// 	int8_t offset1,offset2;

// 	offset1 =  get_frame_atual()->code[(get_frame_atual()->pc)+1];
// 	offset2 =  get_frame_atual()->code[(get_frame_atual()->pc)+2];

// 	indice = (offset1 << 8) | offset2;

// 	objeto* objeto = (struct objeto*) pop_op();

// 	if(objeto == NULL){
// 		printf("Objeto nulo!\n");
// 		push_pilha_operandos(0);
// 	}

// 	char* nomeClasse = retornaNomeClasse(objeto->classe);

// 	char* nomeIndice = retornaNome(get_frame_atual()->classe,indice);

// 	if(strcmp(nomeClasse,nomeIndice) == 0){
// 		printf("Objeto é do tipo: %s\n",nomeIndice);
// 		push_pilha_operandos(1);
// 	}
// 	atualizaPc();
// }

// void wide(){

// }

// void multianewarray(){

// }

// void ifnull(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha = pop_op();

// 	if(retPilha == 0){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void ifnonnull(){
// 	uint8_t offset1,offset2;
// 	int16_t offset;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset = offset1;
// 	offset <<= 8;
// 	offset |= offset2;

// 	int32_t retPilha = pop_op();

// 	if(retPilha != 0){
// 		get_frame_atual()->pc += offset;
// 	}else{
// 		get_frame_atual()->pc += 3;
// 	}
// }

// void goto_w(){
// 	int32_t deslocamento,offset1,offset2,offset3,offset4;

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset3 = get_frame_atual()->code[get_frame_atual()->pc + 3];
// 	offset4 = get_frame_atual()->code[get_frame_atual()->pc + 4];

// 	deslocamento  = (offset1 & 0xFF)<<24;
// 	deslocamento |= (offset2 & 0xFF)<<16;
// 	deslocamento |= (offset3 & 0xFF)<<8;
// 	deslocamento |= (offset4 & 0xFF);

// 	get_frame_atual()->pc += deslocamento;
// }

// void jsr_w(){
// 	int32_t deslocamento,offset1,offset2,offset3,offset4;

// 	push_pilha_operandos(get_frame_atual()->code[get_frame_atual()->pc + 5]);

// 	offset1 = get_frame_atual()->code[get_frame_atual()->pc + 1];
// 	offset2 = get_frame_atual()->code[get_frame_atual()->pc + 2];
// 	offset3 = get_frame_atual()->code[get_frame_atual()->pc + 3];
// 	offset4 = get_frame_atual()->code[get_frame_atual()->pc + 4];

// 	deslocamento  = (offset1 & 0xFF)<<24;
// 	deslocamento |= (offset2 & 0xFF)<<16;
// 	deslocamento |= (offset3 & 0xFF)<<8;
// 	deslocamento |= (offset4 & 0xFF);

// 	get_frame_atual()->pc += deslocamento;
// }