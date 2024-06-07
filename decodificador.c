/**
 *@file
 *@section DESCRIPTION
 *Universidade de Brasilia
 *
 *Matheus Barbosa e Silva - 190113987\n
 *Plínio Candide Rios Mayer - 180129562\n
 *William Xavier dos Santos - 190075384\n
 *Eduardo Afonso da Silva Inácio - 221033920\n
 *Marcus Paulo Kaller Vargas - 200041096\n\n
 *
 * Software Basico - 1/2024\n
 * Professor: Marcelo Ladeira\n\n
 *
 * Este arquivo contém a implementação da função responsável por decodificar as instruções bytecode de um arquivo .class,
 * convertendo os códigos operacionais (opcodes) em seus respectivos mnemônicos. Esses mnemônicos são utilizados
 * para facilitar a visualização e entendimento do fluxo operacional das instruções Java no exibidor.
 *
 * A função de decodificação permite que o interpretador apresente uma forma legível das operações codificadas
 * dentro de um arquivo .class, servindo como uma ferramenta essencial para análise e depuração de bytecodes.
 */

#include "./includes/decodificador.h"

void start_decoder(decoder dec[]) {
  /* instrucoes constantes */

  strcpy(dec[0].instruction, "nop");
  dec[0].bytes = 0;

  strcpy(dec[1].instruction, "aconst_null");
  dec[1].bytes = 0;

  strcpy(dec[2].instruction, "iconst_m1");
  dec[2].bytes = 0;

  strcpy(dec[3].instruction, "iconst_0");
  dec[3].bytes = 0;

  strcpy(dec[4].instruction, "iconst_1");
  dec[4].bytes = 0;

  strcpy(dec[5].instruction, "iconst_2");
  dec[5].bytes = 0;

  strcpy(dec[6].instruction, "iconst_3");
  dec[6].bytes = 0;

  strcpy(dec[7].instruction, "iconst_4");
  dec[7].bytes = 0;

  strcpy(dec[8].instruction, "iconst_5");
  dec[8].bytes = 0;

  strcpy(dec[9].instruction, "lconst_0");
  dec[9].bytes = 0;

  strcpy(dec[10].instruction, "lconst_1");
  dec[10].bytes = 0;

  strcpy(dec[11].instruction, "fconst_0");
  dec[11].bytes = 0;

  strcpy(dec[12].instruction, "fconst_1");
  dec[12].bytes = 0;

  strcpy(dec[13].instruction, "fconst_2");
  dec[13].bytes = 0;

  strcpy(dec[14].instruction, "dconst_0");
  dec[14].bytes = 0;

  strcpy(dec[15].instruction, "dconst_1");
  dec[15].bytes = 0;

  strcpy(dec[16].instruction, "bipush");
  dec[16].bytes = 1;

  strcpy(dec[17].instruction, "sipush");
  dec[17].bytes = 2;

  strcpy(dec[18].instruction, "ldc");
  dec[18].bytes = 1;

  strcpy(dec[19].instruction, "ldc_w");
  dec[19].bytes = 2;

  strcpy(dec[20].instruction, "ldc2_w");
  dec[20].bytes = 2;

  strcpy(dec[21].instruction, "iload");
  dec[21].bytes = 1;

  strcpy(dec[22].instruction, "lload");
  dec[22].bytes = 1;

  strcpy(dec[23].instruction, "fload");
  dec[23].bytes = 1;

  strcpy(dec[24].instruction, "dload");
  dec[24].bytes = 1;

  strcpy(dec[25].instruction, "aload");
  dec[25].bytes = 1;

  strcpy(dec[26].instruction, "iload_0");
  dec[26].bytes = 0;

  strcpy(dec[27].instruction, "iload_1");
  dec[27].bytes = 0;

  strcpy(dec[28].instruction, "iload_2");
  dec[28].bytes = 0;

  strcpy(dec[29].instruction, "iload_3");
  dec[29].bytes = 0;

  strcpy(dec[30].instruction, "lload_0");
  dec[30].bytes = 0;

  strcpy(dec[31].instruction, "lload_1");
  dec[31].bytes = 0;

  strcpy(dec[32].instruction, "lload_2");
  dec[32].bytes = 0;

  strcpy(dec[33].instruction, "lload_3");
  dec[33].bytes = 0;

  strcpy(dec[34].instruction, "fload_0");
  dec[34].bytes = 0;

  strcpy(dec[35].instruction, "fload_1");
  dec[35].bytes = 0;

  strcpy(dec[36].instruction, "fload_2");
  dec[36].bytes = 0;

  strcpy(dec[37].instruction, "fload_3");
  dec[37].bytes = 0;

  strcpy(dec[38].instruction, "dload_0");
  dec[38].bytes = 0;

  strcpy(dec[39].instruction, "dload_1");
  dec[39].bytes = 0;

  strcpy(dec[40].instruction, "dload_2");
  dec[40].bytes = 0;

  strcpy(dec[41].instruction, "dload_3");
  dec[41].bytes = 0;

  /* loads */

  strcpy(dec[42].instruction, "aload_0");
  dec[42].bytes = 0;

  strcpy(dec[43].instruction, "aload_1");
  dec[43].bytes = 0;

  strcpy(dec[44].instruction, "aload_2");
  dec[44].bytes = 0;

  strcpy(dec[45].instruction, "aload_3");
  dec[45].bytes = 0;

  strcpy(dec[46].instruction, "iaload");
  dec[46].bytes = 0;

  strcpy(dec[47].instruction, "laload");
  dec[47].bytes = 0;

  strcpy(dec[48].instruction, "faload");
  dec[48].bytes = 0;

  strcpy(dec[49].instruction, "daload");
  dec[49].bytes = 0;

  strcpy(dec[50].instruction, "aaload");
  dec[50].bytes = 0;

  strcpy(dec[51].instruction, "baload");
  dec[51].bytes = 0;

  strcpy(dec[52].instruction, "caload");
  dec[52].bytes = 0;

  strcpy(dec[53].instruction, "saload");
  dec[53].bytes = 0;

  strcpy(dec[54].instruction, "istore");
  dec[54].bytes = 1;

  strcpy(dec[55].instruction, "lstore");
  dec[55].bytes = 1;

  strcpy(dec[56].instruction, "fstore");
  dec[56].bytes = 1;

  strcpy(dec[57].instruction, "dstore");
  dec[57].bytes = 1;

  strcpy(dec[58].instruction, "astore");
  dec[58].bytes = 1;

  strcpy(dec[59].instruction, "istore_0");
  dec[59].bytes = 0;

  strcpy(dec[60].instruction, "istore_1");
  dec[60].bytes = 0;

  strcpy(dec[61].instruction, "istore_2");
  dec[61].bytes = 0;

  strcpy(dec[62].instruction, "istore_3");
  dec[62].bytes = 0;

  strcpy(dec[63].instruction, "lstore_0");
  dec[63].bytes = 0;

  strcpy(dec[64].instruction, "lstore_1");
  dec[64].bytes = 0;

  strcpy(dec[65].instruction, "lstore_2");
  dec[65].bytes = 0;

  strcpy(dec[66].instruction, "lstore_3");
  dec[66].bytes = 0;

  strcpy(dec[67].instruction, "fstore_0");
  dec[67].bytes = 0;

  strcpy(dec[68].instruction, "fstore_1");
  dec[68].bytes = 0;

  strcpy(dec[69].instruction, "fstore_2");
  dec[69].bytes = 0;

  strcpy(dec[70].instruction, "fstore_3");
  dec[70].bytes = 0;

  strcpy(dec[71].instruction, "dstore_0");
  dec[71].bytes = 0;

  strcpy(dec[72].instruction, "dstore_1");
  dec[72].bytes = 0;

  strcpy(dec[73].instruction, "dstore_2");
  dec[73].bytes = 0;

  strcpy(dec[74].instruction, "dstore_3");
  dec[74].bytes = 0;

  strcpy(dec[75].instruction, "astore_0");
  dec[75].bytes = 0;

  strcpy(dec[76].instruction, "astore_1");
  dec[76].bytes = 0;

  strcpy(dec[77].instruction, "astore_2");
  dec[77].bytes = 0;

  strcpy(dec[78].instruction, "astore_3");
  dec[78].bytes = 0;

  strcpy(dec[79].instruction, "iastore");
  dec[79].bytes = 0;

  strcpy(dec[80].instruction, "lastore");
  dec[80].bytes = 0;

  strcpy(dec[81].instruction, "fastore");
  dec[81].bytes = 0;

  strcpy(dec[82].instruction, "dastore");
  dec[82].bytes = 0;

  strcpy(dec[83].instruction, "aastore");
  dec[83].bytes = 0;

  strcpy(dec[84].instruction, "bastore");
  dec[84].bytes = 0;

  strcpy(dec[85].instruction, "castore");
  dec[85].bytes = 0;

  strcpy(dec[86].instruction, "sastore");
  dec[86].bytes = 0;

  strcpy(dec[87].instruction, "pop");
  dec[87].bytes = 0;

  strcpy(dec[88].instruction, "pop2");
  dec[88].bytes = 0;

  strcpy(dec[89].instruction, "dup");
  dec[89].bytes = 0;

  strcpy(dec[90].instruction, "dup_x1");
  dec[90].bytes = 0;

  strcpy(dec[91].instruction, "dup_x2");
  dec[91].bytes = 0;

  strcpy(dec[92].instruction, "dup2");
  dec[92].bytes = 0;

  strcpy(dec[93].instruction, "dup2_x1");
  dec[93].bytes = 0;

  strcpy(dec[94].instruction, "dup2_x2");
  dec[94].bytes = 0;

  strcpy(dec[95].instruction, "swap");
  dec[95].bytes = 0;

  strcpy(dec[96].instruction, "iadd");
  dec[96].bytes = 0;

  strcpy(dec[97].instruction, "ladd");
  dec[97].bytes = 0;

  strcpy(dec[98].instruction, "fadd");
  dec[98].bytes = 0;

  strcpy(dec[99].instruction, "dadd");
  dec[99].bytes = 0;

  strcpy(dec[100].instruction, "isub");
  dec[100].bytes = 0;

  strcpy(dec[101].instruction, "lsub");
  dec[101].bytes = 0;

  strcpy(dec[102].instruction, "fsub");
  dec[102].bytes = 0;

  strcpy(dec[103].instruction, "dsub");
  dec[103].bytes = 0;

  strcpy(dec[104].instruction, "imul");
  dec[104].bytes = 0;

  strcpy(dec[105].instruction, "lmul");
  dec[105].bytes = 0;

  strcpy(dec[106].instruction, "fmul");
  dec[106].bytes = 0;

  strcpy(dec[107].instruction, "dmul");
  dec[107].bytes = 0;

  strcpy(dec[108].instruction, "idiv");
  dec[108].bytes = 0;

  strcpy(dec[109].instruction, "ldiv");
  dec[109].bytes = 0;

  strcpy(dec[110].instruction, "fdiv");
  dec[110].bytes = 0;

  strcpy(dec[111].instruction, "ddiv");
  dec[111].bytes = 0;

  strcpy(dec[112].instruction, "irem");
  dec[112].bytes = 0;

  strcpy(dec[113].instruction, "lrem");
  dec[113].bytes = 0;

  strcpy(dec[114].instruction, "frem");
  dec[114].bytes = 0;

  strcpy(dec[115].instruction, "drem");
  dec[115].bytes = 0;

  strcpy(dec[116].instruction, "ineg");
  dec[116].bytes = 0;

  strcpy(dec[117].instruction, "lneg");
  dec[117].bytes = 0;

  strcpy(dec[118].instruction, "fneg");
  dec[118].bytes = 0;

  strcpy(dec[119].instruction, "dneg");
  dec[119].bytes = 0;

  strcpy(dec[120].instruction, "ishl");
  dec[120].bytes = 0;

  strcpy(dec[121].instruction, "lshl");
  dec[121].bytes = 0;

  strcpy(dec[122].instruction, "ishr");
  dec[122].bytes = 0;

  strcpy(dec[123].instruction, "lshr");
  dec[123].bytes = 0;

  strcpy(dec[124].instruction, "iushr");
  dec[124].bytes = 0;

  strcpy(dec[125].instruction, "lushr");
  dec[125].bytes = 0;

  strcpy(dec[126].instruction, "iand");
  dec[126].bytes = 0;

  strcpy(dec[127].instruction, "land");
  dec[127].bytes = 0;

  strcpy(dec[128].instruction, "ior");
  dec[128].bytes = 0;

  strcpy(dec[129].instruction, "lor");
  dec[129].bytes = 0;

  strcpy(dec[130].instruction, "ixor");
  dec[130].bytes = 0;

  strcpy(dec[131].instruction, "lxor");
  dec[131].bytes = 0;

  strcpy(dec[132].instruction, "iinc");
  dec[132].bytes = 2;

  strcpy(dec[133].instruction, "i2l");
  dec[133].bytes = 0;

  strcpy(dec[134].instruction, "i2f");
  dec[134].bytes = 0;

  strcpy(dec[135].instruction, "i2d");
  dec[135].bytes = 0;

  strcpy(dec[136].instruction, "l2i");
  dec[136].bytes = 0;

  strcpy(dec[137].instruction, "l2f");
  dec[137].bytes = 0;

  strcpy(dec[138].instruction, "l2d");
  dec[138].bytes = 0;

  strcpy(dec[139].instruction, "f2i");
  dec[139].bytes = 0;

  strcpy(dec[140].instruction, "f2l");
  dec[140].bytes = 0;

  strcpy(dec[141].instruction, "f2d");
  dec[141].bytes = 0;

  strcpy(dec[142].instruction, "d2i");
  dec[142].bytes = 0;

  strcpy(dec[143].instruction, "d2l");
  dec[143].bytes = 0;

  strcpy(dec[144].instruction, "d2f");
  dec[144].bytes = 0;

  strcpy(dec[145].instruction, "i2b");
  dec[145].bytes = 0;

  strcpy(dec[146].instruction, "i2c");
  dec[146].bytes = 0;

  strcpy(dec[147].instruction, "i2s");
  dec[147].bytes = 0;

  strcpy(dec[148].instruction, "lcmp");
  dec[148].bytes = 0;

  strcpy(dec[149].instruction, "fcmpl");
  dec[149].bytes = 0;

  strcpy(dec[150].instruction, "fcmpg");
  dec[150].bytes = 0;

  strcpy(dec[151].instruction, "dcmpl");
  dec[151].bytes = 0;

  strcpy(dec[152].instruction, "dcmpg");
  dec[152].bytes = 0;

  strcpy(dec[153].instruction, "ifeq");
  dec[153].bytes = 2;

  strcpy(dec[154].instruction, "ifne");
  dec[154].bytes = 2;

  strcpy(dec[155].instruction, "iflt");
  dec[155].bytes = 2;

  strcpy(dec[156].instruction, "ifge");
  dec[156].bytes = 2;

  strcpy(dec[157].instruction, "ifgt");
  dec[157].bytes = 2;

  strcpy(dec[158].instruction, "ifle");
  dec[158].bytes = 2;

  strcpy(dec[159].instruction, "if_icmpeq");
  dec[159].bytes = 2;

  strcpy(dec[160].instruction, "if_icmpne");
  dec[160].bytes = 2;

  strcpy(dec[161].instruction, "if_icmplt");
  dec[161].bytes = 0;

  strcpy(dec[162].instruction, "if_icmpge");
  dec[162].bytes = 0;

  strcpy(dec[163].instruction, "if_icmpgt");
  dec[163].bytes = 0;

  strcpy(dec[164].instruction, "if_icmple");
  dec[164].bytes = 0;

  strcpy(dec[165].instruction, "if_acmpeq");
  dec[165].bytes = 2;

  strcpy(dec[166].instruction, "if_acmpne");
  dec[166].bytes = 2;

  strcpy(dec[167].instruction, "goto");
  dec[167].bytes = 2;

  strcpy(dec[168].instruction, "jsr");
  dec[168].bytes = 2;

  strcpy(dec[169].instruction, "ret");
  dec[169].bytes = 1;

  strcpy(dec[170].instruction, "tableswitch");

  dec[170].bytes = 14;

  strcpy(dec[171].instruction, "lookupswitch");

  dec[171].bytes = 10;

  strcpy(dec[172].instruction, "ireturn");
  dec[172].bytes = 0;

  strcpy(dec[173].instruction, "lreturn");
  dec[173].bytes = 0;

  strcpy(dec[174].instruction, "freturn");
  dec[174].bytes = 0;

  strcpy(dec[175].instruction, "dreturn");
  dec[176].bytes = 0;

  strcpy(dec[176].instruction, "areturn");
  dec[176].bytes = 0;

  strcpy(dec[177].instruction, "return");
  dec[177].bytes = 0;

  strcpy(dec[178].instruction, "getstatic");
  dec[178].bytes = 2;

  strcpy(dec[179].instruction, "putstatic");
  dec[179].bytes = 2;

  strcpy(dec[180].instruction, "getfield");
  dec[180].bytes = 2;

  strcpy(dec[181].instruction, "putfield");
  dec[181].bytes = 2;

  strcpy(dec[182].instruction, "invokevirtual");
  dec[182].bytes = 2;

  strcpy(dec[183].instruction, "invokespecial");
  dec[183].bytes = 2;

  strcpy(dec[184].instruction, "invokestatic");
  dec[184].bytes = 2;

  strcpy(dec[185].instruction, "invokeinterface");
  dec[185].bytes = 4;

  strcpy(dec[186].instruction, "invokedynamic");
  dec[186].bytes = 4;

  strcpy(dec[187].instruction, "new");
  dec[187].bytes = 2;

  strcpy(dec[188].instruction, "newarray");
  dec[188].bytes = 1;

  strcpy(dec[189].instruction, "anewarray");
  dec[189].bytes = 2;

  strcpy(dec[190].instruction, "arraylength");
  dec[190].bytes = 0;

  strcpy(dec[191].instruction, "athrow");
  dec[191].bytes = 0;

  strcpy(dec[192].instruction, "checkcast");
  dec[192].bytes = 2;

  strcpy(dec[193].instruction, "instanceof");
  dec[193].bytes = 2;

  strcpy(dec[194].instruction, "monitorenter");
  dec[194].bytes = 0;

  strcpy(dec[195].instruction, "monitorexit");
  dec[195].bytes = 0;

  strcpy(dec[196].instruction, "wide");

  dec[196].bytes = 3;

  strcpy(dec[197].instruction, "multianewarray");
  dec[197].bytes = 3;

  strcpy(dec[198].instruction, "ifnull");
  dec[198].bytes = 2;

  strcpy(dec[199].instruction, "ifnonnull");
  dec[199].bytes = 2;

  strcpy(dec[200].instruction, "goto_w");
  dec[200].bytes = 4;

  strcpy(dec[201].instruction, "jsr_w");
  dec[201].bytes = 4;

  strcpy(dec[202].instruction, "breakpoint");
  dec[202].bytes = 0;

  strcpy(dec[254].instruction, "impdep1");
  dec[254].bytes = 0;

  strcpy(dec[255].instruction, "impdep2");
  dec[255].bytes = 0;
}
