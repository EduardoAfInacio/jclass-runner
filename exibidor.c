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
 * Arquivo que contém funções destinadas a imprimir detalhadamente no prompt a estrutura do arquivo Classfile que foi lido.
 * As informações exibidas incluem detalhes sobre a pool de constantes, versões, flags de acesso, métodos,
 * atributos, entre outros componentes críticos do Classfile.
 *
 * Para facilitar a análise e documentação, ou para simplesmente armazenar as saídas para revisão posterior,
 * é possível redirecionar a saída do prompt para um arquivo de texto. Para fazer isso, execute o programa
 * da seguinte forma:
 * ./jvm [nome do arquivo].class 1 > log.txt
 *
 * Onde '[nome do arquivo].class' deve ser substituído pelo nome real do arquivo Classfile que você deseja
 * inspecionar. A saída será então salva no arquivo 'log.txt'.
 */

#include "./includes/exibidor.h"

void print_prompt(ClassFile* cf) {
  printf("----General Information----\n");
  printf("CAFEBABE: 0x%0x \n", cf->magic);
  printf("Minor version: %d \n", cf->minor_version);
  printf("Major version: %d \n", cf->major_version);
  printf("Constant Pool Count: %d \n", cf->constant_pool_count);
  printf("----End General----\n\n");

  printf("----Constant Pool----\n");

  for (int i = 0; i < cf->constant_pool_count - 1; i++) {
    int tag = cf->constant_pool[i].tag;

    switch (tag) {
      case CONSTANT_Class:
        printf("[%d] CONSTANT_Class_info - name_index: cp info #%d ", i + 1,
               cf->constant_pool[i].info.Class.name_index);
        print_string_pool(cf->constant_pool,
                          cf->constant_pool[i].info.Class.name_index - 1);
        printf("\n");

        break;

      case CONSTANT_Fieldref:
        printf("[%d] CONSTANT_Fieldref_info - class_index: cp info #%d ", i + 1,
               cf->constant_pool[i].info.Fieldref.class_index);
        print_string_pool(cf->constant_pool,
                          cf->constant_pool[i].info.Fieldref.class_index - 1);
        printf("\n");

        printf(
            "[%d] CONSTANT_Fieldref_info - name_and_type_index: cp info #%d ",
            i + 1, cf->constant_pool[i].info.Fieldref.name_and_type_index);
        print_string_pool(
            cf->constant_pool,
            cf->constant_pool[i].info.Fieldref.name_and_type_index - 1);
        printf("\n");

        break;

      case CONSTANT_NameAndType:
        printf("[%d] CONSTANT_NameAndType_info - name_index: cp info info #%d ",
               i + 1, cf->constant_pool[i].info.NameAndType.name_index);
        print_string_pool(cf->constant_pool,
                          cf->constant_pool[i].info.NameAndType.name_index - 1);
        printf("\n");

        printf(
            "[%d] CONSTANT_NameAndType_info - descriptor_index: cp info #%d ",
            i + 1, cf->constant_pool[i].info.NameAndType.descriptor_index);
        print_string_pool(
            cf->constant_pool,
            cf->constant_pool[i].info.NameAndType.descriptor_index - 1);
        printf("\n");

        break;

      case CONSTANT_Utf8:
        printf("[%d] CONSTANT_Utf8_info - length:%d\n", i + 1,
               cf->constant_pool[i].info.Utf8.length);
        printf("[%d] CONSTANT_Utf8_info - bytes: %s\n", i + 1,
               cf->constant_pool[i].info.Utf8.bytes);
        break;

      case CONSTANT_Methodref:
        printf("[%d] CONSTANT_Methodref_info - class_index: cp info #%d ",
               i + 1, cf->constant_pool[i].info.Methodref.class_index);
        print_string_pool(cf->constant_pool,
                          cf->constant_pool[i].info.Methodref.class_index - 1);
        printf("\n");

        printf(
            "[%d] CONSTANT_Methodref_info - name_and_type_index: cp info #%d ",
            i + 1, cf->constant_pool[i].info.Methodref.name_and_type_index);
        print_string_pool(
            cf->constant_pool,
            cf->constant_pool[i].info.Methodref.name_and_type_index - 1);
        printf("\n");

        break;

      case CONSTANT_InterfaceMethodref:
        printf(
            "[%d] CONSTANT_InterfaceMethodref_info - class_index: cp info #%d ",
            i + 1, cf->constant_pool[i].info.InterfaceMethodref.class_index);
        print_string_pool(cf->constant_pool,
                          cf->constant_pool[i].info.Methodref.class_index - 1);
        printf("\n");

        printf(
            "[%d] CONSTANT_InterfaceMethodref_info - name_and_type_index: cp "
            "info #%d ",
            i + 1,
            cf->constant_pool[i].info.InterfaceMethodref.name_and_type_index);
        print_string_pool(
            cf->constant_pool,
            cf->constant_pool[i].info.Methodref.name_and_type_index - 1);
        printf("\n");

        break;

      case CONSTANT_String:
        printf("[%d] CONSTANT_String_info - string_index: cp info #%d ", i + 1,
               cf->constant_pool[i].info.String.string_index);
        print_string_pool(cf->constant_pool,
                          cf->constant_pool[i].info.String.string_index - 1);
        printf("\n");
        break;

      case CONSTANT_Integer:
        printf("[%d] CONSTANT_Integer_info - bytes:%d\n", i + 1,
               cf->constant_pool[i].info.Integer.bytes);
        break;

      case CONSTANT_Float:
        printf("[%d] CONSTANT_Float_info - bytes:%d\n", i + 1,
               cf->constant_pool[i].info.Float.bytes);

        float fVal1;
        memcpy(&fVal1, &cf->constant_pool[i].info.Float.bytes, sizeof(int32_t));
        printf("[%d] CONSTANT_Float_info - valor:%f\n", i + 1, fVal1);
        break;
      case CONSTANT_Double:
        printf("[%d] CONSTANT_Double_info - high-bytes: 0x%0x\n", i + 1,
               cf->constant_pool[i].info.Double.high_bytes);
        printf("[%d] CONSTANT_Double_info - low-bytes: 0x%0x\n", i + 1,
               cf->constant_pool[i].info.Double.low_bytes);

        int64_t dVal = cf->constant_pool[i].info.Double.high_bytes;

        dVal <<= 32;

        dVal = dVal + cf->constant_pool[i].info.Double.low_bytes;

        double valorDouble1;
        memcpy(&valorDouble1, &dVal, sizeof(int64_t));

        printf("[%d] CONSTANT_Double_info - valor: %f\n", i + 1, valorDouble1);
        break;
      default:
        break;
    }
  }
  printf("----End Pool----\n\n");

  printf("----Second General Info----\n");
  printf("Access Flags: 0x%0x ", cf->access_flags);
  print_access_flags(cf->access_flags);
  printf("This Class: cp info #%d ", cf->this_class);
  print_string_pool(cf->constant_pool, cf->this_class - 1);
  printf("\n");
  printf("Super Class: cp info #%d ", cf->super_class);
  print_string_pool(cf->constant_pool, cf->super_class - 1);
  printf("\n");
  printf("interfaces_count: %d\n", cf->interfaces_count);
  if (cf->interfaces_count != 0) {
    printf("---- Interfaces ----\n");

    for (int i = 0; i < cf->interfaces_count; i++) {
      printf("Interface: cp info #%d ", cf->interfaces[i]);
      print_string_pool(cf->constant_pool, cf->interfaces[i] - 1);
      printf("\n");
    }

    printf("---- End Interface ----\n");
  }
  printf("Fields Count: %d\n", cf->fields_count);
  if (cf->fields_count != 0) {
    printf("----Fields----\n");
    for (int i = 0; i < cf->fields_count; i++) {
      printf("Name: cp info #%d ", cf->fields[i].name_index);
      print_string_pool(cf->constant_pool, cf->fields[i].name_index - 1);
      printf("\n");
      printf("Descriptor: cp info #%d ", cf->fields[i].descriptor_index);
      print_string_pool(cf->constant_pool, cf->fields[i].descriptor_index - 1);
      printf("\n");
      printf("Access Flag: 0x%x ", cf->fields[i].access_flags);
      print_access_flags(cf->fields[i].access_flags);

      for (int j = 0; j < cf->fields[i].attributes_count; j++) {
        printf("\t\t----Attribute Info do Field----\n");

        printf("attribute_name_index: cp info #%d\n",
               cf->fields[i].attributes->name_index);
        printf("attribute_length: %d\n",
               cf->fields[i].attributes->length);

        printf("constant_value_index: cp info #%d",
               cf->fields[i].attributes->index);
        print_string_pool(cf->constant_pool,
                          cf->fields[i].descriptor_index - 1);
        printf("\n");

        printf("\t\t----Fim da Attribute Info do Field----\n");
      }
    }

    printf("----End Fields----\n");
  }

  print_methods(cf);

  printf("attributes_count: %d\n", cf->attributes_count);
  if (cf->attributes_count != 0) {
    Attribute* cp = cf->attributes;

    for (uint16_t i = 0; i < cf->attributes_count; cp++) {
      printf("----Attributes Info----\n");
      printf("attribute_name_index: cp info #%d ", cp->name_index);
      print_string_pool(cf->constant_pool, cp->name_index - 1);
      printf("\n");
      printf("attribute_length: %d\n", cp->length);
      for (uint32_t j = 0; j < cp->length; cp->info++) {
        if (*(cp->info) != 0) {
          printf("Source file name index: cp info #%d ", *(cp->info));
          print_string_pool(cf->constant_pool, *(cp->info) - 1);
          printf("\n");
        }
        j++;
      }
      printf("----End Attributes----\n\n");
      i++;
    }
  }
  printf("----End Second General----\n\n");
}

void print_access_flags(uint16_t access_flags) {
  if (access_flags == 0x0000) printf("\n");
  if (access_flags == 0x0001 || access_flags == 0x0021) printf("Public\n");
  if (access_flags == 0x0009) printf("Public Static\n");
  if (access_flags == 0x0002) printf("Private\n");
  if (access_flags == 0x0004) printf("Protected\n");
  if (access_flags == 0x0008) printf("Static\n");
  if (access_flags == 0x0010) printf("Final\n");
  if (access_flags == 0x0020) printf("Super\n");
  if (access_flags == 0x0200) printf("Interface\n");
  if (access_flags == 0x0400) printf("Abstract\n");
}

void print_methods(ClassFile* cf) {
  uint16_t name_ind;
  uint32_t att_len;
  uint16_t methods_count = cf->methods_count;

  printf("Methods Count: %d\n", cf->methods_count);
  if (methods_count == 0)
    return;
  else {
    Method* cp = cf->methods;
    for (int i = 0; i < methods_count; cp++, i++) {
      printf("\n----Method %d----\n", i);
      printf("access_flag: 0x%0x ", cp->access_flags);
      print_access_flags(cp->access_flags);
      printf("name_index: cp info #%d ", cp->name_index);
      print_string_pool(cf->constant_pool, cp->name_index - 1);
      printf("\n");
      printf("descriptor_index: cp info #%d ", cp->descriptor_index);
      print_string_pool(cf->constant_pool, cp->descriptor_index - 1);
      printf("\n");
      printf("attributes_count: %d\n", cp->attributes_count);

      print_code(cf, cp->code_attribute);

      if (cp->attributes_count == 2) {
        print_exc(cf, cp->exception_attribute);
      }

      printf("----End Method %d----\n", i);
    }
    printf("----End Method----\n\n");
  }
}

void print_code(ClassFile* cf, CodeAttribute* cd_atrb) {
  int opcode, pos_referencia;
  int bytes_preench, offsets;
  uint32_t default_v, low, high, npairs, temp;

  if (cd_atrb == NULL) {
    return;
  }

  printf("\n----Code Info----\n");
  printf("attribute_name_index: cp info #%d ", cd_atrb->name_index);
  print_string_pool(cf->constant_pool, cd_atrb->name_index - 1);
  printf("\n");
  printf("attribute_length: %d\n", cd_atrb->length);

  printf("Stack max size: %d\n", cd_atrb->max_stack);
  printf("Local variable max: %d\n", cd_atrb->max_locals);
  printf("Code size: %d\n", cd_atrb->code_length);

  decoder dec[MAX_INSTRUCTIONS_NUMBER];
  start_decoder(dec);

  for (uint32_t k = 0; k < cd_atrb->code_length;) {
    opcode = cd_atrb->code[k];
    printf("%d: %s  ", k, dec[opcode].instruction);

    k++;

    if (opcode == TABLESWITCH) {
      pos_referencia = k - 1;

      bytes_preench = (4 - (k % 4)) % 4;
      for (int l = 0; l < bytes_preench; l++) {
        k++;
      }

      default_v = 0;
      for (int l = 0; l < 4; l++) {
        default_v = (default_v << 4) + cd_atrb->code[k];
        k++;
      }

      low = 0;
      for (int l = 0; l < 4; l++) {
        low = (low << 4) + cd_atrb->code[k];
        k++;
      }

      high = 0;
      for (int l = 0; l < 4; l++) {
        high = (high << 4) + cd_atrb->code[k];
        k++;
      }

      printf("  de  %d ateh %d\n", low, high);

      offsets = 1 + high - low;
      for (int l = 0; l < offsets; l++) {
        temp = 0;
        for (int i = 0; i < 4; i++) {
          temp = (temp << 4) + cd_atrb->code[k];
          k++;
        }

        printf("\t%d: %d (+%d)\n", l, (pos_referencia + temp), temp);
      }
      printf("\tdefault: %d (+%d)\n", (default_v + pos_referencia), default_v);
    }

    else if (opcode == LOOKUPSWITCH) {
      pos_referencia = k - 1;

      bytes_preench = (4 - (k % 4)) % 4;
      for (int l = 0; l < bytes_preench; l++) {
        k++;
      }

      default_v = 0;
      for (int l = 0; l < 4; l++) {
        default_v = (default_v << 4) + cd_atrb->code[k];
        k++;
      }

      npairs = 0;
      for (int l = 0; l < 4; l++) {
        npairs = (npairs << 4) + cd_atrb->code[k];
        k++;
      }

      printf("  %d\n", npairs);

      for (uint32_t l = 0; l < npairs; l++) {
        temp = 0;
        for (int i = 0; i < 4; i++) {
          temp = (temp << 8) + cd_atrb->code[k];
          k++;
        }
        printf("\t%d:  ", temp);

        temp = 0;
        for (int i = 0; i < 4; i++) {
          temp = (temp << 8) + cd_atrb->code[k];
          k++;
        }
        printf("%d (+%d)\n", temp + pos_referencia, temp);
      }
      printf("\tdefault: %d (+%d)\n", default_v + pos_referencia, default_v);

    }

    else if (opcode == WIDE) {
      printf("\n");

      opcode = cd_atrb->code[k];
      k++;

      if (opcode == ILOAD || opcode == FLOAD || opcode == ALOAD ||
          opcode == LLOAD || opcode == DLOAD || opcode == ISTORE ||
          opcode == FSTORE || opcode == ASTORE || opcode == LSTORE ||
          opcode == DSTORE || opcode == RET) {
        printf("%d: %s  ", k - 1, dec[opcode].instruction);

        k++;

        k++;
        temp = cd_atrb->code[k - 2] << 8;
        temp += cd_atrb->code[k - 1];
        printf(" %u \n", temp);
      }

      else if (opcode == IINC) {
        printf("%d: iinc ", k - 1);

        k++;

        k++;

        temp = cd_atrb->code[k - 2] << 8;
        temp += cd_atrb->code[k - 1];
        printf(" %u ", temp);

        k++;

        k++;

        temp = cd_atrb->code[k - 2] << 8;
        temp += cd_atrb->code[k - 1];
        printf(" por  %u \n", temp);
      }

      else {
        printf("arquivo .class invalido na instrucao wide");
        exit(1);
      }

    }

    else {
      int num_bytes = dec[opcode].bytes;
      for (int l = 0; l < num_bytes; l++) {
        printf("%d  ", cd_atrb->code[k]);
        if (cd_atrb->code[k] != 0)
          print_string_pool(cf->constant_pool, cd_atrb->code[k] - 1);

        k++;
      }
      printf("\n");
    }
  }
}

void print_exc(ClassFile* cf, ExceptionAttribute* exc_atrb) {
  printf("\n----Exception Info----\n");
  printf("attribute_name_index: cp info #%d ", exc_atrb->name_index);
  print_string_pool(cf->constant_pool, exc_atrb->name_index - 1);
  printf("\n");
  printf("# - Excecao\n");
  for (int k = 0; k < exc_atrb->number_of_exceptions; k++) {
    printf("%d - %d\n", k, exc_atrb->exception_index_table[k]);
  }
}

void print_string_pool(ConstantPool* cp, int pos_pool) {
  int tag;

  tag = cp[pos_pool].tag;

  if (tag == CONSTANT_Utf8) {
    printf("%s  ", cp[pos_pool].info.Utf8.bytes);
    return;
  }

  switch (tag) {
    case CONSTANT_Class:
      print_string_pool(cp, cp[pos_pool].info.Class.name_index - 1);
      break;

    case CONSTANT_Fieldref:
      print_string_pool(cp, cp[pos_pool].info.Fieldref.class_index - 1);
      print_string_pool(cp, cp[pos_pool].info.Fieldref.name_and_type_index - 1);
      break;

    case CONSTANT_NameAndType:
      print_string_pool(cp, cp[pos_pool].info.NameAndType.name_index - 1);
      print_string_pool(cp, cp[pos_pool].info.NameAndType.descriptor_index - 1);
      break;

    case CONSTANT_Methodref:
      print_string_pool(cp, cp[pos_pool].info.Methodref.class_index - 1);
      print_string_pool(cp,
                        cp[pos_pool].info.Methodref.name_and_type_index - 1);
      break;

    case CONSTANT_InterfaceMethodref:
      print_string_pool(cp,
                        cp[pos_pool].info.InterfaceMethodref.class_index - 1);
      print_string_pool(
          cp, cp[pos_pool].info.InterfaceMethodref.name_and_type_index - 1);
      break;

    case CONSTANT_String:
      print_string_pool(cp, cp[pos_pool].info.String.string_index - 1);
      break;

    case CONSTANT_Integer:

      break;

    case CONSTANT_Float:

      break;

    default:
      break;
  }
}
