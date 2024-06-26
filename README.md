# jclass-reader

## Build

Para gerar o executável:

```
make all
```

## Execute

Para executar o programa:

```
./jclass-runner <caminho/classe> [-cp <classpath>]
```

## Observações

Utilize o nome da classe sem a extensão (.class). Este projeto segue o mesmo método de resolução de caminhos que o executável `java`, então execute os comandos usando o `jclass-runner` como você executaria usando `java`.

Junto ao código fonte do projeto há uma pasta chamada `classpath`. Esta pasta corresponde ao classpath padrão utilizado pelo programa (`./classpath`) quando não se define um classpath de usuário utilizando a flag `-cp` . Dentro desta pasta há um binário compilado da classe `java.lang.Object`.

## Documentação

Para gerar a documentação, basta instalar o doxygen na sua máquina e executar:

```
doxygen Doxyfile
```

Isso irá criar uma pasta 'Documentacao', dentro dela, abra o arquivo index.html para visualizar a documentação.
