# pe-analyzer-cpp

Parser de arquivos PE (.exe, .dll) em C++17 puro, sem dependências. Lê header DOS, COFF, Optional, tabela de seções, imports, exports e calcula entropia por seção. Funciona em Linux e Windows porque só lê bytes do arquivo.

## Por que eu fiz isso

Queria entender o formato que o Windows loader lê antes de executar qualquer binário. Comecei pelo MZ e terminei listando imports reais de executáveis de 5 MB sem quebrar em binário packado ou seção virtual.

## Como funciona

Leitura em três etapas, todas com validação de limites antes de tocar no buffer.

1. Headers: valida MZ em 0x00, lê e_lfanew em 0x3C, valida assinatura PE em nt, lê COFF (Machine, NumberOfSections, TimeDateStamp, SizeOfOptionalHeader, Characteristics). Rejeita se NumberOfSections for 0 ou maior que 96, ou se SizeOfOptionalHeader estiver fora de 28 a 1024.

2. Sections e RVA: resolve diretórios de dados (Export em 0, Import em 1), lê tabela de seções de 40 bytes cada. Conversão RVA para offset passa pela tabela de seções, com fallback para SizeOfHeaders. Seção com PointerToRawData zero ou fora do arquivo é tratada como virtual, entropia zero, sem abortar o parse.

3. Imports, exports e entropia: importa via IMAGE_IMPORT_DESCRIPTOR até descritor nulo, limite de 512 DLLs, 4096 thunks por DLL. Distingue PE32 e PE32+ pelo flag de ordinal (0x80000000 e 0x8000000000000000). Exporta via IMAGE_EXPORT_DIRECTORY com limite de 8192 nomes. Entropia de Shannon por seção para indicar packing ou recurso comprimido.

## Segurança

Nenhum cast direto em buffer não validado. Toda leitura passa por Reader::can com checagem de overflow. Limite de arquivo em 100 MB. CString limitada a 256 bytes com rejeição de bytes fora de 32 a 126. Contadores com teto para impedir loop infinito em arquivo corrompido. Compila com -Wall -Wextra -Wpedantic -Werror, fortify e stack protector.

## Estrutura

    src/
      main.cpp         CLI e formatação de saída
      pe_parser.cpp    parsing e validação
    include/
      pe_parser.hpp    structs e Reader com bounds check
    examples/
      output-launcher_v5.txt       PE32+ x64 de 5.8 MB
      output-bluestacks-x86.txt    PE32 x86 de 953 KB
    CMakeLists.txt
    README.md

## Como compilar

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j
    ./build/pe-analyzer target.exe

No Windows com Visual Studio usa o mesmo CMakeLists. Precisa de compilador com C++17.

## Como rodar

    pe-analyzer <file.exe>

Retorno 0 em sucesso, 1 em argumento inválido, 2 em falha de parse. Erro vai para stderr no formato parse_failed: motivo.

## Lendo o resultado

    VA  endereço virtual onde a seção carrega
    VS  tamanho virtual
    RAW tamanho no arquivo, zero significa seção virtual como .bss
    ENT entropia de 0 a 8, acima de 7 indica compressão ou cifra
    CH  characteristics da seção

Exemplo real de saída em executável x64:

    .text    VA=0x00001000 VS=  109144 RAW=  109568 ENT=6.185 CH=0x60000060
    .rsrc    VA=0x00029000 VS= 5740120 RAW= 5740544 ENT=7.053 CH=0x40000040

## Testes validados

    launcher_v5.exe de 5884416 bytes, PE32+ x64, 11 seções, 2 DLLs, 76 funções — OK
    launcher_dev_v2.exe de 5817344 bytes, PE32+ x64, 11 seções, 2 DLLs, 55 funções — OK
    BlueStacksInstaller de 953352 bytes, PE32 x86, 4 seções, 4 DLLs, 120 funções — OK
    /bin/ls em ELF rejeitado com bad_mz — OK
    binário próprio rejeitado com bad_mz — OK
    caminho inexistente rejeitado com open_failed — OK
    sem argumento retorna usage com código 1 — OK

Saídas completas em examples/.

## Limitações

Só leitura. Não modifica, não faz rebuild, não resolve delay imports nem bound imports como entrada separada. Não trata .NET metadata nem certificado Authenticode. Export forwarding por string não é resolvido para RVA.

## Próximos passos

Suporte a delay import directory, cálculo de imphash, detecção de packer por heurística de entropia mais nomes de seção, saída em JSON para uso por EDR.

## Autor

Rafael Nunes — [@Rafaelnunes-alt2](https://github.com/Rafaelnunes-alt2)
