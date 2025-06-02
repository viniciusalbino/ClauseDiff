2. Pilha Tecnológica Recomendada para o MVP

Para o ClauseDiff MVP, a seguinte stack tecnológica é sugerida, escolhida por equilibrar rapidez de desenvolvimento e capacidade de atender aos requisitos:
	•	Frontend: Next.js (React) – oferece flexibilidade de criar uma Single Page Application com React, além de rotas API embutidas se necessário. O Next.js facilita o deploy no Vercel e suporta SSR ou geração estática, embora neste MVP podemos usar principalmente funcionalidades client-side para interatividade. Para estilos, usar TailwindCSS pela agilidade em criar um design responsivo e consistente por meio de classes utilitárias. Configurar as fontes Source Sans Pro (para textos gerais e UI) e Source Code Pro (fonte monoespaçada, para possíveis trechos de diferença ou conteúdo que precise alinhamento fixo) – ambas podem ser obtidas via Google Fonts. Essa combinação garante um visual limpo e profissional.
	•	Backend: Node.js com um framework leve como Express para construir uma API RESTful. O backend exporá endpoints (por exemplo, POST /diff para fazer upload dos dois arquivos e retornar o resultado da comparação, GET /pdf para gerar/download do PDF, etc.). Utilizaremos o Supabase como serviço gerenciado de autenticação e banco de dados Postgres. A princípio, a autenticação será básica (p.ex. permitir login com Google OAuth via Supabase Auth) para restringir o acesso se desejado. O Supabase também pode ser usado para armazenar logs temporários – por exemplo, registros das comparações realizadas (metadados, não necessariamente o conteúdo dos documentos por questões de privacidade) ou armazenamento efêmero dos resultados para permitir geração de PDF on-demand. O uso do Supabase evita precisar montar todo um sistema de autenticação do zero e fornece APIs prontas para login/logout e gestão de usuários.
	•	Processamento de Documentos:
	•	mammoth.js – biblioteca que converte arquivos .docx em HTML ou texto de forma relativamente fiel, mantendo estrutura sem trazer excessos de estilo. Vamos usá-la para extrair o conteúdo textual dos documentos do usuário. Assim garantimos que diferenças de formatação não entrem no cálculo – o foco são diferenças de texto. A saída pode ser HTML sem formatação pesada, ou mesmo apenas texto simples com marcações mínimas (parágrafos, listas).
	•	diff-match-patch – algoritmo de diff de alta performance (original do Google) disponível em JavaScript. Ele compara duas strings e identifica trechos inseridos, removidos ou iguais. Vamos aplicá-lo no texto extraído dos documentos para obter as diferenças. A biblioteca permite cleanup semântico, ou seja, refinamento do diff para evitar detecções muito pequenas ou fragmentadas, melhorando a legibilidade das mudanças.
	•	Puppeteer – biblioteca que controla um navegador Chromium headless. Será usada para tirar uma “foto” em PDF da visualização de diferenças. Em outras palavras, geraremos uma página HTML (com o resultado das diferenças e marcações coloridas) e o Puppeteer irá renderizá-la e exportar em formato PDF. Isso facilita criar um relatório portátil das alterações, preservando as cores e estilos de destaque definidos.
	•	Deploy: Vercel ou Railway – Para hospedar a aplicação, podemos usar Vercel para o frontend (é a plataforma nativa do Next.js, facilitando muito o deploy contínuo). O backend Node/Express pode rodar no Railway, que permite hospedar facilmente serviços Node com suporte a execução contínua e agendada (necessário para o job de limpeza de arquivos temporários, por exemplo). Em desenvolvimento local, o frontend Next rodará em um porta (ex: 3000) e o backend Express em outra (ex: 3001), e configuramos o frontend para chamar a API do backend adequadamente. Em produção, podemos integrar tudo no Vercel (usando API Routes do Next para a lógica backend), porém a geração de PDF com Puppeteer e jobs agendados funcionam melhor em um serviço contínuo – por isso, optar por Railway para o backend pode ser mais estável. Ambos Vercel e Railway suportam configuração de variáveis de ambiente (como chaves do Supabase, URLs etc.), então manteremos segredos fora do código.

Observação: Poderíamos realizar parte do processamento no frontend (mammoth.js e diff-match-patch rodam em JS puro e poderiam ser executados no browser, economizando chamadas ao servidor). Contudo, optamos por fazê-lo no backend para:
	•	Centralizar a lógica de comparação (futuro versionamento, log de uso, etc.).
	•	Evitar carregar toda a biblioteca de diff no cliente (performance em dispositivos do usuário).
	•	Permitir a geração do PDF no servidor facilmente após ter o resultado.
Além disso, no backend podemos mais facilmente limitar tamanho de arquivos, fazer validações adicionais e garantir a remoção dos dados após uso, preservando confidencialidade.

3. Layout Inicial e Identidade Visual

O design da interface do ClauseDiff seguirá diretrizes minimalistas e funcionais, garantindo clareza na visualização das diferenças. Os principais pontos da identidade visual e layout são:
	•	Layout Dividido: A interface principal será dividida em duas seções lado a lado. Por exemplo, após o upload dos documentos, a coluna da esquerda exibirá o texto do documento original e a coluna da direita exibirá o texto do documento modificado. Essa visualização paralela facilita comparar cláusulas linha a linha. Cada coluna ocupará ~50% da largura da tela em desktops (em telas menores, pode-se ajustar para empilhar verticalmente ou permitir scroll horizontal na comparação). No topo ou em algum lugar visível, deve haver uma indicação de qual lado é a versão antiga e qual é a nova, para evitar confusão.
	•	Barra/Painel de Resumo: Além das colunas de comparação, haverá um painel de resumo das mudanças, possivelmente alinhado à direita da tela (como uma barra lateral estreita) ou no topo em formato de barra horizontal. Esse resumo apresentará informações como: número total de adições, remoções e modificações detectadas. Poderá também listar de forma concisa as alterações, por exemplo:
	•	Adições: 5 trechos adicionados (marcados em verde)
	•	Remoções: 3 trechos removidos (marcados em vermelho)
	•	Modificações: 2 trechos modificados (marcados em amarelo)
Cada item do resumo pode vir acompanhado de um ícone minimalista (por exemplo, um ícone de “mais” em verde para adições, “menos” em vermelho para remoções, e talvez um ícone de edição ou alerta em amarelo para modificações). O objetivo é dar ao usuário um panorama rápido do que mudou, sem precisar ler todo o texto. Em versões futuras, esse painel poderia permitir clicar em um item para rolar a tela até a alteração correspondente.
	•	Cores e Destaques: O esquema de cores será clean, usando principalmente branco ou tons neutros para o fundo da aplicação e textos em preto/cinza para conteúdo padrão. As cores vibrantes serão usadas apenas para destacar as diferenças:
	•	Trechos adicionados no documento novo aparecerão marcados em verde (ex.: texto com fundo verde claro, ou texto verde sublinhado).
	•	Trechos removidos do documento original aparecerão em vermelho (ex.: texto com fundo vermelho claro e talvez tachado para indicar remoção).
	•	Trechos modificados (alterados de uma versão para outra) podem ser destacados em amarelo para chamar atenção. Por exemplo, se numa frase apenas algumas palavras foram alteradas, essas palavras podem ter um highlight amarelo no fundo em ambas versões, indicando “mudança de conteúdo”. Em conjunto com as marcações verde/vermelho, o amarelo evidencia a área exata da modificação.
Essas cores de destaque devem ser suaves (pastel) para não ofuscar a leitura do texto. Podemos usar classes Tailwind padrão, como bg-green-100 text-green-800 para fundo verde claro em texto adicionado, bg-red-100 text-red-800 line-through para removido, e bg-yellow-100 text-yellow-800 para destacar modificações dentro de linhas alteradas. A consistência dessas cores em tela e no PDF é importante – definiremos estilos que o Puppeteer respeitará ao gerar o PDF.
	•	Tipografia: Conforme mencionado, usaremos Source Sans Pro como fonte principal para textos e rótulos da interface, por sua ótima legibilidade em parágrafos. Para elementos que exijam alinhamento uniforme ou destaques de código/texto diferenciado (por exemplo, trechos de diff muito técnicos ou onde queremos evidenciar espaços em branco), poderemos usar Source Code Pro (monoespaçada). No entanto, para o texto dos documentos em si (que provavelmente são cláusulas de contratos, etc.), é preferível manter Source Sans Pro para que pareçam documentos normais, não código. A fonte monoespaçada pode ser empregada em pequenos elementos, como numeração de linhas (se adicionarmos) ou no sumário de mudanças, caso seja apresentado de forma estruturada. Ambas as fontes devem ser importadas no projeto (via <link> no _document do Next.js ou via @import no CSS, ou ainda usando Tailwind plugin de fontes se configurado).
	•	Ícones e Estilo Geral: Manter o visual minimalista. Usar ícones simples (estilo outline) somente onde necessário para claridade. Por exemplo, um ícone de upload ao lado do texto “Arraste e solte o arquivo aqui” pode tornar a interface mais intuitiva. Ícones de download (para o botão de exportar PDF) e os já mencionados ícones de “adição/remoção” no resumo também são úteis. Uma biblioteca recomendada é o Heroicons (já integrada facilmente com Tailwind, fornecendo SVGs limpos) ou outra coleção de ícones minimalistas. As cores dos ícones devem seguir a paleta do sistema (ícones de ação em preto ou cinza escuro; ícones indicativos coloridos conforme a categoria – verde, vermelho, amarelo).
A interface não terá muitos elementos decorativos; priorizamos espaços em branco e alinhamento para organização. Por exemplo, o container principal pode ter uma leve borda ou sombra para destacar a área de comparação. O painel de resumo pode ser distinguido com um fundo neutro (um cinza bem claro) para separá-lo do texto principal.
	•	Responsividade: Garantir que o layout funcione em diferentes tamanhos de tela. Em telas médias/grandes, o layout dividido (colunas lado a lado + painel de resumo) funciona bem. Em telas muito pequenas (mobile), poderemos:
	•	Empilhar as colunas verticalmente (primeiro a versão antiga com remoções marcadas, depois a versão nova com adições).
	•	O painel de resumo poderia virar um dropdown ou uma barra superior resumida (por exemplo, mostrar ícones + números de mudanças).
	•	A funcionalidade de upload deve ser acessível em mobile (elemento de input file clicável, já que drag & drop é menos usual em touch devices).

Em resumo, a identidade visual do ClauseDiff deve transmitir simplicidade e foco no conteúdo das diferenças. Com a tipografia consistente, cores somente para realçar mudanças e ícones discretos, o usuário poderá navegar pelas alterações de forma intuitiva tanto na interface web quanto no PDF gerado.

4. Estrutura de Diretórios e Organização do Código

Manter uma estrutura organizada é essencial, especialmente ao usar o Cursor (que se beneficia de contexto bem distribuído entre arquivos). Podemos estruturar o projeto em dois módulos principais – frontend e backend – dentro de um mesmo repositório (monorepo) ou em repositórios separados, dependendo da preferência. Abaixo uma estrutura sugerida usando um monorepo com pastas separadas:

ClauseDiff/
├── frontend/               # Projeto Next.js (Frontend)
│   ├── pages/              # Páginas do Next (rotas do frontend)
│   │   ├── index.js        # Página principal: upload de arquivos e exibição de diff
│   │   ├── _app.js         # Configuração global do Next (importa Tailwind CSS, fontes)
│   │   └── api/            # (Opcional) Rotas API Next.js, se preferir usar em vez do backend separado
│   │       └── diff.js     # Exemplo: endpoint API para processar diff (caso não use backend Express)
│   ├── components/         # Componentes React reutilizáveis
│   │   ├── FileUpload.js   # Componente de upload (área de drag & drop, seleção de .docx)
│   │   ├── DiffViewer.js   # Componente para exibir textos lado a lado com destaques
│   │   ├── SummaryPanel.js # Componente do painel lateral de resumo de mudanças
│   │   └── LoadingSpinner.js # (Opcional) Componente de feedback de carregamento
│   ├── styles/
│   │   ├── globals.css     # CSS global, inclui diretivas do Tailwind, fontes etc.
│   │   └── tailwind.css    # (Se preferir separar, ou usar direto no globals)
│   ├── utils/
│   │   └── formatDiff.js   # (Opcional) Funções utilitárias para formatar diffs para display
│   ├── public/             # Arquivos públicos (ex: ícones SVG, talvez se não usar lib de ícones)
│   ├── hooks/              # (Opcional) Hooks customizados (ex: useAuth para Supabase)
│   ├── .env.local          # Variáveis de ambiente do frontend (URL do backend, keys Supabase públicas)
│   ├── tailwind.config.js  # Configurações Tailwind (cores customizadas se necessário, etc.)
│   ├── next.config.js      # Configurações do Next.js 
│   └── package.json        # Dependências do frontend (Next, React, Tailwind, etc.)
│
└── backend/                # Projeto Node.js (Backend Express)
    ├── src/
    │   ├── index.js            # Inicialização do servidor Express (setup de rotas, conexões)
    │   ├── routes/
    │   │   ├── diff.js         # Rota POST /diff – recebe arquivos .docx e retorna diferenças
    │   │   ├── pdf.js          # Rota GET /pdf – gera e retorna o PDF das diferenças
    │   │   └── auth.js         # (Opcional) Rotas relacionadas à auth, se necessárias (ex: webhook do Supabase ou verificação de token)
    │   ├── services/
    │   │   ├── docProcessor.js # Lógica de processamento de documentos: uses mammoth + diff-match-patch
    │   │   └── pdfGenerator.js # Lógica de geração de PDF usando Puppeteer
    │   ├── utils/
    │   │   ├── fileStorage.js  # (Opcional) Funções para salvar arquivos temporariamente (no disco ou memória)
    │   │   └── cleanupJob.js   # Script/func para limpar arquivos temporários antigos (executado periodicamente)
    │   ├── middleware/
    │   │   └── authMiddleware.js # (Opcional) Middleware para verificar autenticação via Supabase JWT nas rotas protegidas
    │   └── ... (outros módulos auxiliares, se necessário)
    ├── .env                    # Variáveis de ambiente do backend (chaves privadas Supabase, etc.)
    ├── package.json            # Dependências do backend (Express, mammoth, diff-match-patch, Puppeteer, supabase-js, etc.)
    └── supabaseClient.js       # (Opcional) Inicialização do cliente do Supabase para usar no backend (por ex, verificar tokens, ou inserir logs no DB)

	xplicação da organização:
	•	No frontend, seguimos a convenção do Next.js:
	•	A pasta pages/ contém as páginas de interface. Aqui teremos pelo menos a página principal (index.js) que combina o formulário de upload e, após processamento, exibe o resultado das diferenças. Podemos também criar outras páginas se necessário (por exemplo, uma página separada de login se optarmos por um fluxo de autenticação customizado, ou uma página de resultado de diff dedicada). A subpasta pages/api/ dentro do frontend é opcional – podemos usá-la se quisermos implementar a lógica de diff diretamente em rotas serverless do Next.js (o que facilitaria deploy tudo em Vercel). Porém, dado que planejamos um backend separado, podemos deixar essa pasta quase vazia ou usá-la para pequenas funções (como talvez uma rota de status ou algo do tipo).
	•	A pasta components/ mantém componentes React reutilizáveis, facilitando a manutenção. Alguns componentes previstos:
	•	FileUpload.js: Componente que implementa a área de drag & drop ou botão de upload para arquivos .docx. Inclui lógica de validação (aceitar apenas .docx, mostrar mensagem de erro se outro tipo for fornecido) e possivelmente estado interno para visual feedback (ex.: “arquivo recebido: nome_do_arquivo.docx”).
	•	DiffViewer.js: Componente que recebe como props os conteúdos dos dois documentos (ou um resultado já formatado do diff) e renderiza o texto lado a lado com as marcações de destaque (span/div com classes Tailwind correspondentes a verde/vermelho/amarelo). Ele cuida de aplicar estilos nos trechos adicionados/removidos. Pode usar elementos HTML como <ins> e <del> ou <mark> para semântica, estilizados via CSS.
	•	SummaryPanel.js: Componente para o painel de resumo das mudanças. Recebe dados estatísticos (quantidade de adições, remoções, etc., e eventualmente lista de mudanças) e renderiza isso de forma visual (talvez uma lista ou apenas números destacados com ícones).
	•	Outros componentes utilitários: por exemplo, um LoadingSpinner para indicar processamento enquanto os arquivos são enviados e comparados; um componente de ProtectedRoute se implementar proteção de rota via login; etc.
	•	Pasta styles/: terá o arquivo global CSS onde o Tailwind será importado (Tailwind exige um CSS global que inclua as diretivas @tailwind base; @tailwind components; @tailwind utilities;). Aqui também podemos definir estilos globais ou overrides (por exemplo, estilos para as tags <ins> e <del> geradas pelo diff, se preferirmos ajustar via CSS e não inline). Se necessário, podemos ter um arquivo tailwind.config.js na raiz do frontend para customizar tema (por ex., adicionar cores custom ou estender a paleta se quisermos tons específicos de verde/vermelho).
	•	Pasta utils/: funções utilitárias do frontend. Por exemplo, se decidirmos formatar o diff no lado do cliente, aqui poderia ter funções que transformam a saída do diff (tal array de diferenças) em elementos HTML ou em uma estrutura fácil de renderizar em React. Outra utilidade poderia ser uma função para calcular o sumário (contar quantos inserts/deletes).
	•	Pasta hooks/: poderia armazenar hooks customizados. Um candidato é useSupabaseAuth para gerenciar login/logout e estado do usuário no frontend.
	•	Arquivos de configuração e ambiente: manter .env.local (não commitado) com configurações como URL do Supabase e chave pública, URL do backend (caso seja diferente em dev/prod). O next.config.js pode ser usado se precisarmos, por exemplo, configurar webpack para algo ou redirecionamentos (poderíamos definir um proxy para chamadas /api/* para apontar para o backend externo em desenvolvimento, facilitando chamadas).
	•	No backend, a separação segue princípios de API:
	•	O arquivo src/index.js configura o servidor Express: carrega variáveis de ambiente, inicializa conexões (por ex., se formos usar a SDK do Supabase no servidor, inicializa aqui), define middlewares (CORS, JSON body parser, talvez multer para upload de arquivos .docx), e monta as rotas definidas.
	•	A pasta routes/ contém módulos separados por funcionalidade:
	•	diff.js: Define o handler para POST /diff. Nele, usamos um middleware de upload (como multer ou similar) para receber dois arquivos (por exemplo, campos ‘file1’ e ‘file2’ no form-data). Valida que são .docx. Então invoca funções do serviço de comparação (em docProcessor.js) para obter o resultado das diferenças. Retorna esse resultado ao cliente (provavelmente como JSON contendo HTML formatado para diffs, ou dados estruturados).
	•	pdf.js: Define handler para gerar o PDF. Pode ser um GET /pdf/:id onde :id referencia um resultado de diff armazenado temporariamente, ou um POST /pdf que recebe diretamente o conteúdo/ID. Esse handler usará pdfGenerator.js para, dado um HTML de diferenças ou um ID para recuperar os dados, rodar o Puppeteer e devolver o PDF (com cabeçalhos adequados application/pdf).
	•	auth.js: (Opcional) Poderia lidar com rotas de autenticação se precisássemos (por exemplo, se configurarmos webhooks do Supabase ou endpoints para verificar sessão). Talvez não seja necessário, já que o Supabase Auth pode ser gerido no front e via middleware.
	•	A pasta services/ concentra lógica de negócio:
	•	docProcessor.js: Contém funções como processDocuments(fileBuffer1, fileBuffer2) que dentro usam mammoth para extrair texto ou HTML de cada arquivo, depois usam diff-match-patch para comparar. Provavelmente terá sub-funções como convertDocxToText(buffer) e generateDiff(text1, text2) para clareza. Essa separação facilita testar essas funções independentemente (ex.: testes unitários em generateDiff).
	•	pdfGenerator.js: Função generatePdfFromDiff(htmlDiff) que configura o Puppeteer (lança browser headless, cria uma página, define conteúdo HTML e CSS, ajusta opções de página como formato A4, e salva em buffer ou arquivo temporário). Pode salvar o PDF gerado num diretório temporário e retornar o caminho ou buffer na response.
	•	Pasta utils/: utilitários do servidor.
	•	fileStorage.js: se optarmos por armazenar os arquivos enviados ou os resultados diff temporariamente, aqui podemos ter funções para salvar e ler esses dados. Por exemplo, salvar os HTMLs de diff em um diretório /tmp ou até em memória (um objeto global Node) associado a um ID. Também poderia interagir com Supabase (ex.: salvar registro em tabela “diff_logs” com ID, timestamp, e talvez caminho do arquivo).
	•	cleanupJob.js: script ou módulo que verifica periodicamente os arquivos/temp data armazenados e remove os que passaram de 1 hora. Podemos usar um pacote de agendamento (como node-cron) para rodar essa limpeza a cada intervalo (ex: a cada 10 minutos limpar tudo que for >1h). Alternativamente, podemos simplesmente, após gerar cada diff ou PDF, agendar via setTimeout a remoção dos arquivos específicos em 1 hora.
	•	Pasta middleware/: poderia conter middlewares do Express. Um exemplo é authMiddleware.js que verifica se a requisição possui um token válido do Supabase (JWT) antes de permitir acessar certas rotas. Assim podemos facilmente proteger a rota de diff e pdf se quisermos que apenas usuários logados usem. Esse middleware usaria a chave pública do Supabase (JWKS) ou a própria SDK do Supabase para validar o token do header.
	•	Arquivo supabaseClient.js: caso queiramos usar a SDK do Supabase no backend (por exemplo, para inserir um log no banco, ou para verificar token via supabase.auth.api.getUser(token)), podemos inicializar o cliente aqui com URL e service role key (uma chave secreta que permita ler/escrever no DB). Isso fica protegido no backend (.env).

Essa organização modular torna o desenvolvimento no Cursor mais fácil: você pode focar em um arquivo/funcionalidade por vez (por exemplo, pedir para o Cursor AI “gerar a função generateDiff no docProcessor.js” sem se preocupar em misturar com código de roteamento, etc.). Além disso, mantém responsabilidades separadas: componentes de UI não conhecem detalhes de diff, o backend não se preocupa com renderização, e assim por diante.

Dica: usando o Cursor, lembre de criar os arquivos necessários antes de pedir implementações (ou peça para o AI criar). Por exemplo, crie os esqueletos de docProcessor.js, pdfGenerator.js e do handler de rota, para depois detalhar cada um. Isso ajuda o AI a saber onde colocar cada parte do código.

5. Etapas para Desenvolvimento Incremental do MVP

Com a arquitetura e estrutura definidas, é recomendável implementar o MVP de forma iterativa, adicionando funcionalidades passo a passo. Abaixo estão as etapas sugeridas, na ordem, para construir a aplicação ClauseDiff:
	1.	Implementar Upload de Arquivos (.docx) com Drag and Drop e Validação:
Comece pelo frontend criando o componente de upload. Implemente dois campos de upload – um para o documento original e outro para o documento modificado (isso evita confusão de qual arquivo é qual). Utilize um input do tipo file que aceite apenas .docx (accept=".docx"). Envolva cada input em uma área de drag-and-drop estilizada: uma caixa com borda tracejada e ícone de upload, que muda de estilo ao arrastar um arquivo sobre ela (por exemplo, fica com borda sólida). Ao soltar o arquivo ou selecionar via clique, valide o tipo (verifique a extensão ou file.type – documentos Word geralmente têm MIME application/vnd.openxmlformats-officedocument.wordprocessingml.document). Se o arquivo não for válido, exiba uma mensagem de erro amigável (ex.: “Por favor, selecione um arquivo .docx válido”). Se for válido, atualize o estado local com o arquivo selecionado e talvez mostre o nome do arquivo carregado. Garanta suporte a arrastar dois arquivos ao mesmo tempo ou um por vez nos campos corretos. (Uma alternativa: uma única área que aceita dois arquivos e você determina ordem pelo nome ou deixa o usuário escolher qual é base e qual é nova – porém duas áreas separadas tornam mais claro). Dica: Use o Cursor AI para gerar boa parte desse componente fornecendo um prompt como “Criar componente React FileUpload com drag-and-drop para .docx”. Após o componente pronto, integre-o na página principal. Nenhuma lógica de envio ao servidor ainda – foque primeiro em conseguir os arquivos no estado do React e pronto para enviar.
	2.	Parsing dos Documentos com mammoth.js e Cálculo de Diferenças (diff-match-patch):
Agora, implemente o backend (ou função API) que recebe os arquivos e processa a comparação. No backend Express, configure a rota POST /diff. Use um middleware como multer para lidar com form-data contendo dois arquivos (ex.: campos file1 e file2). No handler, para cada arquivo recebido, chame o mammoth.js para convertê-lo:

const mammoth = require("mammoth");
const result = await mammoth.convertToHtml({ buffer: file1Buffer });
const html1 = result.value;  // HTML do primeiro documento


(Faça o mesmo para o segundo arquivo). Você pode usar convertToHtml para preservar alguma estrutura HTML, ou convertToMarkdown/convertToText se preferir trabalhar com texto puro. Uma abordagem comum é extrair o texto puro mantendo apenas quebras de parágrafo – isso evita que diferenças de estilos atrapalhem. Em seguida, use diff-match-patch para comparar os dois textos. Por exemplo, usando a biblioteca diff-match-patch (NPM: diff-match-patch):

const DMP = require("diff-match-patch");
const dmp = new DMP();
let diffs = dmp.diff_main(text1, text2);
dmp.diff_cleanupSemantic(diffs);

sso retorna um array diffs de tuplas com código de operação e texto, e realiza um cleanup semântico para unir diffs pequenos ou irrelevantes. Agora, transforme esse resultado em um formato utilizável pelo frontend. Duas opções:
	•	Gerar HTML com marcações: Você pode transformar o array de diffs diretamente em HTML marcado com <ins> (inserções) e <del> (deleções) por exemplo, ou <span class="added">...</span> etc. A própria biblioteca possui um método diff_prettyHtml(diffs) que retorna um HTML básico com <ins> e <del> usando estilos inline. Você pode usar esse output e depois aplicar CSS via classes (por exemplo, adicionar regras para <ins> ter fundo verde claro, <del> fundo vermelho claro, etc.). Essa abordagem é rápida – basta retornar essa string HTML pronta na resposta.
	•	Retornar dados estruturados: Alternativamente, retornar o array de diffs ou um objeto JSON com segmentos adicionados/removidos, e deixar o frontend decidir como exibir. Ex: { diffs: [ {op: 'equal', text: 'Clause 1 ...'}, {op: 'delete', text: 'old text'}, {op: 'insert', text: 'new text'}, ... ] }. Essa abordagem dá mais controle no front (pode montar as duas colunas manualmente), mas é um pouco mais complexa de implementar rapidamente.
Para um MVP, gerar o HTML com as marcações já é suficiente, pois simplifica a renderização. Portanto, o endpoint /diff pode responder com um JSON contendo a string HTML resultante, ou até somente a string (mas JSON com chave html é mais extensível). Exemplo de response: { "diffHtml": "<p>Clause 1: <del style='...'>old text</del><ins style='...'>new text</ins> ...</p>" }.
No frontend, após enviar os arquivos (via fetch ou Axios no evento de submit do upload), você receberá esse HTML e poderá inserir no DOM. Lembre-se de colocar o componente de upload para enviar os arquivos ao backend (talvez criar um botão “Comparar” que chama a API). Durante o envio e processamento, indique estado de loading (um spinner ou mensagem “Comparando…”). Importante: Teste a lógica de diff com arquivos pequenos inicialmente ou mesmo textos estáticos, para garantir que a integração mammoth + diff está funcionando antes de partir para o próximo passo.

	3.	Renderização Lado a Lado das Diferenças Destacadas:
Com o resultado das diferenças disponível (seja em HTML ou dados), construa a exibição comparativa. Se optou por HTML unificado com <ins> e <del>, você pode inseri-lo no componente DiffViewer usando dangerouslySetInnerHTML dentro de um contêiner, estilizando as tags via CSS/Tailwind. Entretanto, para obter um layout de colunas lado a lado, considere separar o HTML em duas colunas: uma representando o texto original e outra o texto novo:
	•	Para fazer isso, você pode processar o array de diffs: construir uma string para o documento antigo e outra para o novo. Por exemplo, iterando pelos diffs:
	•	Quando op for equal, adicione o texto igual a ambas strings.
	•	Quando for delete (texto removido no novo), adicione esse texto à string do documento antigo com marcação de remoção (ex: envolver em <span class="bg-red-100 line-through">...</span> ou <del class="bg-red-100">...</del>). Não adicione nada à string do novo (ou poderia adicionar um espaço ou indicação de vazio para manter alinhamento, mas talvez não seja necessário).
	•	Quando for insert (texto adicionado no novo), adicione o texto na string do documento novo com marcação verde (ex: <span class="bg-green-100">...</span>), e não adicione nada correspondente na string do antigo.
	•	O resultado serão duas strings HTML: uma com o conteúdo original marcado com deleções, outra com o conteúdo novo marcado com adições. As partes não modificadas estarão presentes integralmente em ambas, mantendo o alinhamento textual o melhor possível.
	•	Estas strings podem então ser renderizadas em dois elementos <div> adjacentes, estilizados como colunas (por ex., usando flex ou grid via Tailwind: grid grid-cols-2 gap-4 ou similar). Cada coluna poderia ter scroll independente se o texto for muito longo, ou podemos sincronizar o scroll via código para que ao rolar uma, a outra acompanhe (melhoria opcional).
	•	Para destacar modificações dentro de linhas (trechos alterados), as próprias marcações verde/vermelha já indicam, mas poderíamos adicionar um destaque amarelo se quisermos sinalizar que uma linha teve alteração em vez de ser totalmente adicionada/removida. Isso poderia ser conseguido detectando quando um delete é seguido imediatamente de um insert no diff (sinal de substituição): então poderíamos aplicar uma classe extra nesses trechos, ex: <span class="bg-red-100 bg-yellow-50">old</span> e <span class="bg-green-100 bg-yellow-50">new</span> para combinar cores. No MVP, essa granularidade é bacana mas não obrigatória – o essencial é que verde e vermelho já permitam identificar o que saiu e entrou.
Depois de montar essa lógica, integre-a no frontend: o componente DiffViewer pode receber diretamente a diffHtml unificada (e então dividir em duas colunas via CSS splitting e maybe some JS) ou receber dois campos (oldText, newText) já processados. Uma estratégia simples: modificar o backend para retornar já um objeto { originalHtml, modifiedHtml }, onde cada um é a coluna respectiva. Assim o front só insere cada em sua coluna. Em termos de UX, mostre de forma clara qual coluna é qual (títulos acima de cada coluna, ex: “Versão Antiga” acima da esquerda, “Versão Nova” acima da direita). Aplique estilos das cores conforme planejado (Tailwind classes ou CSS global para <del> e <ins> se usando essas tags). Teste com um exemplo simples para ver se o alinhamento visual está bom. Ajuste detalhes como espaçamento de parágrafos, etc., para que a leitura lado a lado fique fácil.
	4.	Geração do Painel Lateral de Resumo de Mudanças:
Com a visualização básica das diferenças pronta, implemente o SummaryPanel que resume as mudanças. No backend, ao calcular o diff, você pode contar quantos inserts e deletes houve. Por exemplo, após diffs = dmp.diff_main(...), percorra:

let addedCount = 0, removedCount = 0;
diffs.forEach(([op, data]) => {
    if(op === 1) addedCount++;      // código 1 para insert
    else if(op === -1) removedCount++; // código -1 para delete
});
let modifiedCount = Math.min(addedCount, removedCount); 
// Heurística: se há tanto insert quanto delete, assume-se que certos deletes correspondem a inserts (modificações)

A lógica acima é simplificada – modificações reais (substituições) podem ser inferidas quando um trecho deletado é seguido de um inserido. Mas para um sumário simples, poderíamos definir “modificações” como o menor dos dois números (pois, por exemplo, 5 deletions e 5 insertions provavelmente significam 5 modificações pareadas; se há extras de um lado, o restante são adições ou remoções puras). Em todo caso, no sumário podemos apresentar:
	•	Adições: total de segmentos adicionados (texto presente apenas na nova versão).
	•	Remoções: total de segmentos removidos (texto que existia apenas na versão antiga).
	•	Modificações: se calculado, ou podemos omitir se for confuso. Mas idealmente, as modificações seriam aquelas adições e remoções que formam um par (trecho alterado em vez de simplesmente inserido ou deletado isoladamente).
No frontend, passe esses números (e possivelmente listas de trechos ou posições) para o componente SummaryPanel. Nele, renderize os dados de forma clara, usando os ícones e cores correspondentes. Por exemplo:

<div className="p-4 bg-gray-50 text-sm">
  <h3 className="font-semibold mb-2">Resumo das Mudanças</h3>
  <ul>
    <li><span className="text-green-600 font-bold">+5</span> Adições</li>
    <li><span className="text-red-600 font-bold">-3</span> Remoções</li>
    <li><span className="text-yellow-600 font-bold">~2</span> Modificações</li>
  </ul>
</div>

O sumário pode ser mais elaborado, por exemplo listar os títulos das cláusulas afetadas (isso exigiria identificar títulos no documento – fora do escopo MVP a não ser que facilmente deduzido de formatação do Word). Para MVP, manter só os números já é útil. Garantir que o painel de resumo seja fixo ou visível mesmo ao rolar o texto das colunas (talvez torná-lo sticky no topo ou lateral). Se optar por lateral, implementá-lo como uma terceira coluna estreita à direita, ou sobreposto no canto. Teste diferentes tamanhos de tela para ver se o sumário não atrapalha a visualização do texto principal.

	5.	Exportação para PDF com marcações coloridas via Puppeteer:
Depois de confirmar que a comparação aparece corretamente no navegador, desenvolva a funcionalidade de exportar PDF. Adicione um botão “Exportar PDF” na interface (por exemplo, no topo da página ou junto do painel de resumo). Ao clicar, esse botão deve acionar uma chamada ao backend, provavelmente para o endpoint /pdf. Precisamos decidir: enviar todo o conteúdo via requisição, ou o backend recuperar um resultado armazenado? Duas abordagens:
	•	Reenviar dados: Enviar novamente (via POST) o resultado diff (ou os arquivos originais) para o endpoint PDF. O backend então repete o processamento ou usa o diff recebido para gerar PDF. Isso é simples mas pode ser redundante e custoso (processar duas vezes).
	•	Identificador temporário: Alternativamente, quando o cliente obtém o diff na etapa 2, o backend poderia ter gerado e retornado um id associado ao resultado armazenado. Por exemplo, ao responder em /diff, além do HTML, retornar resultId. O frontend guarda esse ID. Então a chamada para /pdf poderia ser um GET contendo o resultId (ex: /pdf?resultId=12345). O backend olha em seu armazenamento temporário (memória, arquivo ou banco) e encontra o diff HTML correspondente para gerar o PDF sem recalcular tudo. Esse armazenamento poderia ser um simples objeto global (chave-> {html, timestamp}) ou uma tabela no Supabase. Considerando o prazo curto, um armazenamento em memória no próprio processo Node ou em arquivos temporários no disco é aceitável, desde que a instância não reinicie com frequência.
Implementando a geração: no pdfGenerator.js, use Puppeteer:

const puppeteer = require('puppeteer');
async function generatePdfFromHtml(diffHtml) {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();
    // Opcional: defina formato A4 e margens nas opções do PDF
    await page.setContent(diffHtml, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
    await browser.close();
    return pdfBuffer;
}

mantenha as cores. Ou seja, se o diffHtml depende de classes Tailwind, você precisará ou embutir o CSS do Tailwind no HTML (por exemplo, um <style>...</style> gerado a partir do build do Tailwind) ou incluir um link CDN para o CSS se disponível. Como alternativa mais simples, poderíamos construir um HTML inline com estilos simples (ex: <span style="background-color:#d1fae5;"> que é bg-green-100) no próprio diffHtml retornado. O método diff_prettyHtml da biblioteca já insere estilos inline por padrão (por ex., background:#e6ffe6 para ins, etc.). Se usarmos isso ou definirmos manualmente estilos inline, o PDF sairá colorido sem esforço adicional de CSS.
O endpoint /pdf então obtém o HTML (através do resultId ou corpo da requisição), chama generatePdfFromHtml, e devolve o buffer com res.type('application/pdf').send(pdfBuffer). No frontend, ao chamar esse endpoint, é possível fazer via fetch e depois criar um blob para download, mas mais simples: colocar o link diretamente para /pdf?resultId=XYZ e usando window.open ou location.href isso deve disparar o download no navegador. Se precisar via código, use fetch e em seguida use a API Blob and FileSaver para baixar.
Teste a geração de PDF com um exemplo. Verifique se as quebras de página estão aceitáveis (talvez cláusulas longas partam página, etc. – podemos ajustar margens ou inserir CSS page-break-inside: avoid em elementos como parágrafos/títulos se for necessário melhorar). Para MVP, garantir que o PDF baixa e contém o texto e highlights coloridos conforme visto na tela.

	6.	Exclusão Automática de Arquivos/Dados Temporários após 1h (Job no Backend):
Finalmente, implemente a limpeza de dados temporários para não acumular arquivos no servidor. Isso é relevante se:
	•	Você está armazenando os arquivos .docx enviados (pode deletá-los logo após extrair o texto, não são mais necessários).
	•	Você está armazenando o resultado diff (HTML ou JSON) associado a um resultId para uso posterior (como PDF). Esses resultados podem ficar obsoletos após algum tempo ou após o PDF ser gerado.
	•	Logs ou entradas no banco (Supabase) que sejam temporárias.
Uma abordagem simples: quando processar uma comparação no /diff, armazene o resultado em algum lugar (memória ou arquivo) junto com um timestamp. Em seguida, agende a remoção. Por exemplo, se armazenado em memória:

const results = {}; // in-memory storage at module scope
// ... inside /diff handler:
const resultId = generateUniqueId();
results[resultId] = { html: diffHtml, created: Date.now() };
// schedule deletion:
setTimeout(() => { delete results[resultId]; }, 3600 * 1000);

Isso garantirá que em 1 hora aquele resultado sai da memória. Se optou por salvar em disco (por exemplo, arquivos HTML ou PDF temporários), pode usar fs.unlink dentro do setTimeout para apagá-los.
Uma solução mais robusta é rodar um job periódico. Usando o pacote node-cron, você pode configurar algo como:

cron.schedule('0 * * * *', () => { 
   // a cada hora executa
   const oneHourAgo = Date.now() - 3600*1000;
   for(let id in results) {
      if(results[id].created < oneHourAgo) delete results[id];
   }
});

Assim, de hora em hora limpa tudo antigo (ou poderia ser a cada 10 minutos). Isso é útil caso a instância do Node fique ligada por muito tempo.
Se usar Supabase para armazenar logs temporários, você poderia definir uma policy ou procedimento para limpar registros antigos, mas isso complicaria o MVP. Mais simples: só grave no Supabase se quiser auditoria e limpe “manualmente” via script quando precisar.
Teste o mecanismo de limpeza configurando um tempo menor em desenvolvimento (como 1 minuto) para ver se está funcionando (ver logs ou verificar se um dado some). Tenha cuidado para não deletar algo em uso – por exemplo, se o usuário gerar o diff e só clicar no PDF 59 minutos depois, ainda deve funcionar. 1h é um prazo razoável. Documente aos usuários (ou para si) que os dados não ficam no servidor além desse tempo por segurança.

Seguindo essas etapas em ordem, ao final terá um fluxo completo: upload de dois .docx -> processamento no backend -> diffs exibidos lado a lado com destaques -> resumo mostrado -> opção de PDF para baixar -> limpeza automática no servidor. Cada etapa pode ser testada isoladamente e em conjunto conforme vai sendo construída.

6. Testes Sugeridos para o MVP

Para garantir a qualidade do MVP ClauseDiff, escreva alguns testes, focando nos pontos críticos. Dada a rapidez do ciclo, priorize:
	•	Testes Unitários (foco na lógica de comparação): Concentre-se em testar a função que compara os documentos, ou seja, a que utiliza diff-match-patch e formata o resultado. Você pode simular entradas pequenas e controladas:
	•	Exemplo: comparar "Hello world" com "Hello brave new world". Verifique que o resultado indica uma adição de "brave new " no lugar correto.
	•	Exemplo: comparar "Clause 1: The Sky is blue." com "Clause 1: The Sky is light blue.". Esperado: o diff deve marcar a inserção de "light " como adição (ou modificação) dentro da frase.
	•	Se você implementou uma função que gera HTML, verifique que a string resultante contém as tags esperadas (<ins> ou classes de highlight) para os trechos específicos.
	•	Caso tenha separado em função que gera duas colunas de texto, teste que a coluna da esquerda contém o texto original completo mais marcações de remoção, e a da direita contém o texto novo com marcações de adição.
	•	Utilize Jest (popular no Node e suportado também em ambiente Next/React) para criar esses testes. Você pode mockar o mammoth (ou usar um pequeno .docx de teste salvo no repo para integração) – porém, talvez seja mais fácil testar a diff usando strings simples (assumindo mammoth funciona).
	•	Teste também funções auxiliares: por exemplo, se criou uma função para contar mudanças ou para identificar modificações pareadas, teste esses cálculos com arrays de diffs simulados.
	•	Testes End-to-End (fluxo upload -> resultado): Para o MVP, testes E2E ajudam a pegar bugs integrados. Usar ferramentas como Cypress ou Playwright:
	•	Um teste E2E pode rodar a aplicação (talvez em modo headless) e simular o usuário selecionando ou arrastando dois arquivos de exemplo e clicando no botão de comparar. Você pode preparar dois arquivos .docx de teste no diretório de testes (por exemplo, sample_old.docx e sample_new.docx com diferenças conhecidas). O teste faria o upload desses arquivos (Cypress permite selecionar arquivos para um input file), acionaria a comparação, esperaria a resposta e então verificaria elementos na tela:
	•	Por exemplo, verificar que na coluna da direita aparece um trecho com classe .bg-green-100 (indicando adição) contendo um texto específico que estava somente no doc novo.
	•	Verificar que a coluna da esquerda tem um <del> ou elemento com classe de remoção contendo um texto que foi removido.
	•	Conferir que o SummaryPanel exibiu os números certos (por exemplo, “Adições: 1” se nos docs de teste você sabe que tinha 1 inserção).
	•	Outro teste E2E poderia acionar o botão de Exportar PDF e verificar o resultado. Isso é um pouco mais complexo: você poderia verificar a resposta da requisição /pdf (por exemplo, esperar um status 200 e content-type pdf). Para checar o conteúdo do PDF mesmo seria necessário abrir o PDF e ler o texto/coros (o que foge do escopo normalmente). Mas garantir que o download inicia já valida o fluxo. Em Cypress, você pode interceptar a chamada /pdf e confirmar que retorna um blob. Em testes manuais, obviamente você abriria o PDF para inspeção visual.
	•	Teste de componentes (opcional): Com React e ferramentas como React Testing Library, você pode testar que o componente DiffViewer ao receber uma props diffHtml ou originalHtml/modifiedHtml renderiza os elementos certos. Por exemplo, passar uma pequena string com <del>old</del><ins>new</ins> e ver se no DOM resultante existe um element <del> com texto “old” e que possui estilos de cor vermelha (pode checar a classe CSS). Como nosso foco principal é a lógica e integração, esses testes de render não são tão críticos, mas podem ajudar a evitar regressões de UI.

Além dos testes automatizados, testes manuais são importantes para este tipo de aplicação, pois diferenças de documentos podem ter casos muito variados (mudança de ordem de parágrafos, edições pequenas vs remoções grandes, etc.). Recomenda-se criar ou obter alguns documentos de exemplo:
	•	Um par de documentos quase idênticos (para ver que poucas mudanças aparecem claramente).
	•	Um par com diferenças extensas (para ver como a interface se comporta com muito texto marcado).
	•	Documentos com listas, títulos, diferentes formatações, para ver se a conversão mammoth + diff lida bem (por exemplo, numa lista, adicionar um item – o diff deve mostrar só aquele item em verde).
	•	Testar upload de um arquivo só ou arquivos inválidos para garantir as validações (o sistema deve rejeitar e instruir corretamente).

Por último, teste o comportamento de auth se implementado: por exemplo, se a página de comparação requer login, usar supabase em modo de teste ou stub do token para simular usuário não logado tentando acessar (esperado redirecionamento ou bloqueio).

Automatize o que for possível dentro do tempo disponível e deixe instruções de teste manual para cobrir o restante. Assim você terá maior confiança na estabilidade do MVP antes do lançamento.

7. Como Utilizar o Cursor AI no Desenvolvimento do ClauseDiff

O Cursor, como IDE com AI, pode acelerar significativamente o desenvolvimento. A chave é saber formular pedidos claros ao assistente de código para gerar ou melhorar trechos. A seguir, algumas dicas de como usar o Cursor AI em situações específicas do nosso projeto:
	•	Gerar Handlers de Backend RESTful: No arquivo de rotas do Express (por exemplo, routes/diff.js), você pode escrever um comentário ou descrição do que deseja e deixar o AI implementar. Exemplo: no Cursor, abra o arquivo e digite algo como:

	// TODO: Implementar rota POST /diff:
// - Receber dois arquivos .docx do request (form-data).
// - Validar que sejam .docx.
// - Usar mammoth para converter cada um em texto/HTML.
// - Usar diff-match-patch para comparar os textos.
// - Retornar um JSON com o resultado (HTML das diferenças e talvez estatísticas).

Em seguida, selecione essa descrição e utilize o atalho do Cursor para “Implement function” ou similar (ou use o painel de chat dizendo: “Implemente a rota acima”). O Cursor AI deverá gerar o código do handler Express correspondente, incluindo possivelmente a configuração do multer para arquivos, chamadas ao mammoth e diff-match-patch. Fique pronto para revisar: verifique se ele nomeou corretamente os campos de arquivo, se tratou erros (ex: arquivo ausente, exceções do mammoth) e se o formato de resposta está como você quer. Provavelmente você precisará ajustar detalhes ou refinar o prompt pedindo, por exemplo, “Use variável X definida no escopo”, etc. A vantagem é que o AI escreverá o boilerplate rapidamente (leitura do req, etc.) e você pode iterar melhorando.

	•	Criar Componentes React Estilizados com Tailwind: De modo similar, ao trabalhar em um componente no frontend, aproveite o Cursor para gerar estrutura JSX e classes Tailwind. Por exemplo, para o componente FileUpload, você pode fornecer um prompt no arquivo:

	{/* Componente de Upload de Arquivo .docx com drag-and-drop.
    Requisitos:
    - Deve aceitar apenas arquivos .docx.
    - Mostrar área de drag and drop com texto "Arraste e solte..." e ícone.
    - Destacar visualmente quando arquivo estiver sendo arrastado sobre a área.
    - Exibir nome do arquivo selecionado após upload.
    - Chamar props.onFilesSelected(file1, file2) quando ambos arquivos forem selecionados.
*/}

Após escrever isso como comentário JSX, peça ao Cursor para gerar o componente. Ele criará provavelmente um <div onDragOver onDrop> com estados internos e classes Tailwind (como border-2 border-dashed p-6 text-center etc.). Talvez o resultado não esteja perfeito de primeira – você pode iterar pedindo: “Adicione um ícone SVG de upload no centro”, ou “Melhore a mensagem de erro para arquivos inválidos”. O AI consegue ajustar incrementos se você especificar. Dica: Ao gerar Tailwind, às vezes o AI pode sugerir classes inexistentes ou muito específicas; use a documentação Tailwind para corrigir ou simplificar classes se necessário. Você também pode pedir: “Refatore para usar componentes do Headless UI” se quisesse, mas no nosso caso não há necessidade.

	•	Revisar Funções de Comparação e Gerar Testes com Jest: Quando tiver escrito (ou gerado) a função de diff (por ex., generateDiff em docProcessor.js), peça ao Cursor para revisá-la: no chat, você pode colar a função e perguntar “Você vê algum possível erro ou caso não coberto nessa função?”. O AI pode identificar cenários como “E se um dos textos for vazio?” ou sugerir usar outro método de limpeza diff. Isso ajuda a aprimorar a robustez. Em seguida, para testes, o Cursor pode criar rapidamente um conjunto de casos. Por exemplo, diga: “Gere testes unitários Jest para a função generateDiff que cobrem casos básicos de adição, remoção e modificação.” Certifique-se de já ter a função exportada e um arquivo de teste .test.js criado. O Cursor então pode produzir algo como:

	test('detects added text', () => { ... });
test('detects removed text', () => { ... });

com entradas e saídas esperadas. Revise os valores esperados, ajustando conforme a lógica específica da sua função (talvez o AI não saiba exatamente seu formato de saída sem você especificar). Essa auto-geração de testes poupa tempo, garantindo que você tenha pelo menos uma cobertura inicial. Lembre-se de rodar os testes (provavelmente via npm test) e, se algum falhar, você pode pedir ajuda ao Cursor para entender o motivo ou corrigir a implementação.

	•	Refatorar Funções Grandes e Manter Separação de Responsabilidades: Conforme for desenvolvendo, talvez alguma função ou componente fique extenso. Por exemplo, pode acontecer de termos muita lógica no próprio handler /diff em vez de delegar para funções de serviço. Você pode selecionar o bloco de código no Cursor e usar um comando de refatoração, ou pelo chat pedir: “Refatore esse código separando em funções menores e claras”. O Cursor AI tende a sugerir extração de funções auxiliares. Por exemplo, no backend ele poderia mover a parte de diff para uma função computeDiff(text1, text2) e a parte de mammoth para uma função extractTextFromDocx(file). No frontend, se um componente faz coisas demais (upload + mostrar resultado no mesmo lugar), o AI pode sugerir dividir em dois componentes. Sempre verifique se após refatoração tudo ainda se conecta corretamente. Outra forma de usar o Cursor é pedir por padrões de projeto: ex: “Como posso organizar melhor o código para separar a lógica de X da de Y?” – ele pode descrever uma possível reorganização (às vezes até criar novos arquivos). Use esse conselho aliado ao seu julgamento.

Em todos esses casos, combine a assistência do Cursor com revisões manuais. O AI acelera tarefas repetitivas e boilerplate, mas pode cometer enganos sutis (por exemplo, usar uma API depreciada, ou esquecer alguma condição). Mantenha a documentação das libs aberta (você pode até usar o Cursor com comandos @docs ou @web se disponível, para consultar referências enquanto desenvolve). Outra dica: se o Cursor inserir código que você não entende bem, peça explicação: “Explique esse trecho” ou comente no código pedindo esclarecimentos – isso ajuda a aprender e verificar se o código faz sentido.

Utilizando o Cursor AI de forma iterativa – geração, teste, revisão, refino – você conseguirá desenvolver cada parte do ClauseDiff MVP de maneira muito ágil, sem sacrificar a qualidade.

8. Prompt Auxiliar para Integração com Supabase Auth (Login Google opcional)

Se você decidir incluir autenticação de usuários no MVP (por exemplo, para que somente usuários logados possam fazer comparações, ou apenas para ter um controle de quem usa), integrar o Supabase Auth é uma boa escolha. O Cursor AI pode ajudar a configurar isso. Abaixo um exemplo de prompt (em português) que você pode usar no Cursor para orientar a geração dessa integração:

**Tarefa:** Integrar autenticação de usuário via Supabase no projeto ClauseDiff (Next.js + Node).

**Requisitos:**
- Utilizar a SDK JavaScript do Supabase (pacote @supabase/supabase-js) no frontend para autenticação.
- Permitir login social com Google (OAuth do Supabase).
- Criar um componente de Login com um botão "Login com Google" que, ao ser clicado, chama `supabase.auth.signInWithOAuth({ provider: 'google' })`.
- Gerenciar o estado de autenticação no frontend: após login, armazenar o usuário (pelo menos seu id ou email) e mostrar na UI (ex: "Olá, {nome}").
- Proteger a página de comparação de documentos para que somente usuários logados acessem: se não autenticado, redirecionar para página de Login ou mostrar um aviso e botão de login.
- Implementar logout simples: um botão "Sair" que chama `supabase.auth.signOut()` e atualiza o estado.
- (Opcional) No backend, verificar o token do Supabase nos requests: por exemplo, nas rotas /diff e /pdf, ler o header Authorization Bearer (JWT do Supabase) e validar usando a chave pública do projeto Supabase, negando acesso se inválido.

**Detalhes de Configuração:**
- Já tenho as credenciais do Supabase: URL do projeto e chave anônima pública para o frontend. Use variáveis de ambiente para essas informações.
- No frontend Next.js, criar um arquivo de inicialização (ex: `utils/supabaseClient.js`) com `createClient(supabaseUrl, supabaseAnonKey)`.
- Criar um contexto React ou usar um simples estado global para armazenar `user` retornado pelo Supabase após login. O Supabase pode fornecer `auth.onAuthStateChange` para reagir automaticamente.
- Para a página de login (se for separada) ou componente de login, estilizar usando Tailwind (por ex., um cartão central com botão Google).
- A autenticação é opcional no MVP, então se o usuário não quiser logar, podemos ainda permitir uso? (Decidir: talvez sim, se assim, então tornar login apenas informativo).

sse prompt detalha passo a passo o que precisa ser feito. Você pode colocá-lo no Cursor e pedir: “Gerar código de exemplo para os pontos acima”. Possivelmente, o assistente vai:
	•	Criar o arquivo supabaseClient.js com createClient.
	•	Gerar um componente Login.js com um botão que chama signInWithOAuth.
	•	Mostrar como integrar o provedor Google (no Supabase, isso requer previamente configurar o app Google nas configurações do projeto Supabase).
	•	Sugerir um contexto AuthProvider ou uso do hook useState no _app.js para guardar o usuário.
	•	Talvez até dar exemplo de proteger páginas (em Next, podemos usar getServerSideProps para verificar sessão ou no cliente verificar e redirect).
	•	Fornecer um exemplo de middleware backend para validar tokens (se pedirmos).

Lembre-se de ajustar conforme seu cenário. Por exemplo, se não quiser complicar com verificação no backend no MVP, pode ignorar essa parte e simplesmente não chamar o backend se não logado. O Supabase Auth por padrão guarda a sessão no localStorage, então o usuário permanecerá logado após refresh; você só precisa recuperar esse estado.

Depois de obter o código sugerido pelo AI, teste o fluxo:
	•	Ao clicar login, deve abrir o pop-up de OAuth Google (Supabase cuida disso). Após login, verificar se supabase.auth.session() retorna um usuário e token.
	•	Tente proteger as rotas do Next: por exemplo, se um usuário não logado acessar / (onde se faz a comparação), decida se redireciona para /login. Isso pode ser feito via Next middleware ou simplesmente no componente useEffect checando user e redirect.
	•	Teste logout também.

A integração de auth adiciona alguma complexidade, então só inclua se realmente for necessário para a primeira versão. Caso implementado, esse prompt auxiliar deve te acelerar bastante, evitando ter que ler toda a documentação da Supabase (que de toda forma está disponível e é bem feita, recomendo consultá-la para entender limites, como refresh de token, etc.).

9. Sugestão de Meta Semanal para Lançar o MVP (5–7 dias)

Dividindo o trabalho em metas diárias, você pode entregar um MVP funcional em uma semana ou menos. Aqui está uma sugestão de cronograma, assumindo ~5 dias de desenvolvimento intenso e 2 dias de refinamento/testes:
	•	Dia 1: Configuração do Projeto e Upload Básico
Meta: Repositório inicial pronto, base do frontend e backend configurados, upload de arquivos funcional na interface.
Tarefas: Inicialize o projeto Next.js (instale Tailwind e configure fonts). Inicialize o projeto Node/Express (setup de base, teste um endpoint simples). Configure o repositório git (com commits iniciais). Implemente o componente de upload de arquivos (drag & drop) e verifique no console do browser que ele capta os arquivos corretamente. No backend, teste recebimento de um arquivo via Postman ou similar (pode criar rota /upload-test temporária para ver se multer está ok). Não é necessário já comparar documentos, mas garanta que você consegue passar o arquivo do front para o back (CORS configurado se front e back separados, etc.). Componente de upload deve ter validação .docx com feedback ao usuário.
	•	Dia 2: Lógica de Conversão e Diferença
Meta: Dois documentos .docx -> diffs calculados e retornados do backend.
Tarefas: Implementar no backend a rota /diff usando mammoth e diff-match-patch. Testar unitariamente ou com pequenos trechos (pode chamar essa rota manualmente com arquivos de teste via um cliente REST e inspecionar o JSON/HTML retornado). No frontend, ao clicar “Comparar”, chamar a API e logar a resposta (por enquanto). Talvez criar um estado diffResult para armazenar o resultado recebido. No fim do dia, idealmente, você consegue ver um output de diff (mesmo que sem estilo) aparecendo na página após um upload de dois arquivos de exemplo. Obs: Se algum obstáculo surgir (ex: problemas para instalar Puppeteer ou mammoth), considere alternativas ou resolução nesse dia, antes de prosseguir.
	•	Dia 3: Exibição das Diferenças e Destaques Visuais
Meta: Usuário pode ver lado a lado os documentos com as alterações destacadas em verde/vermelho/amarelo, e um sumário básico de mudanças.
Tarefas: Trabalhar no componente DiffViewer para formatar e mostrar as diferenças. Aplicar o layout de duas colunas com as classes Tailwind apropriadas. Certificar-se que textos longos ficam scrolláveis. Implementar o SummaryPanel calculando dados (pode ser no frontend mesmo, contando ocorrências de <ins> e <del> no HTML, ou usando os dados do backend). Ajustar detalhes de estilo: por exemplo, garantir que fonte correta está sendo aplicada, tamanhos de texto adequados (talvez 1rem para texto normal, 0.875rem para sumário, etc.), cores legíveis na tela (testar verde/vermelho para daltonismo – talvez usar ícones + cores). Ao final do dia, você deve ter a interface mostrando diferenças claramente. Seria bom aqui fazer testes manuais com vários documentos para validar se tudo faz sentido visualmente.
	•	Dia 4: PDF Export e Refinamento Backend
Meta: Funcionalidade de exportar PDF operando e backend robusto com limpeza de temporários.
Tarefas: Integrar Puppeteer no backend e implementar /pdf. Testar gerando PDF localmente primeiro (cuidado com dependências do Chromium, talvez instalar pacote adicional se estiver em ambiente serverless – no Railway geralmente funciona out of the box, no Vercel requer aquele pacote chrome-aws-lambda). Ajustar o conteúdo do PDF: pode criar um template HTML estático por enquanto que consome o resultado (ex: uma página HTML com links das fontes CSS, etc.). Conectar o frontend: implementar o handler do botão “Exportar PDF” para chamar o endpoint e realizar o download. Testar com um diff real se o PDF sai correto. Implementar a limpeza: seja via setTimeout ou cron, escreva esse código e teste reduzindo o tempo para confirmar. Se ainda não o fez, este dia também é bom para integrar Supabase Auth se for uma necessidade – configurar o projeto Supabase e testando login/logout (porque no dia 5 já queremos rodar testes e deploy, então convém ter auth configurado até o 4 se possível).
	•	Dia 5: Testes, Correções e Autenticação (se aplicável)
Meta: MVP funcional completado, com testes básicos passando, e autenticação integrada (opcional).
Tarefas: Escrever os testes unitários para a função de diff e quaisquer outras críticas. Executá-los e corrigir bugs que apareçam (por exemplo, casos não tratados). Implementar testes E2E simples se houver tempo, ou pelo menos realizar um “test run” manual de todo o fluxo em ambiente que simule produção (por exemplo, buildar o front e rodar o back localmente, para ver o comportamento sem o conveniente do dev mode). Finalizar integração de Supabase Auth se deixou para este dia: proteger rotas (por exemplo, no frontend, se user não logado e tentar usar a página, mostrar tela de login). Testar login de fato (use uma conta Google de teste configurada no Supabase). Resolver qualquer problema de CORS ou token entre front-back.
	•	Também use este dia para polir a UX: mensagens de erro amigáveis (ex: se upload falhar ou diff endpoint retornar erro, exibir “Não foi possível comparar esses documentos. Tente novamente.”), instruções no upload (talvez exemplos do que fazer), etc.
	•	Dia 6: Deploy e Feedback Rápido
Meta: Aplicação implantada em ambiente de teste (Vercel/Railway) e recebendo feedback.
Tarefas: Preparar os arquivos de configuração para deploy. No Vercel: configurar o projeto Next (basta conectar o repo, inserir as env vars do Supabase etc.). No Railway: criar um serviço para o backend, configurar env vars (Supabase, talvez a URL do front para CORS). Fazer deploy de ambos. Então realizar testes no ambiente de produção (às vezes surgem issues somente lá, como path de Chrome no Puppeteer, ou limit de função serverless). Colete feedback de um colega ou use como se fosse usuário final: é intuitivo? As cores estão boas na impressão? O sumário está correto?
	•	Aproveite o Cursor AI mesmo após deploy: se algum bug aparecer (ex: texto codificado errado, ou PDF cortando página), consulte-o para possíveis soluções rápidas.
	•	Inicie um README ou documentação rápida no repo para guiar usos e limitações do MVP.
	•	Dia 7: Buffer para Ajustes Finais (ou entrega)
Meta: Qualquer ponto pendente resolvido e MVP pronto para lançamento.
Tarefas: Se tudo correu bem, use esse dia adicional para melhorar detalhes: adicionar alguma pequena funcionalidade de nice-to-have se tempo (por exemplo, um botão “Trocar documentos” para inverter as versões, ou suporte a mais de um par de arquivos sem recarregar). Ou apenas refatore trechos de código que ficaram apressados, garantindo mantenibilidade. Verifique a consistência de todo o projeto (nomes de variáveis claros, arquivos organizados, remover logs de console desnecessários, comentários TODO resolvidos ou anotados para o futuro). Finalmente, faça a entrega: marque uma versão 1.0.0 no git, crie um release, ou simplesmente comunique que o MVP ClauseDiff está completo para uso interno/cliente, incluindo instruções de como rodar.

Esse cronograma naturalmente pode ser ajustado conforme suas circunstâncias – por exemplo, se você já tem experiência nessas tecnologias, talvez consiga juntar etapas ou ir mais rápido em algumas. O importante é ter metas claras a cada dia, de forma que ao final de cada estágio você tenha algo testável. Dessa maneira, qualquer problema é detectado cedo (feedback rápido) e pode ser corrigido sem comprometer o prazo final.

10. Dicas para Consistência, Versionamento e Ciclo Rápido de Feedback

Para assegurar que o desenvolvimento do ClauseDiff MVP transcorra de forma organizada e que futuras manutenções sejam fáceis, considere as seguintes práticas:
	•	Controle de Versão (Git): Utilize um repositório Git desde o início. Faça commits frequentes e com mensagens claras do tipo “Add diff endpoint with basic text comparison” ou “Style diff viewer with Tailwind highlights”. Isso ajuda a rastrear o que foi feito em cada etapa e reverter algo específico se o AI gerar código problemático. Estruture ramificações se estiver colaborando (no MVP talvez seja você sozinho, mas ainda assim, poderia usar uma branch dev e depois merge para main quando estável, simular um fluxo de release).
	•	Consistência de Código: Mantenha um padrão de código consistente, mesmo ao usar o AI. Por exemplo, se você prefere usar function expressions vs function declarations, ou determinado estilo de nome de variável (camelCase), tente seguir ao longo do projeto. Configure ferramentas como Prettier e ESLint para aplicar formatação automática. Isso evita que contribuições do AI venham com espaçamento diferente ou aspas simples vs duplas misturados, etc. O Cursor AI pode ser instruído a seguir certos padrões – por exemplo, inclua no prompt inicial ou com comentários no código preferências (ex: // Código em padrão Airbnb ESLint ou // usar async/await, não .then encadeado).
	•	Documentação e Comentários: Anote decisões importantes no README ou em comentários do código. Por exemplo, comente funções complexas como generateDiff explicando em uma linha o que ela retorna. Isso ajuda tanto você depois de dias intensos, quanto outra pessoa que vá olhar. Além disso, caso use o Cursor AI depois de um tempo longe do projeto, esses comentários servem de contexto para ele também. Documente no README como rodar o projeto, variáveis necessárias, etc., já pensando no momento do deploy e entrega.
	•	Utilize o Cursor para Feedback Rápido em Erros: Durante o desenvolvimento, se você se deparar com um erro ou comportamento inesperado, use o Cursor GPT para te ajudar a debugar. Por exemplo, se ao gerar PDF aparece um erro de falta de fonte ou de permissões no Chromium, copie o erro no chat e pergunte o que pode ser. Muitas vezes ele fornecerá dicas valiosas (como “No Vercel, Puppeteer precisa de configurações X”). Isso poupa tempo de buscar no Google manualmente. Da mesma forma, se um teste unitário falha, mostrar o trecho e a mensagem de erro ao AI pode levar a insights rápidos.
	•	Ciclo Ágil de Desenvolvimento: A integração do Cursor AI permite um ciclo code -> test -> feedback -> code muito rápido. Tire proveito disso rodando a aplicação em modo dev e testando interativamente a cada mudança significativa. Por exemplo, ao implementar o diff highlight, atualize um arquivo de teste e veja imediatamente no browser; se algo sai estranho, ajuste e atualize – o Next.js recompila rápido em dev. O same vale pro backend se usar nodemon para autoreload. Mantenha o servidor e o frontend rodando juntos e use duas janelas do navegador: uma na app, outra talvez nas devtools ou mostrando logs do backend. Assim, cada ação sua tem retorno imediato (feedback visual ou log), e você pode iterar. O AI entra aqui ajudando a implementar correções: se notar que um elemento não alinhou bem, peça ao Cursor “centralize verticalmente tal coisa” ao invés de você mesmo tentar mil CSS combos – ele faz e você vê o resultado quase instantaneamente.
	•	Manter Escopo Controlado: Com a facilidade de adicionar código via AI, há um risco de querer incluir muitas funcionalidades extras. Lembre-se do objetivo MVP. Mantenha a consistência funcional com o planejado. Se surgir uma ideia nova (ex: “seria legal destacar diferenças de formatação também”), anote numa lista de futuros aprimoramentos no README ao invés de implementar agora, a não ser que tenha tempo sobrando após atingir o essencial. Isso ajuda a evitar dispersão e mantém o versionamento claro (MVP v1 não tem feature X, v2 poderá ter).
	•	Versionamento Semântico: Considere versionar seu MVP (mesmo que internamente) como 0.1.0 ou 1.0.0. Depois cada conjunto de melhorias pode aumentar a versão (1.1, etc.). Taggear releases no git ajuda a saber que commit corresponde à versão implantada. Embora para um MVP interno isso seja opcional, é boa prática se habituar.
	•	Feedback de Usuários e Iterações: Se possível, envolva um usuário final (ou quem teve a ideia do ClauseDiff) o quanto antes – mostre um demo após o Dia 3 ou 4. O feedback inicial vai guiá-lo em ajustes de UX ou correções de interpretação. Usando o Cursor, você consegue fazer mudanças rapidamente baseadas nesse feedback. Por exemplo, se disserem “o verde tá muito claro para ler”, você em segundos muda a classe Tailwind de bg-green-100 para bg-green-200 e já vê o efeito. Essa rapidez em incorporar feedback antes de finalizar o ciclo aumenta a chance do MVP realmente resolver o problema de quem vai usar.
	•	Uso do Cursor a Longo Prazo: Depois de lançar o MVP, você pode continuar usando o Cursor GPT para manutenção e novas features. Mantenha o prompt de arquitetura (atualizado se algo mudou) à mão, para reaplicar e reorientar o AI quando for retornar ao projeto após um tempo. Ensine o AI com exemplos do seu próprio código – por exemplo, se você implementar mais tarde um recurso de comparar mais de 2 versões, mostre como fez para 2 e peça generalização. Esse ciclo de aprendizado contínuo aumenta a produtividade e consistência, pois o AI tende a replicar o estilo existente.
