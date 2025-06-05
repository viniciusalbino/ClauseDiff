import Link from 'next/link';

// ClauseDiff Icon component (consistent with other pages)
const ClauseDiffIcon = () => (
  <svg className="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
  </svg>
);

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col items-center justify-between p-4">
      <header className="w-full max-w-6xl mx-auto flex justify-between items-center py-4 px-2 sm:px-0">
        <Link href="/" className="flex items-center text-2xl font-semibold text-slate-700 hover:text-blue-600">
          <ClauseDiffIcon />
          ClauseDiff
        </Link>
        <Link href="/" className="text-sm text-slate-600 hover:text-blue-600 hover:underline">
          Voltar para Home
        </Link>
      </header>

      <main className="flex flex-col items-center justify-center w-full flex-grow">
        <div className="w-full max-w-4xl p-8 space-y-8 bg-white shadow-xl rounded-lg">
          <div className="text-center border-b border-slate-200 pb-6">
            <h1 className="text-4xl font-bold text-slate-900">
              Política de Privacidade
            </h1>
            <p className="mt-2 text-sm text-slate-600">
              Última atualização: {new Date().toLocaleDateString('pt-BR')}
            </p>
            <p className="mt-1 text-sm text-slate-500">
              Em conformidade com a LGPD (Lei Geral de Proteção de Dados)
            </p>
          </div>

          <div className="prose prose-slate max-w-none">
            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">1. Introdução</h2>
              <p className="text-slate-700 leading-relaxed">
                Esta Política de Privacidade descreve como o ClauseDiff coleta, usa, armazena e protege suas informações pessoais 
                quando você utiliza nossos serviços. Estamos comprometidos em proteger sua privacidade e em cumprir integralmente 
                a Lei Geral de Proteção de Dados (LGPD - Lei 13.709/2018).
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">2. Informações que Coletamos</h2>
              
              <h3 className="text-xl font-medium text-slate-900 mb-3">2.1 Dados Pessoais Fornecidos por Você</h3>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4 mb-4">
                <li><strong>Dados de Cadastro:</strong> Nome, sobrenome, endereço de email</li>
                <li><strong>Dados Opcionais:</strong> Cidade, estado, CPF</li>
                <li><strong>Dados de Autenticação:</strong> Senha criptografada</li>
                <li><strong>Dados de OAuth:</strong> Informações básicas do Google (quando utilizado)</li>
              </ul>

              <h3 className="text-xl font-medium text-slate-900 mb-3">2.2 Dados Coletados Automaticamente</h3>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4 mb-4">
                <li><strong>Dados de Uso:</strong> Logs de acesso, IP, navegador, sistema operacional</li>
                <li><strong>Dados de Sessão:</strong> Cookies de autenticação e preferências</li>
                <li><strong>Dados de Segurança:</strong> Tentativas de login, eventos de segurança</li>
              </ul>

              <h3 className="text-xl font-medium text-slate-900 mb-3">2.3 Conteúdo dos Documentos</h3>
              <p className="text-slate-700 leading-relaxed">
                Os documentos que você faz upload para comparação são processados temporariamente e não são armazenados 
                permanentemente em nossos servidores, exceto quando necessário para fornecer o serviço solicitado.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">3. Base Legal e Finalidades do Tratamento</h2>
              
              <h3 className="text-xl font-medium text-slate-900 mb-3">3.1 Execução de Contrato</h3>
              <p className="text-slate-700 leading-relaxed mb-4">
                Tratamos seus dados pessoais para fornecer nossos serviços de comparação de documentos, 
                gerenciar sua conta e processar suas solicitações.
              </p>

              <h3 className="text-xl font-medium text-slate-900 mb-3">3.2 Legítimo Interesse</h3>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4 mb-4">
                <li>Melhorar nossos serviços e experiência do usuário</li>
                <li>Prevenir fraudes e garantir a segurança da plataforma</li>
                <li>Realizar análises estatísticas (dados anonimizados)</li>
              </ul>

              <h3 className="text-xl font-medium text-slate-900 mb-3">3.3 Consentimento</h3>
              <p className="text-slate-700 leading-relaxed">
                Para dados opcionais e comunicações de marketing (quando aplicável), 
                solicitamos seu consentimento explícito, que pode ser retirado a qualquer momento.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">4. Como Protegemos seus Dados</h2>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4">
                <li><strong>Criptografia:</strong> Senhas são criptografadas com bcrypt e salt</li>
                <li><strong>HTTPS:</strong> Todas as comunicações são criptografadas em trânsito</li>
                <li><strong>Controle de Acesso:</strong> Autenticação obrigatória para dados sensíveis</li>
                <li><strong>Logs de Auditoria:</strong> Monitoramento de atividades suspeitas</li>
                <li><strong>Rate Limiting:</strong> Proteção contra ataques de força bruta</li>
                <li><strong>Headers de Segurança:</strong> CSP, HSTS e outras proteções</li>
              </ul>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">5. Compartilhamento de Dados</h2>
              <p className="text-slate-700 leading-relaxed mb-4">
                <strong>Não vendemos, alugamos ou compartilhamos</strong> seus dados pessoais com terceiros para fins comerciais. 
                Podemos compartilhar dados apenas nas seguintes situações:
              </p>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4">
                <li><strong>Prestadores de Serviço:</strong> Provedores de hospedagem e infraestrutura (com contratos de proteção)</li>
                <li><strong>Obrigação Legal:</strong> Quando exigido por lei ou ordem judicial</li>
                <li><strong>Proteção de Direitos:</strong> Para proteger nossos direitos legais ou de terceiros</li>
              </ul>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">6. Retenção de Dados</h2>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4">
                <li><strong>Contas Ativas:</strong> Dados mantidos enquanto a conta estiver ativa</li>
                <li><strong>Dados de Segurança:</strong> Logs mantidos por até 12 meses</li>
                <li><strong>Documentos:</strong> Processados temporariamente e excluídos após a comparação</li>
                <li><strong>Contas Inativas:</strong> Dados podem ser excluídos após 24 meses de inatividade</li>
              </ul>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">7. Seus Direitos (LGPD)</h2>
              <p className="text-slate-700 leading-relaxed mb-4">
                Conforme a LGPD, você tem os seguintes direitos sobre seus dados pessoais:
              </p>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4">
                <li><strong>Acesso:</strong> Solicitar acesso aos seus dados pessoais</li>
                <li><strong>Correção:</strong> Corrigir dados incompletos, inexatos ou desatualizados</li>
                <li><strong>Exclusão:</strong> Solicitar a exclusão de dados desnecessários ou tratados em desconformidade</li>
                <li><strong>Portabilidade:</strong> Solicitar a portabilidade dos dados a outro fornecedor</li>
                <li><strong>Revogação:</strong> Revogar o consentimento para tratamento de dados</li>
                <li><strong>Informação:</strong> Obter informações sobre o tratamento de seus dados</li>
              </ul>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">8. Cookies e Tecnologias Similares</h2>
              <p className="text-slate-700 leading-relaxed mb-4">
                Utilizamos cookies essenciais para:
              </p>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4 mb-4">
                <li>Manter sua sessão autenticada</li>
                <li>Proteger contra ataques CSRF</li>
                <li>Lembrar suas preferências de interface</li>
              </ul>
              <p className="text-slate-700 leading-relaxed">
                Você pode gerenciar cookies através das configurações do seu navegador, mas isso pode afetar 
                o funcionamento do serviço.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">9. Transferência Internacional</h2>
              <p className="text-slate-700 leading-relaxed">
                Seus dados são processados e armazenados em servidores localizados no Brasil. 
                Caso haja necessidade de transferência internacional, esta será feita em conformidade 
                com as exigências da LGPD e com garantias adequadas de proteção.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">10. Menores de Idade</h2>
              <p className="text-slate-700 leading-relaxed">
                Nossos serviços não são direcionados a menores de 18 anos. Não coletamos 
                conscientemente dados pessoais de menores. Se descobrirmos que coletamos dados 
                de um menor sem o consentimento dos pais, tomaremos medidas para excluir essas informações.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">11. Alterações nesta Política</h2>
              <p className="text-slate-700 leading-relaxed">
                Esta Política de Privacidade pode ser atualizada periodicamente. Notificaremos você sobre 
                mudanças significativas por email ou através da plataforma. A data da última atualização 
                sempre estará indicada no topo desta página.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">12. Contato e Encarregado de Dados</h2>
              <p className="text-slate-700 leading-relaxed mb-4">
                Para exercer seus direitos, esclarecer dúvidas ou fazer reclamações sobre o tratamento 
                de seus dados pessoais, entre em contato conosco:
              </p>
              <div className="bg-slate-100 p-4 rounded-lg">
                <p className="text-slate-700">
                  <strong>Email:</strong> <a href="mailto:privacidade@clausediff.com" className="text-blue-600 hover:text-blue-500 hover:underline">privacidade@clausediff.com</a><br/>
                  <strong>Encarregado de Dados (DPO):</strong> <a href="mailto:dpo@clausediff.com" className="text-blue-600 hover:text-blue-500 hover:underline">dpo@clausediff.com</a>
                </p>
              </div>
              <p className="text-slate-700 leading-relaxed mt-4">
                Você também pode apresentar reclamação à Autoridade Nacional de Proteção de Dados (ANPD) 
                se considerar que seus direitos não foram adequadamente atendidos.
              </p>
            </section>
          </div>
        </div>
      </main>

      <footer className="w-full max-w-6xl mx-auto text-center py-6 px-2 sm:px-0">
        <div className="flex flex-col sm:flex-row justify-center items-center space-y-2 sm:space-y-0 sm:space-x-6">
          <Link href="/termos-de-uso" className="text-xs text-slate-600 hover:text-blue-600 hover:underline">
            Termos de Uso
          </Link>
          <Link href="/politica-privacidade" className="text-xs text-slate-600 hover:text-blue-600 hover:underline">
            Política de Privacidade
          </Link>
        </div>
        <p className="text-xs text-slate-500 mt-2">
          © {new Date().getFullYear()} ClauseDiff. Todos os direitos reservados.
        </p>
      </footer>
    </div>
  );
} 