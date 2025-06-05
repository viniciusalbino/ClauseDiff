import Link from 'next/link';

// ClauseDiff Icon component (consistent with other pages)
const ClauseDiffIcon = () => (
  <svg className="w-6 h-6 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
  </svg>
);

export default function TermsOfUsePage() {
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
              Termos de Uso
            </h1>
            <p className="mt-2 text-sm text-slate-600">
              Última atualização: {new Date().toLocaleDateString('pt-BR')}
            </p>
          </div>

          <div className="prose prose-slate max-w-none">
            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">1. Aceitação dos Termos</h2>
              <p className="text-slate-700 leading-relaxed">
                Ao acessar e utilizar o ClauseDiff, você concorda em cumprir estes Termos de Uso e todas as leis aplicáveis. 
                Se você não concordar com algum destes termos, está proibido de usar ou acessar este serviço.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">2. Descrição do Serviço</h2>
              <p className="text-slate-700 leading-relaxed mb-4">
                O ClauseDiff é uma plataforma de comparação de documentos que permite aos usuários:
              </p>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4">
                <li>Fazer upload e comparar documentos de texto</li>
                <li>Identificar diferenças entre versões de documentos</li>
                <li>Gerar relatórios de comparação</li>
                <li>Gerenciar histórico de comparações</li>
              </ul>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">3. Registro e Conta de Usuário</h2>
              <p className="text-slate-700 leading-relaxed mb-4">
                Para utilizar certas funcionalidades do ClauseDiff, você deve:
              </p>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4">
                <li>Criar uma conta fornecendo informações precisas e atualizadas</li>
                <li>Manter a confidencialidade de suas credenciais de acesso</li>
                <li>Ser responsável por todas as atividades que ocorrem em sua conta</li>
                <li>Notificar-nos imediatamente sobre uso não autorizado de sua conta</li>
              </ul>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">4. Uso Aceitável</h2>
              <p className="text-slate-700 leading-relaxed mb-4">
                Você concorda em NÃO usar o ClauseDiff para:
              </p>
              <ul className="list-disc list-inside text-slate-700 space-y-2 ml-4">
                <li>Fazer upload de conteúdo ilegal, difamatório ou que viole direitos de terceiros</li>
                <li>Tentar acessar sistemas ou dados não autorizados</li>
                <li>Interferir no funcionamento normal do serviço</li>
                <li>Usar o serviço para fins comerciais sem autorização prévia</li>
                <li>Reproduzir, distribuir ou criar trabalhos derivados sem permissão</li>
              </ul>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">5. Propriedade Intelectual</h2>
              <p className="text-slate-700 leading-relaxed">
                O ClauseDiff e todo seu conteúdo, funcionalidades e características são de propriedade da nossa empresa 
                e são protegidos por direitos autorais, marcas registradas e outras leis de propriedade intelectual. 
                Você mantém todos os direitos sobre os documentos que faz upload para comparação.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">6. Privacidade e Proteção de Dados</h2>
              <p className="text-slate-700 leading-relaxed">
                Sua privacidade é importante para nós. O tratamento de seus dados pessoais está descrito em nossa 
                <Link href="/politica-privacidade" className="text-blue-600 hover:text-blue-500 hover:underline">
                  Política de Privacidade
                </Link>, que faz parte destes Termos de Uso.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">7. Limitação de Responsabilidade</h2>
              <p className="text-slate-700 leading-relaxed">
                O ClauseDiff é fornecido "como está" sem garantias de qualquer tipo. Não nos responsabilizamos por 
                danos diretos, indiretos, incidentais ou consequenciais resultantes do uso ou incapacidade de usar nosso serviço.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">8. Modificações dos Termos</h2>
              <p className="text-slate-700 leading-relaxed">
                Reservamo-nos o direito de modificar estes termos a qualquer momento. As alterações entrarão em vigor 
                imediatamente após a publicação. O uso continuado do serviço após as modificações constitui aceitação dos novos termos.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">9. Encerramento</h2>
              <p className="text-slate-700 leading-relaxed">
                Podemos encerrar ou suspender sua conta e acesso ao serviço imediatamente, sem aviso prévio, 
                por qualquer motivo, incluindo violação destes Termos de Uso.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">10. Lei Aplicável</h2>
              <p className="text-slate-700 leading-relaxed">
                Estes Termos de Uso são regidos pelas leis brasileiras. Qualquer disputa será resolvida nos 
                tribunais competentes do Brasil.
              </p>
            </section>

            <section className="mb-8">
              <h2 className="text-2xl font-semibold text-slate-900 mb-4">11. Contato</h2>
              <p className="text-slate-700 leading-relaxed">
                Se você tiver dúvidas sobre estes Termos de Uso, entre em contato conosco através do email: 
                <a href="mailto:legal@clausediff.com" className="text-blue-600 hover:text-blue-500 hover:underline">
                  legal@clausediff.com
                </a>
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