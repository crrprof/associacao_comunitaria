# Associação Comunitária Esperança — MVP

Aplicação web simples para organizar participantes e inscrições em atividades comunitárias.

## Funcionalidades
- Login de acesso com senha armazenada em hash Argon2.
- Cadastro, consulta, edição e exclusão de participantes.
- Registro e cancelamento de inscrições.
- Validação de campos obrigatórios no servidor.
- Consultas SQL parametrizadas e proteção CSRF nos formulários.
- Banco SQLite com chave estrangeira entre participantes e inscrições.
- Interface responsiva básica.

## Tecnologias
Python 3.11 ou superior, Flask, SQLite, Flask-WTF, Flask-Limiter e Argon2.

## Executar localmente
1. Instale Python 3.11+.
2. Crie e ative um ambiente virtual:
   - Windows: `python -m venv .venv` e `.venv\\Scripts\\activate`
   - macOS/Linux: `python3 -m venv .venv` e `source .venv/bin/activate`
3. Instale as dependências: `pip install -r requirements.txt`
4. Copie `.env.example` para `.env`.
5. Altere `SECRET_KEY` e `ADMIN_PASSWORD` no `.env`.
6. Execute `python app.py`.
7. Acesse `http://127.0.0.1:5000`.

O usuário administrador é criado na primeira execução quando `ADMIN_USERNAME` e `ADMIN_PASSWORD` estão definidos. Para trocar a senha depois da criação inicial, implemente um fluxo administrativo ou recrie o banco de desenvolvimento.

## GitHub
Não envie `.env`, o arquivo SQLite ou dados reais para o repositório. O `.gitignore` já exclui esses itens.

## Observações de segurança
- O servidor usa cookies HTTPOnly e SameSite=Lax.
- Em hospedagem HTTPS, configure `COOKIE_SECURE=1` e uma `SECRET_KEY` forte.
- Não use `FLASK_DEBUG=1` em produção.
- Use somente dados fictícios nos testes.
- O protótipo ainda precisa de revisão, testes e configuração segura antes de receber dados reais, especialmente dados de crianças e adolescentes.

## Escopo atual
Este é um MVP acadêmico. Não inclui recuperação de senha, perfis avançados de permissão, notificações por WhatsApp, relatórios avançados ou integração com serviços externos.
