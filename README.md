# Projeto de Controle de Finanças Pessoais

Este projeto é uma API RESTful desenvolvida em Node.js para um sistema de controle de finanças pessoais, como parte da avaliação da disciplina de Segurança de Sistemas. A API permite o gerenciamento de usuários, categorias, receitas e despesas, com um foco especial na implementação de boas práticas de segurança.

## Tecnologias Utilizadas

* **Backend:** Node.js, Express.js
* **Banco de Dados:** MySQL com Sequelize ORM
* **Autenticação:** JSON Web Tokens (JWT)
* **Segurança:**
    * `helmet`: Para proteção de cabeçalhos HTTP.
    * `bcrypt`: Para hashing de senhas.
    * `csurf`: Para proteção contra ataques Cross-Site Request Forgery (CSRF).
    * `joi`: Para validação de schemas de dados de entrada.
    * `multer`: Para upload seguro de arquivos.
* **Outras:** `dotenv`, `cors`, `cookie-parser`

## Instruções para Rodar Localmente

### Pré-requisitos
* Node.js (versão 18 ou superior)
* NPM ou Yarn
* Um servidor de banco de dados MySQL rodando localmente.

### Passos

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/seu-usuario/seu-repositorio.git](https://github.com/seu-usuario/seu-repositorio.git)
    cd seu-repositorio
    ```

2.  **Instale as dependências:**
    ```bash
    npm install
    ```

3.  **Configure o banco de dados:**
    * Crie um banco de dados no seu MySQL com o nome `financas_pessoais`.
    * Você pode usar um cliente como DBeaver, HeidiSQL ou o próprio terminal MySQL.

4.  **Configure as variáveis de ambiente:**
    * Crie um arquivo chamado `.env` na raiz do projeto.
    * Copie o conteúdo do arquivo `.env.example` (se houver) ou use o modelo abaixo e preencha com suas credenciais:
    ```ini
    DB_USER=root
    DB_PASSWORD=sua_senha_do_mysql
    DB_HOST=localhost
    DB_NAME=financas_pessoais
    JWT_SECRET=crie_um_segredo_forte_aqui
    CSRF_SECRET=crie_outro_segredo_forte_aqui
    PORT=3000
    ```

5.  **Inicie o servidor:**
    ```bash
    npm start
    ```
    O servidor estará rodando em `http://localhost:3000`.

## Tratamento de Vulnerabilidades de Segurança

O sistema foi desenvolvido para mitigar as seguintes vulnerabilidades:

### 1. Hardcoded SQL & SQL Injection
* **Solução:** Utilizamos o **Sequelize ORM**. Todas as consultas ao banco de dados são feitas através de métodos do Sequelize, que automaticamente parametrizam as queries. Isso elimina a necessidade de escrever SQL manualmente e previne ataques de SQL Injection, pois os dados do usuário nunca são concatenados diretamente na string de consulta.

### 2. Cross-Site Scripting (XSS)
* **Solução:**
    * **`helmet`**: A biblioteca Helmet adiciona cabeçalhos HTTP de segurança, como `Content-Security-Policy`, que instruem o navegador a apenas executar scripts de fontes confiáveis, mitigando XSS.
    * **Cookies `HttpOnly`**: O token de autenticação JWT e o token CSRF são armazenados em cookies com a flag `HttpOnly`. Isso impede que scripts maliciosos no lado do cliente acessem esses cookies, tornando o roubo de tokens muito mais difícil.

### 3. Cross-Site Request Forgery (CSRF)
* **Solução:** Implementamos a biblioteca **`csurf`**. O backend gera um token CSRF único por sessão e o envia ao cliente. Para cada requisição que modifica o estado (POST, PUT, DELETE), o cliente deve enviar este token de volta (geralmente em um cabeçalho, como `X-CSRF-Token`). O servidor valida o token antes de processar a requisição, garantindo que ela foi originada de forma legítima pela nossa aplicação frontend.

### 4. Mass Assignment
* **Solução:**
    * **Validação com `Joi`**: Antes de processar qualquer dado de entrada (`req.body`), utilizamos schemas `Joi` para validar e garantir que apenas os campos esperados estão presentes e no formato correto. Campos extras enviados pelo cliente são ignorados.
    * **Criação Explícita**: Nos controllers, ao criar ou atualizar um registro (ex: `Transaction.create()`), construímos o objeto de dados explicitamente com as variáveis validadas, em vez de passar o `req.body` inteiro. Isso garante que um invasor não possa sobrescrever campos sensíveis como `idUser` ou `isAdmin`.

### 5. Session Hijacking
* **Solução:**
    * **JWT em Cookies `HttpOnly` e `Secure`**: Como mencionado, armazenar o token em um cookie `HttpOnly` previne seu roubo via XSS. A flag `Secure` (ativada em produção) garante que o cookie só seja enviado sobre HTTPS, prevenindo ataques *man-in-the-middle*.
    * **Tokens com Expiração Curta**: Nossos JWTs são configurados para expirar em um período curto (1 hora). Isso limita a janela de oportunidade para um invasor caso um token seja comprometido. Para uma experiência de usuário melhor, uma implementação com *refresh tokens* seria o próximo passo.
    * **Proteção CSRF**: A proteção CSRF também ajuda a garantir que a sessão do usuário não seja usada por um site malicioso para realizar ações em seu nome.

### 6. Outras Vulnerabilidades
* **Validação de Entrada:** A biblioteca `Joi` é usada em todas as rotas que recebem dados para garantir que os tipos, formatos e valores estejam dentro do esperado.
* **Autenticação Segura:** Senhas são hasheadas com `bcrypt` (com salt) antes de serem salvas no banco. A comparação durante o login também é feita usando `bcrypt.compare`, prevenindo *timing attacks*.
* **Upload de Arquivos:** Usamos `multer` para gerenciar uploads. Configuramos limites de tamanho de arquivo e filtros de tipo de arquivo (`mimetype`) para garantir que apenas PDFs e imagens sejam enviados, prevenindo o upload de arquivos maliciosos.