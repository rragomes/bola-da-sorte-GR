const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

// Importar as funções do database.js
const { 
    pool, 
    promisePool, 
    testConnection, 
    initializeDatabase, 
    countAdmins, 
    cleanupExpiredSessions 
} = require("../lib/database");

// Carrega as variáveis de ambiente
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY;
const APOSTADOR_SECRET_KEY = process.env.APOSTADOR_SECRET_KEY;

// Inicialização do banco de dados
(async () => {
    await testConnection();
    await initializeDatabase();
})();

// Middleware
// Configuração do CORS
app.use(cors({
    origin: ['https://boladasorte.vercel.app', 'http://localhost:3000'],
    credentials: true
  }));

  
app.use(bodyParser.json());
app.use(helmet());
app.use(express.json());

// Middleware para verificar o tipo de usuário
function authorizeRole(requiredRole) {
    return (req, res, next) => {
        if (req.user.tipo !== requiredRole) {
            return res.status(403).json({ error: "Acesso negado! Permissão insuficiente." });
        }
        next();
    };
}

// Limitação de requisições (por IP)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Muitas requisições vindas deste IP. Por favor, tente novamente mais tarde.",
});
app.use(limiter);

function autenticarJWT(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Token não fornecido!" });
    }

    // Verificar se o token está na lista de sessões ativas
    const query = `SELECT * FROM active_sessions WHERE token = ? AND expires_at > NOW()`;
    pool.query(query, [token], (err, result) => {
        if (err) {
            console.error("Erro ao verificar sessão:", err.message);
            return res.status(500).json({ error: "Erro ao verificar autenticação!" });
        }

        if (result.length === 0) {
            return res.status(403).json({ error: "Sessão inválida ou expirada!" });
        }

        const session = result[0];
        const secretKey = session.session_type === 'admin' ? ADMIN_SECRET_KEY : APOSTADOR_SECRET_KEY;

        jwt.verify(token, secretKey, (err, decoded) => {
            if (err) {
                // Se o token estiver inválido, remover da tabela de sessões ativas
                pool.query(`DELETE FROM active_sessions WHERE token = ?`, [token]);
                return res.status(403).json({ error: "Token inválido ou expirado!" });
            }

            req.user = decoded;
            req.sessionType = session.session_type;
            next();
        });
    });
}

// Servir arquivos estáticos da pasta public
app.use(express.static(path.join(__dirname, '../public')));

// Rota para a página inicial
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Rotas para as outras páginas
app.get('/tela-usuario.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/tela-usuario.html'));
});

app.get('/tela-administrador.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/tela-administrador.html'));
});

app.get('/minhas_apostas.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/minhas_apostas.html'));
});

// Atualizar o endpoint para salvar as apostas com o user_id
app.post(
    "/apostas",
    autenticarJWT, // Apenas exige que o usuário esteja autenticado
    [
        body("apostas").isArray({ min: 1 }).withMessage("Apostas devem ser um array com pelo menos 1 item."),
        body("apostas.*.jogo").isString().withMessage("O campo 'jogo' deve ser uma string."),
        body("apostas.*.opcoes")
            .isArray({ min: 1 })
            .withMessage("O campo 'opcoes' deve ser um array com pelo menos 1 opção."),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        // Extrair o usuário e as apostas do request
        const { firstName, lastName } = req.user; // Nome do usuário autenticado
        const apostas = req.body.apostas; // Apostas enviadas no corpo da requisição

        // Nome completo do usuário
        const userName = `${firstName} ${lastName}`;

        // Calcular o valor total da aposta (valor base = R$10)
        let valorTotal = 10;
        let multiplicador = 1;

        // Aplicar multiplicadores para cada aposta com dupla ou tripla
        apostas.forEach(aposta => {
            if (aposta.opcoes.length === 2) {
                multiplicador *= 2; // Dupla multiplica por 2
            } else if (aposta.opcoes.length === 3) {
                multiplicador *= 3; // Tripla multiplica por 3
            }
        });

        // Aplicar o multiplicador total
        valorTotal *= multiplicador;

        // Concatenar os jogos e as opções em strings para salvar no banco
        const jogos = apostas.map((aposta) => aposta.jogo).join(", "); // String com os jogos separados por vírgula
        const opcoes = apostas.map((aposta) => aposta.opcoes.join(",")).join("; "); // String com as opções separadas

        // Query para inserir os dados no banco de dados
        const query = `
        INSERT INTO apostas (user_name, jogo, opcoes, valor_total)
        VALUES (?, ?, ?, ?)`;

        // Executar a query no banco de dados
        pool.query(query, [userName, jogos, opcoes, valorTotal], (err, result) => {
            if (err) {
                console.error("Erro ao salvar aposta no banco de dados:", err.message);
                return res.status(500).json({ error: "Erro ao salvar a aposta no banco de dados." });
            }

            // Obter o ID da aposta criada
            const apostaId = result.insertId;

            // Retornar uma resposta de sucesso
            res.status(201).json({
                message: "Aposta salva com sucesso!",
                aposta: {
                    id: apostaId,
                    user_name: userName,
                    jogos,
                    opcoes,
                    valor_total: valorTotal,
                },
            });
        });
    }
);

// Atualizar o endpoint para retornar apostas agrupadas por usuário
app.get("/apostas", autenticarJWT, (req, res) => {
    if (req.user.tipo !== 'admin') {
        return res.status(403).json({ error: "Acesso negado! Somente administradores podem ver todas as apostas." });
    }

    const query = `
        SELECT 
            id,
            user_name,
            jogo,
            opcoes,
            valor_total
        FROM 
            apostas
        ORDER BY 
            id DESC
    `;

    pool.query(query, (err, result) => {
        if (err) {
            console.error("Erro ao buscar apostas:", err.message);
            return res.status(500).json({ error: "Erro ao buscar apostas no banco de dados." });
        }

        const apostas = result.map((row) => ({
            id: row.id,
            user_name: row.user_name,
            jogos: row.jogo.split(", "),
            opcoes: row.opcoes.split("; ").map((op) => op.split(",")),
            valor_total: row.valor_total,
        }));

        res.json({ apostas });
    });
});

// Endpoint para excluir uma aposta do próprio usuário
app.delete("/apostas/:id", autenticarJWT, (req, res) => {
    const apostaId = req.params.id;
    const { firstName, lastName } = req.user; // Nome do usuário autenticado
    const userName = `${firstName} ${lastName}`; // Nome completo do usuário

    const query = `DELETE FROM apostas WHERE id = ? AND user_name = ?`;

    // Executar a query para excluir a aposta no banco de dados
    pool.query(query, [apostaId, userName], (err, result) => {
        if (err) {
            console.error("Erro ao excluir aposta:", err.message);
            return res.status(500).json({ error: "Erro ao excluir aposta no banco de dados." });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Aposta não encontrada ou você não tem permissão para excluí-la." });
        }

        res.status(200).json({ message: "Aposta excluída com sucesso!" });
    });
});

// Rota para buscar as apostas do usuário logado
app.get("/minhas-apostas", autenticarJWT, (req, res) => {
    const { firstName, lastName } = req.user; // Nome do usuário autenticado
    const userName = `${firstName} ${lastName}`; // Nome completo do usuário

    const query = `
        SELECT 
            id,
            jogo,
            opcoes,
            valor_total
        FROM 
            apostas
        WHERE 
            user_name = ?
        ORDER BY 
            id DESC
    `;

    // Buscar as apostas do usuário no banco de dados
    pool.query(query, [userName], (err, result) => {
        if (err) {
            console.error("Erro ao buscar apostas do usuário:", err.message);
            return res.status(500).json({ error: "Erro ao buscar apostas no banco de dados." });
        }

        if (result.length === 0) {
            return res.status(404).json({ message: "Nenhuma aposta encontrada." });
        }

        // Processar os dados das apostas
        const apostas = result.map((row) => ({
            id: row.id,
            jogos: row.jogo.split(", "), // Separar os jogos por vírgula
            opcoes: row.opcoes.split("; ").map((op) => op.split(",")), // Separar as opções
            valor_total: row.valor_total,
        }));

        // Calcular o valor total a pagar
        const valorTotal = apostas.reduce((total, aposta) => total + aposta.valor_total, 0);

        res.json({
            usuario: userName,
            apostas,
            valorTotal,
        });
    });
});

// Rota de cadastro
app.post(
    "/register",
    [
        body("firstName").isLength({ min: 2 }).withMessage("O nome deve ter pelo menos 2 caracteres."),
        body("lastName").isLength({ min: 2 }).withMessage("O sobrenome deve ter pelo menos 2 caracteres."),
        body("email").isEmail().withMessage("E-mail inválido."),
        body("password").isLength({ min: 6 }).withMessage("A senha deve ter pelo menos 6 caracteres."),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { firstName, lastName, email, password, tipo, cpf } = req.body;

        if (tipo === "admin") {
            if (!cpf) {
                return res.status(400).json({ error: "CPF é obrigatório para administradores!" });
            }

            try {
                const count = await countAdmins();
                if (count >= 2) {
                    return res.status(400).json({ error: "Já existem dois administradores cadastrados no sistema!" });
                }

                const hashedPassword = await bcrypt.hash(password, 10);

                const query = `INSERT INTO users (firstName, lastName, email, password, tipo, cpf) VALUES (?, ?, ?, ?, ?, ?)`;
                pool.query(query, [firstName, lastName, email, hashedPassword, tipo, cpf], (err) => {
                    if (err) {
                        if (err.code === 'ER_DUP_ENTRY') {
                            return res.status(400).json({ error: "E-mail já cadastrado!" });
                        }
                        console.error("Erro ao cadastrar administrador:", err.message);
                        return res.status(500).json({ error: "Erro ao cadastrar administrador!" });
                    }

                    return res.status(201).json({ message: "Administrador cadastrado com sucesso!" });
                });
            } catch (err) {
                console.error("Erro ao verificar administradores:", err);
                return res.status(500).json({ error: "Erro ao verificar administradores!" });
            }
        } else {
            try {
                const hashedPassword = await bcrypt.hash(password, 10);

                const query = `INSERT INTO users (firstName, lastName, email, password, tipo) VALUES (?, ?, ?, ?, ?)`;
                pool.query(query, [firstName, lastName, email, hashedPassword, "apostador"], (err) => {
                    if (err) {
                        if (err.code === 'ER_DUP_ENTRY') {
                            return res.status(400).json({ error: "E-mail já cadastrado!" });
                        }
                        console.error("Erro ao cadastrar apostador:", err.message);
                        return res.status(500).json({ error: "Erro ao cadastrar apostador!" });
                    }

                    return res.status(201).json({ message: "Apostador cadastrado com sucesso!" });
                });
            } catch (err) {
                console.error("Erro ao hashear a senha:", err);
                return res.status(500).json({ error: "Erro ao hashear a senha!" });
            }
        }
    }
);

// Rota de login modificada para usar sessões separadas
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "E-mail e senha são obrigatórios!" });
    }

    const query = `SELECT * FROM users WHERE email = ?`;
    pool.query(query, [email], (err, result) => {
        if (err) {
            console.error("Erro ao buscar usuário:", err.message);
            return res.status(500).json({ error: "Erro ao buscar usuário!" });
        }

        const user = result[0]; // Para MySQL, acessar diretamente o primeiro elemento

        if (!user) {
            return res.status(401).json({ error: "Usuário ou senha inválidos!" });
        }

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) {
                return res.status(401).json({ error: "Usuário ou senha inválidos!" });
            }

            // Escolher a chave secreta com base no tipo de usuário
            const secretKey = user.tipo === 'admin' ? ADMIN_SECRET_KEY : APOSTADOR_SECRET_KEY;
            
            // Definir tempo de expiração (1 hora)
            const expiresIn = '1h';
            const expiresAt = new Date();
            expiresAt.setHours(expiresAt.getHours() + 1);

            const tokenPayload = {
                id: user.id,
                tipo: user.tipo,
                firstName: user.firstName,
                lastName: user.lastName,
            };

            const token = jwt.sign(tokenPayload, secretKey, { expiresIn });

            // Verificar se já existe uma sessão ativa para este usuário com o mesmo tipo
            const checkSessionQuery = `
                SELECT * FROM active_sessions 
                WHERE user_id = ? AND session_type = ?
            `;
            
            pool.query(checkSessionQuery, [user.id, user.tipo], (err, sessions) => {
                if (err) {
                    console.error("Erro ao verificar sessões existentes:", err.message);
                    return res.status(500).json({ error: "Erro ao processar login!" });
                }

                // Se já existe uma sessão do mesmo tipo, substituir
                if (sessions.length > 0) {
                    const updateQuery = `
                        UPDATE active_sessions 
                        SET token = ?, created_at = NOW(), expires_at = ? 
                        WHERE user_id = ? AND session_type = ?
                    `;
                    
                    pool.query(updateQuery, [token, expiresAt, user.id, user.tipo], (err) => {
                        if (err) {
                            console.error("Erro ao atualizar sessão:", err.message);
                            return res.status(500).json({ error: "Erro ao processar login!" });
                        }
                        
                        return res.status(200).json({
                            token,
                            tipo: user.tipo,
                            firstName: user.firstName,
                            lastName: user.lastName,
                        });
                    });
                } else {
                    // Criar uma nova sessão
                    const insertQuery = `
                        INSERT INTO active_sessions (user_id, session_type, token, expires_at)
                        VALUES (?, ?, ?, ?)
                    `;
                    
                    pool.query(insertQuery, [user.id, user.tipo, token, expiresAt], (err) => {
                        if (err) {
                            console.error("Erro ao criar sessão:", err.message);
                            return res.status(500).json({ error: "Erro ao processar login!" });
                        }
                        
                        return res.status(200).json({
                            token,
                            tipo: user.tipo,
                            firstName: user.firstName,
                            lastName: user.lastName,
                        });
                    });
                }
            });
        });
    });
});

// Adicionar rota de logout
app.post("/logout", autenticarJWT, (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    
    if (!token) {
        return res.status(400).json({ error: "Token não fornecido!" });
    }
    
    // Remover o token da tabela de sessões ativas
    const query = `DELETE FROM active_sessions WHERE token = ?`;
    
    pool.query(query, [token], (err, result) => {
        if (err) {
            console.error("Erro ao fazer logout:", err.message);
            return res.status(500).json({ error: "Erro ao processar logout!" });
        }
        
        return res.status(200).json({ message: "Logout realizado com sucesso!" });
    });
});

// Para qualquer outra rota, redirecionar para index.html (para SPA)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Limpar sessões expiradas periodicamente (não funcionará no ambiente serverless)
// Em vez disso, vamos limpar as sessões expiradas em cada requisição de autenticação
app.use((req, res, next) => {
    if (req.path === '/login' || req.path === '/register' || req.headers.authorization) {
        cleanupExpiredSessions();
    }
    next();
});

// Vercel serverless handler
if (process.env.NODE_ENV === 'production') {
    module.exports = app;
} else {
    // Inicializa o servidor para desenvolvimento local
    app.listen(PORT, () => {
        console.log(`Servidor rodando em http://localhost:${PORT}`);
    });
}