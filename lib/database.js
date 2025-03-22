// lib/database.js
require('dotenv').config();
const mysql = require('mysql2');

// Criar pool de conexões
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '4000'),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
    },
    // Configurações recomendadas para TiDB Serverless
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

// Promisify para uso com async/await
const promisePool = pool.promise();

// Função para testar a conexão
const testConnection = async () => {
    try {
        const [rows] = await promisePool.query('SELECT NOW() as now');
        console.log('Conexão com TiDB bem-sucedida! Data atual:', rows[0].now);
        return true;
    } catch (err) {
        console.error('Erro ao conectar ao TiDB:', err);
        return false;
    }
};

// Função para verificar se uma tabela existe
const tableExists = async (tableName) => {
    try {
        const [rows] = await promisePool.query(
            `SELECT COUNT(*) AS count FROM information_schema.tables 
             WHERE table_schema = ? AND table_name = ?`,
            [process.env.DB_NAME || 'test', tableName]
        );
        return rows[0].count > 0;
    } catch (err) {
        console.error(`Erro ao verificar se a tabela ${tableName} existe:`, err);
        return false;
    }
};

// Função para verificar se um índice existe
const indexExists = async (tableName, indexName) => {
    try {
        const [rows] = await promisePool.query(
            `SELECT COUNT(*) AS count FROM information_schema.statistics 
             WHERE table_schema = ? AND table_name = ? AND index_name = ?`,
            [process.env.DB_NAME || 'test', tableName, indexName]
        );
        return rows[0].count > 0;
    } catch (err) {
        console.error(`Erro ao verificar se o índice ${indexName} existe:`, err);
        return false;
    }
};

// Inicialização do banco de dados em sequência correta
const initializeDatabase = async () => {
    try {
        // 1. Criar tabela de usuários primeiro
        if (!(await tableExists('users'))) {
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    firstName TEXT NOT NULL,
                    lastName TEXT NOT NULL,
                    email TEXT,
                    password TEXT NOT NULL,
                    tipo TEXT,
                    cpf TEXT
                )
            `);
            console.log("Tabela 'users' criada com sucesso.");
        } else {
            console.log("Tabela 'users' já existe.");
        }

        // 2. Criar índice de email após a tabela existir
        if (!(await indexExists('users', 'idx_email'))) {
            await promisePool.query(`CREATE INDEX idx_email ON users (email(255))`);
            console.log("Índice 'idx_email' criado com sucesso.");
        } else {
            console.log("Índice 'idx_email' já existe.");
        }

        // 3. Criar tabela de apostas
        if (!(await tableExists('apostas'))) {
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS apostas (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_name TEXT,
                    jogo TEXT NOT NULL,
                    opcoes TEXT NOT NULL,
                    valor_total DECIMAL(10, 2) NOT NULL
                )
            `);
            console.log("Tabela 'apostas' criada com sucesso.");
        } else {
            console.log("Tabela 'apostas' já existe.");
        }

        // 4. Criar índice de user_name após a tabela existir
        if (!(await indexExists('apostas', 'idx_user_name'))) {
            await promisePool.query(`CREATE INDEX idx_user_name ON apostas (user_name(255))`);
            console.log("Índice 'idx_user_name' criado com sucesso.");
        } else {
            console.log("Índice 'idx_user_name' já existe.");
        }

        // 5. Criar tabela de sessões ativas
        if (!(await tableExists('active_sessions'))) {
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS active_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    session_type VARCHAR(20) NOT NULL,
                    token VARCHAR(500) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
            `);
            console.log("Tabela 'active_sessions' criada com sucesso.");
        } else {
            console.log("Tabela 'active_sessions' já existe.");
        }

        // 6. Criar índices para a tabela de sessões
        if (!(await indexExists('active_sessions', 'idx_user_id'))) {
            await promisePool.query(`CREATE INDEX idx_user_id ON active_sessions (user_id)`);
            console.log("Índice 'idx_user_id' criado com sucesso.");
        } else {
            console.log("Índice 'idx_user_id' já existe.");
        }

        if (!(await indexExists('active_sessions', 'idx_token'))) {
            await promisePool.query(`CREATE INDEX idx_token ON active_sessions (token(255))`);
            console.log("Índice 'idx_token' criado com sucesso.");
        } else {
            console.log("Índice 'idx_token' já existe.");
        }

        console.log("Inicialização do banco de dados concluída com sucesso!");
    } catch (err) {
        console.error("Erro ao inicializar o banco de dados:", err);
    }
};

// Função para contar administradores no sistema
const countAdmins = () => {
    return new Promise((resolve, reject) => {
        const query = `SELECT COUNT(*) AS count FROM users WHERE tipo = 'admin'`;
        pool.query(query, (err, result) => {
            if (err) {
                console.error("Erro ao contar administradores:", err.message);
                reject(err);
            } else {
                resolve(result[0].count);
            }
        });
    });
};

// Limpar sessões expiradas
const cleanupExpiredSessions = () => {
    const cleanupQuery = `DELETE FROM active_sessions WHERE expires_at < NOW()`;
    
    pool.query(cleanupQuery, (err, result) => {
        if (err) {
            console.error("Erro ao limpar sessões expiradas:", err.message);
        } else if (result.affectedRows > 0) {
            console.log(`${result.affectedRows} sessões expiradas foram removidas.`);
        }
    });
};

// Exportar o pool e funções úteis
module.exports = {
    pool,
    promisePool,
    testConnection,
    tableExists,
    indexExists,
    initializeDatabase,
    countAdmins,
    cleanupExpiredSessions
};
