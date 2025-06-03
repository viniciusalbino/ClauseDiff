import pg from 'pg';
import 'dotenv/config';

const { Client } = pg;

const client = new Client({
  connectionString: process.env.SUPABASE_DATABASE_URL
});

client.connect()
  .then(() => {
    console.log('Conexão bem-sucedida com o banco de dados!');
    return client.end();
  })
  .catch(err => {
    console.error('VARIABLE:', process.env.SUPABASE_DATABASE_URL);
    console.error('Erro ao conectar:', err);
  });