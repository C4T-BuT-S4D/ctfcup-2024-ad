#![feature(let_chains)]

use chrono::Duration;
use eyre::{bail, eyre, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::{
    fs::{self, canonicalize},
    io::{BufRead, BufReader, Write},
    path::Path,
};

const FILE_TTL: Duration = Duration::minutes(30);
const DEFAULT_QUOTA: usize = 10 * 1024 * 1024; // 10MB

#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    id: i32,
    username: String,
    password_hash: String,
    quota_used: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct File {
    id: i32,
    owner_id: i32,
    path: String,
    size: i64,
    created_at: chrono::DateTime<chrono::Utc>,
}

struct App {
    db: Pool<Postgres>,
    current_user: Option<User>,
}

impl App {
    async fn new() -> Result<Self> {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@localhost:5432/ark".to_string());

        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .context("Failed to connect to database")?;

        Ok(App {
            db,
            current_user: None,
        })
    }

    async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE username = $1 AND password_hash = $2",
            username,
            password
        )
        .fetch_optional(&self.db)
        .await
        .context("Failed to query user")?;

        match user {
            Some(user) => {
                self.current_user = Some(user);
                println!("Welcome, {}!", username);
                self.list_files()
                    .await
                    .context("Failed to list files after login")?;
            }
            None => println!("Invalid username or password"),
        }

        Ok(())
    }

    async fn register(&mut self, username: &str, password: &str) -> Result<()> {
        sqlx::query!(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
            username,
            password
        )
        .execute(&self.db)
        .await
        .context("Failed to register user")?;

        println!("Registration successful! Please login");
        Ok(())
    }

    async fn save_file(&mut self, path: &str, content: &str) -> Result<()> {
        let user = self
            .current_user
            .as_ref()
            .ok_or_else(|| eyre!("Not logged in"))?;

        if canonicalize(Path::new(path)).is_ok() {
            bail!("File already exists");
        }

        let file_size = content.len() as i64;
        let new_quota = user.quota_used + file_size;

        let mut tx = self
            .db
            .begin()
            .await
            .context("Failed to start transaction")?;

        if new_quota > DEFAULT_QUOTA as i64 {
            while let Some(oldest_file) = sqlx::query_as!(
                File,
                "SELECT * FROM files WHERE owner_id = $1 ORDER BY created_at ASC LIMIT 1",
                user.id
            )
            .fetch_optional(&self.db)
            .await
            .context("Failed to query oldest file")?
            {
                fs::remove_file(&oldest_file.path).context("Failed to remove old file")?;
                sqlx::query!("DELETE FROM files WHERE id = $1", oldest_file.id)
                    .execute(&mut *tx)
                    .await
                    .context("Failed to delete file record")?;

                if user.quota_used - oldest_file.size + file_size <= DEFAULT_QUOTA as i64 {
                    break;
                }
            }
        }

        sqlx::query!(
            "INSERT INTO files (owner_id, path, size) VALUES ($1, $2, $3)",
            user.id,
            path,
            file_size
        )
        .execute(&mut *tx)
        .await
        .context("Failed to insert file record")?;

        sqlx::query!(
            "UPDATE users SET quota_used = quota_used + $1 WHERE id = $2",
            file_size,
            user.id
        )
        .execute(&mut *tx)
        .await
        .context("Failed to update user quota")?;

        // std::fs::File::create(path).context("Failed to create file")?;

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .context("Failed to open file")?;

        f.write_all(content.as_bytes())
            .context("Failed to write file content")?;

        drop(f);

        tx.commit().await.context("Failed to commit transaction")?;

        println!("File saved successfully");
        Ok(())
    }

    async fn copy_file(&mut self, file_id: i32, new_path: &str) -> Result<()> {
        self.current_user
            .as_ref()
            .ok_or_else(|| eyre!("Not logged in"))?;

        if canonicalize(Path::new(new_path))
            .context("Failed to check if target path exists")?
            .exists()
        {
            println!("Target path already exists");
            return Ok(());
        }

        let mut tx = self
            .db
            .begin()
            .await
            .context("Failed to start transaction")?;

        let file = sqlx::query_as!(File, "SELECT * FROM files WHERE id = $1", file_id)
            .fetch_optional(&mut *tx)
            .await
            .context("Failed to query file")?
            .ok_or_else(|| eyre!("File not found"))?;

        sqlx::query!(
            "INSERT INTO files (owner_id, path, size) VALUES ($1, $2, $3)",
            file.owner_id,
            new_path,
            file.size
        )
        .execute(&mut *tx)
        .await
        .context("Failed to insert new file record")?;

        fs::copy(&file.path, new_path).context("Failed to copy file")?;

        tx.commit().await.context("Failed to commit transaction")?;

        println!("File copied successfully");
        Ok(())
    }

    async fn list_files(&self) -> Result<()> {
        if let Some(user) = &self.current_user {
            let files = sqlx::query_as!(File, "SELECT * FROM files WHERE owner_id = $1", user.id)
                .fetch_all(&self.db)
                .await
                .context("Failed to query user files")?;

            println!("Your files:");
            for file in files {
                println!(
                    "ID: {}, Path: {}, Size: {} bytes",
                    file.id, file.path, file.size
                );
            }
        }
        Ok(())
    }

    async fn cleanup_old_files(&self) -> Result<()> {
        let files = sqlx::query_as!(
            File,
            "SELECT * FROM files WHERE created_at < $1",
            chrono::Utc::now() - FILE_TTL
        )
        .fetch_all(&self.db)
        .await?;

        for file in files {
            let mut tx = self.db.begin().await?;
            if let Err(e) = fs::remove_file(&file.path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("Failed to remove file {}: {}", file.path, e);
            }
            sqlx::query!("DELETE FROM files WHERE id = $1", file.id)
                .execute(&mut *tx)
                .await?;

            sqlx::query!(
                "UPDATE users SET quota_used = quota_used - $1 WHERE id = $2",
                file.size,
                file.owner_id
            )
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
        }

        Ok(())
    }

    async fn handle_command(&mut self, line: &str) -> Result<bool> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(true);
        }

        match parts[0] {
            "quit" => return Ok(false),
            "register" if parts.len() == 3 => {
                self.register(parts[1], parts[2]).await?;
            }
            "login" if parts.len() == 3 => {
                self.login(parts[1], parts[2]).await?;
            }
            "save" if parts.len() >= 3 => {
                let content = parts[2..].join(" ");
                self.save_file(parts[1], &content).await?;
            }
            "copy" if parts.len() == 3 => {
                if let Ok(file_id) = parts[1].parse() {
                    self.copy_file(file_id, parts[2]).await?;
                } else {
                    bail!("Invalid file ID");
                }
            }
            "list" => {
                self.list_files().await?;
            }
            _ => {
                bail!("Invalid command");
            }
        }

        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install().context("Failed to install color_eyre")?;

    let mut app = App::new().await.context("Failed to create app")?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());

    // Start cleanup task
    let cleanup_db = app.db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let app = App {
                db: cleanup_db.clone(),
                current_user: None,
            };
            if let Err(e) = app.cleanup_old_files().await {
                eprintln!("Cleanup error: {}", e);
            }
        }
    });

    println!("Welcome to File Storage Service!");
    println!("Commands:");
    println!("register <username> <password>");
    println!("login <username> <password>");
    println!("save <path> <content>");
    println!("copy <file_id> <new_path>");
    println!("list");
    println!("quit");

    let mut line = String::new();
    loop {
        print!("> ");
        stdout.flush().context("Failed to flush stdout")?;
        line.clear();
        reader.read_line(&mut line).context("Failed to read line")?;

        match app.handle_command(&line).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                println!("Error: {}", e);
                eprintln!("Error: {:#}", e); // Pretty print error with context
                continue;
            }
        }
    }

    Ok(())
}
