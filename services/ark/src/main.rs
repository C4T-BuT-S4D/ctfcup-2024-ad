#![feature(let_chains)]

use chrono::Duration;
use env_logger::Env;
use eyre::{bail, eyre, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::{
    fs::{self, canonicalize},
    path::Path,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

const FILE_TTL: Duration = Duration::minutes(30);
const DEFAULT_QUOTA: i32 = 10 * 1024; // 10KB

#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    id: i32,
    username: String,
    password_hash: String,
    quota_used: i32,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct File {
    id: i32,
    owner_id: i32,
    quota_id: i32,
    path: String,
    size: i32,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SuggestedUser {
    username: String,
    created_at: chrono::DateTime<chrono::Utc>,
    file_count: Option<i64>,
    file_size: Option<i64>,
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

    async fn print_menu(&self) {
        println!("Welcome to Ark! You can help save the most important files in the world!");
        println!("Commands:");
        println!("register <username> <password>");
        println!("login <username> <password>");
        println!("save <path> <content>");
        println!("copy <old_path> <new_path>");
        println!("cat <path>");
        println!("list");
        println!("suggest_users");
        println!("list_files <username>");
        println!("quit");
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
        if username.len() < 3 || password.len() < 8 {
            bail!("Username must be at least 3 characters long and password must be at least 8 characters long");
        }

        if username.len() > 255 || password.len() > 255 {
            bail!("Username and password must be less than 255 characters");
        }

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
        if path.len() > 1024 {
            bail!("Path must be less than 1024 characters");
        }

        if content.len() > 1024 {
            bail!("Content must be less than 1KB");
        }

        let user = self
            .current_user
            .as_ref()
            .ok_or_else(|| eyre!("Not logged in"))?;

        if canonicalize(Path::new(path)).is_ok() {
            bail!("File already exists");
        }

        let file_size = content.len() as i32;
        let new_quota = user.quota_used + file_size;

        let mut tx = self
            .db
            .begin()
            .await
            .context("Failed to start transaction")?;

        if new_quota > DEFAULT_QUOTA {
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

                if user.quota_used - oldest_file.size + file_size <= DEFAULT_QUOTA {
                    break;
                }
            }
        }

        sqlx::query!(
            "INSERT INTO files (owner_id, quota_id, path, size) VALUES ($1, $1, $2, $3)",
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

        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await
            .context("Failed to open file")?;

        f.write_all(content.as_bytes())
            .await
            .context("Failed to write file content")?;

        drop(f);

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
            .await
            .context("Failed to set file permissions")?;

        tx.commit().await.context("Failed to commit transaction")?;

        println!("File saved successfully");
        Ok(())
    }

    async fn copy_file(&mut self, old_path: &str, new_path: &str) -> Result<()> {
        let current_user = self
            .current_user
            .as_ref()
            .ok_or_else(|| eyre!("Not logged in"))?;

        if canonicalize(Path::new(new_path)).is_ok() {
            println!("Target path already exists");
            return Ok(());
        }

        let mut tx = self
            .db
            .begin()
            .await
            .context("Failed to start transaction")?;

        let file = sqlx::query_as!(File, "SELECT * FROM files WHERE path = $1", old_path)
            .fetch_optional(&mut *tx)
            .await
            .context("Failed to query file")?
            .ok_or_else(|| eyre!("File not found"))?;

        sqlx::query!(
            "INSERT INTO files (owner_id, quota_id, path, size) VALUES ($1, $2, $3, $4)",
            file.owner_id,
            current_user.id,
            new_path,
            file.size
        )
        .execute(&mut *tx)
        .await
        .context("Failed to insert new file record")?;

        tokio::fs::copy(&file.path, new_path)
            .await
            .context("Failed to copy file")?;

        tokio::fs::set_permissions(new_path, std::fs::Permissions::from_mode(0o400))
            .await
            .context("Failed to set file permissions")?;

        tx.commit().await.context("Failed to commit transaction")?;

        println!("File copied successfully");
        Ok(())
    }

    async fn cat_file(&mut self, path: &str) -> Result<()> {
        let user = self
            .current_user
            .as_ref()
            .ok_or_else(|| eyre!("Not logged in"))?;

        let file = sqlx::query_as!(
            File,
            "SELECT * FROM files WHERE path = $1 AND owner_id = $2",
            path,
            user.id
        )
        .fetch_optional(&self.db)
        .await
        .context("Failed to query file")?
        .ok_or_else(|| eyre!("File not found"))?;

        let mut f = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&file.path)
            .await
            .context("Failed to open file")?;

        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .await
            .context("Failed to read file")?;
        println!(
            "{}",
            String::from_utf8(buf).context("Failed to convert file to string")?
        );
        Ok(())
    }

    async fn list_files(&self) -> Result<()> {
        if let Some(user) = &self.current_user {
            let files = sqlx::query_as!(File, "SELECT * FROM files WHERE quota_id = $1", user.id)
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

    async fn suggest_users(&self) -> Result<()> {
        let users = sqlx::query_as!(
            SuggestedUser,
            "SELECT users.username, users.created_at, COUNT(files.id) AS file_count, SUM(files.size) AS file_size FROM users INNER JOIN files ON users.id = files.owner_id GROUP BY users.id ORDER BY users.created_at DESC LIMIT 50"
        )
        .fetch_all(&self.db)
        .await
        .context("Failed to query users")?;

        println!("Suggested users:");
        for user in users {
            println!(
                "Username: {}, Created At: {}, File Count: {}, Total File Size: {}",
                user.username,
                user.created_at,
                user.file_count.unwrap_or(0),
                user.file_size.unwrap_or(0)
            );
        }
        Ok(())
    }

    async fn list_user_files(&self, username: &str) -> Result<()> {
        let user = sqlx::query_as!(User, "SELECT * FROM users WHERE username = $1", username)
            .fetch_optional(&self.db)
            .await
            .context("Failed to query user")?
            .ok_or_else(|| eyre!("User not found"))?;

        let files = sqlx::query_as!(File, "SELECT * FROM files WHERE quota_id = $1", user.id)
            .fetch_all(&self.db)
            .await
            .context("Failed to query user files")?;

        println!("{}'s files:", username);
        for file in files {
            println!(
                "ID: {}, Path: {}, Size: {} bytes",
                file.id, file.path, file.size
            );
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
                self.copy_file(parts[1], parts[2]).await?;
            }
            "cat" if parts.len() == 2 => {
                self.cat_file(parts[1]).await?;
            }
            "list" => {
                self.list_files().await?;
            }
            "suggest_users" => {
                self.suggest_users().await?;
            }
            "list_files" if parts.len() == 2 => {
                self.list_user_files(parts[1]).await?;
            }
            _ => {
                bail!("Invalid command");
            }
        }

        Ok(true)
    }
}

// Move existing main into a new function
async fn run_app_with_streams(
    mut stdin: impl AsyncReadExt + Unpin,
    mut stdout: impl AsyncWriteExt + Unpin,
) -> Result<()> {
    let mut app = App::new().await.context("Failed to create app")?;

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

    app.print_menu().await;

    let mut buf = String::new();
    let mut read_buf = [0u8; 1024];

    loop {
        stdout
            .write_all(b"> ")
            .await
            .context("Failed to write prompt")?;
        stdout.flush().await.context("Failed to flush stdout")?;

        buf.clear();
        loop {
            match stdin.read(&mut read_buf).await {
                Ok(0) => return Ok(()), // EOF
                Ok(n) => {
                    let chunk =
                        std::str::from_utf8(&read_buf[..n]).context("Invalid UTF-8 in input")?;
                    buf.push_str(chunk);
                    if chunk.contains('\n') {
                        break;
                    }
                }
                Err(e) => bail!("Failed to read input: {}", e),
            }
        }

        match app.handle_command(&buf).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                let error_msg = format!("Error: {}\n", e);
                stdout.write_all(error_msg.as_bytes()).await?;
                continue;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install().context("Failed to install color_eyre")?;
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    if std::env::args().any(|arg| arg == "--child") {
        // Child process - use stdio
        return run_app_with_streams(tokio::io::stdin(), tokio::io::stdout()).await;
    }

    // Set up SIGTERM handler
    let mut sigterm = signal(SignalKind::terminate())?;
    let sigterm_token = CancellationToken::new();

    let sigterm_token_clone = sigterm_token.clone();
    tokio::spawn(async move {
        sigterm.recv().await;
        sigterm_token_clone.cancel();
    });

    // Parent process - listen for TCP connections
    let listener = TcpListener::bind("0.0.0.0:13345")
        .await
        .context("Failed to bind to port 13345")?;

    log::info!("Listening on port 13345");

    let join_handles = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (socket, addr) = accept_result.context("Failed to accept connection")?;
                log::info!(addr:?; "New connection");

                let (mut socket_read, mut socket_write) = socket.into_split();

                let mut child = Command::new(std::env::current_exe().unwrap())
                    .arg("--child")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .context("Failed to spawn child process")?;

                let mut child_read = child.stdout.take().unwrap();
                let mut child_write = child.stdin.take().unwrap();

                let process_finished_token = CancellationToken::new();

                // Spawn a task to monitor the child process
                let sigterm_token_clone = sigterm_token.clone();
                let process_finished_token_clone = process_finished_token.clone();
                let child_monitor = {
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = child.wait() => {
                                log::info!(addr:?; "Child process exited");
                                process_finished_token_clone.cancel();
                            }
                            _ = sigterm_token_clone.cancelled() => {
                                log::info!(addr:?; "Received SIGTERM, shutting down child process");
                                child.kill().await.ok();
                            }
                        }
                    })
                };

                // Child read always finishes with the process, no need to use cancellation token here.
                let child_read_task = tokio::spawn(async move {
                    let result = tokio::io::copy(&mut child_read, &mut socket_write).await;
                    if let Err(e) = result {
                        log::warn!(addr:?; "Error in child read task: {e}");
                    }
                    drop(child_read);
                    drop(socket_write);
                    log::debug!(addr:?; "Child read task finished");
                });

                // Child write task should finish when the process exits or when the client disconnects.
                let child_write_task = tokio::spawn(async move {
                    tokio::select! {
                        _ = process_finished_token.cancelled() => {
                            log::info!(addr:?; "Received SIGTERM, shutting down child write task");
                        }
                        result = tokio::io::copy(&mut socket_read, &mut child_write) => {
                            if let Err(e) = result {
                                log::error!(addr:?; "Error in child write task: {e}");
                            }
                        }
                    }
                    drop(socket_read);
                    drop(child_write);
                    log::debug!(addr:?; "Child write task finished");
                });

                let join_handles_clone = join_handles.clone();
                let handle = tokio::spawn(async move {
                    let (read_result, write_result, _) = tokio::join!(
                        child_read_task,
                        child_write_task,
                        child_monitor
                    );

                    if let Err(e) = read_result {
                        log::error!(addr:?; "Child read task joined with error: {e}");
                    }
                    if let Err(e) = write_result {
                        log::error!(addr:?; "Child write task joined with error: {e}");
                    }

                    log::info!(addr:?; "Client disconnected");

                    join_handles_clone.lock().unwrap().remove(&addr);
                });
                join_handles.lock().unwrap().insert(addr, handle);
            }
            _ = sigterm_token.cancelled() => {
                log::info!("Received SIGTERM, shutting down...");
                let handles = std::mem::take(&mut *(join_handles.lock().unwrap()));
                for (_, handle) in handles {
                    handle.await.unwrap();
                }
                break;
            }
        }
    }

    Ok(())
}
