use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spacetimedb::{ReducerContext, ScheduleAt, SpacetimeType, Table, TimeDuration, Timestamp};
use std::collections::HashMap;
use std::hash::Hash;

// Hashcash 阈值常量
const HASHCASH_THRESHOLDS: (u32, u32, u32) = (18, 10, 5); // (GOOD, WEAK, TRIVIAL)

// 邮件分类关键词
const KEYWORDS: &[(&str, EmailClassification)] = &[
    // Promotions
    ("sale", EmailClassification::Promotions),
    ("discount", EmailClassification::Promotions),
    ("buy now", EmailClassification::Promotions),
    ("limited time", EmailClassification::Promotions),
    ("offer", EmailClassification::Promotions),
    // Social
    ("friend request", EmailClassification::Social),
    ("mentioned you", EmailClassification::Social),
    ("liked your post", EmailClassification::Social),
    ("new follower", EmailClassification::Social),
    // Forums
    ("digest", EmailClassification::Forums),
    ("thread", EmailClassification::Forums),
    ("post reply", EmailClassification::Forums),
    ("new topic", EmailClassification::Forums),
    // Updates
    ("receipt", EmailClassification::Updates),
    ("order confirmation", EmailClassification::Updates),
    ("invoice", EmailClassification::Updates),
    ("payment received", EmailClassification::Updates),
];

// 邮件状态枚举
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, SpacetimeType)]
pub enum EmailStatus {
    Pending,
    Sending,
    Sent,
    Failed,
    Rejected,
    Scheduled,
    Spam,
}

// 邮件分类枚举
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, SpacetimeType)]
pub enum EmailClassification {
    Primary,
    Promotions,
    Social,
    Forums,
    Updates,
}

// 用户表
#[spacetimedb::table(name = users)]
// #[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub domain: String,
    pub password_hash: String,
    pub iq: Option<i32>,
    pub is_banned: bool,
    pub is_admin: bool,
    pub deleted_at: Option<Timestamp>, // Unix timestamp
    pub created_at: Timestamp,         // Unix timestamp
}

// 用户会话表
#[spacetimedb::table(name = user_secret_codes)]
// #[derive(Serialize, Deserialize, Clone)]
pub struct UserSecretCode {
    pub code: String,
    pub user_id: i32,
    pub created_at: Timestamp, // Unix timestamp
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

// 邮件表
#[spacetimedb::table(name = emails)]
// #[derive(Serialize, Deserialize, Clone)]
#[derive(Clone)]
pub struct Email {
    #[primary_key]
    #[auto_inc]
    pub id: i32,
    pub from_address: String,
    pub from_domain: String,
    pub to_address: String,
    pub to_domain: String,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub content_type: String,
    pub html_body: Option<String>,
    pub sent_at: Timestamp, // Unix timestamp
    pub error_message: Option<String>,
    pub status: EmailStatus,
    pub snooze_until: Option<Timestamp>, // Unix timestamp
    pub read_at: Option<Timestamp>,      // Unix timestamp
    pub scheduled_at: Option<Timestamp>, // Unix timestamp
    pub classification: EmailClassification,
    pub reply_to_id: Option<i32>,
    pub thread_id: Option<i32>,
    pub expires_at: Option<Timestamp>, // Unix timestamp
    pub self_destruct: bool,
}

// 附件表
#[spacetimedb::table(name = attachments)]
// #[derive(Serialize, Deserialize, Clone)]
pub struct Attachment {
    pub user_id: Option<i32>,
    pub key: String,
    pub filename: String,
    pub size: i32,
    pub file_type: String,
    pub created_at: Timestamp,         // Unix timestamp
    pub expires_at: Option<Timestamp>, // Unix timestamp
    pub email_id: Option<i32>,
    pub status: String,
}

// 用户设置表
#[spacetimedb::table(name = user_settings)]
// #[derive(Serialize, Deserialize, Clone)]
pub struct UserSettings {
    pub user_id: i32,
    pub notifications_enabled: bool,
    pub created_at: Timestamp, // Unix timestamp
    pub updated_at: Timestamp, // Unix timestamp
}

// Hashcash 验证函数
fn verify_hashcash(ctx: &ReducerContext, header: &str, resource: &str) -> Result<u32, String> {
    let parts: Vec<&str> = header.split(':').collect();
    if parts.len() != 7 {
        return Err("Invalid hashcash format".to_string());
    }

    let (version, bits, date, header_resource, _ext, _rand, _counter) = (
        parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6],
    );

    if version != "1" {
        return Err("Unsupported hashcash version".to_string());
    }

    if header_resource != resource {
        return Err("Resource mismatch".to_string());
    }

    let bits = bits
        .parse::<u32>()
        .map_err(|_| "Invalid bits value".to_string())?;

    // 验证日期
    let header_date = parse_hashcash_date(date)?;
    let now = ctx.timestamp;
    let one_hour = TimeDuration::from_micros(3600 * 1_000_000);
    if now > header_date + one_hour {
        return Err("Hashcash stamp expired".to_string());
    }

    // 验证工作量证明
    let hash = Sha256::digest(header.as_bytes());
    let leading_zeros = count_leading_zeros(&hash);

    if leading_zeros < bits {
        return Err("Insufficient proof of work".to_string());
    }

    Ok(bits)
}

// 解析 Hashcash 日期
fn parse_hashcash_date(date_str: &str) -> Result<Timestamp, String> {
    if date_str.len() != 10 {
        return Err("Invalid date format".to_string());
    }

    let year = 2000
        + date_str[0..2]
            .parse::<i32>()
            .map_err(|_| "Invalid year".to_string())?;
    let month = date_str[2..4]
        .parse::<u32>()
        .map_err(|_| "Invalid month".to_string())?;
    let day = date_str[4..6]
        .parse::<u32>()
        .map_err(|_| "Invalid day".to_string())?;
    let hour = date_str[6..8]
        .parse::<u32>()
        .map_err(|_| "Invalid hour".to_string())?;
    let minute = date_str[8..10]
        .parse::<u32>()
        .map_err(|_| "Invalid minute".to_string())?;

    // Convert to microseconds since Unix epoch
    let micros = (year as i64 * 365 * 24 * 60 * 60 * 1_000_000)
        + ((month - 1) as i64 * 30 * 24 * 60 * 60 * 1_000_000)
        + ((day - 1) as i64 * 24 * 60 * 60 * 1_000_000)
        + (hour as i64 * 60 * 60 * 1_000_000)
        + (minute as i64 * 60 * 1_000_000);
    Ok(Timestamp::from_micros_since_unix_epoch(micros))
}

// 计算前导零位数
fn count_leading_zeros(hash: &[u8]) -> u32 {
    let mut zeros = 0;
    for &byte in hash {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

// 邮件分类函数
fn classify_email(subject: &str, body: &str, html_body: Option<&str>) -> EmailClassification {
    let text = format!("{} {}", subject, body).to_lowercase();
    let mut scores = HashMap::new();

    // 基于关键词的评分
    for (keyword, classification) in KEYWORDS {
        if text.contains(keyword) {
            *scores.entry(classification).or_insert(0) += 1;
        }
    }

    // HTML 结构评分（用于识别促销邮件）
    if let Some(html) = html_body {
        let html_score = html.matches("<img").count()
            + html.matches("<table").count()
            + html.matches("<style").count();
        *scores.entry(&EmailClassification::Promotions).or_insert(0) += html_score.min(5);
    }

    // 返回得分最高的分类
    scores
        .into_iter()
        .max_by_key(|&(_, score)| score)
        .map(|(classification, _)| *classification)
        .unwrap_or(EmailClassification::Primary)
}

// 词汇检查函数
fn check_vocabulary(text: &str, iq: Option<i32>) -> Result<(), String> {
    let max_word_length = match iq {
        Some(iq) if iq < 90 => 3,
        Some(iq) if iq < 100 => 4,
        Some(iq) if iq < 120 => 5,
        Some(iq) if iq < 130 => 6,
        Some(iq) if iq < 140 => 7,
        _ => return Ok(()), // 无限制
    };

    for word in text.split_whitespace() {
        let cleaned_word = word.trim_matches(|c: char| !c.is_alphanumeric());
        if cleaned_word.len() > max_word_length {
            return Err(format!(
                "Word '{}' exceeds maximum length of {} characters for your IQ level",
                cleaned_word, max_word_length
            ));
        }
    }

    Ok(())
}

#[spacetimedb::table(name = email_schedule, scheduled(process_pending_emails))]
pub struct EmailSchedule {
    #[primary_key]
    #[auto_inc]
    scheduled_id: u64,
    scheduled_at: ScheduleAt,
}

#[spacetimedb::table(name = scheduled_emails, scheduled(process_scheduled_emails))]
pub struct ScheduledEmails {
    #[primary_key]
    #[auto_inc]
    scheduled_id: u64,
    scheduled_at: ScheduleAt,
}

#[spacetimedb::table(name = cleanup_schedule, scheduled(cleanup_expired_emails))]
pub struct CleanupSchedule {
    #[primary_key]
    #[auto_inc]
    scheduled_id: u64,
    scheduled_at: ScheduleAt,
}

// 初始化函数
#[spacetimedb::reducer(init)]
pub fn init(ctx: &ReducerContext) {
    log::info!("SHARP server initialized");

    // 设置定时任务
    let interval = TimeDuration::from_micros(60_000_000);

    ctx.db.email_schedule().insert(EmailSchedule {
        scheduled_id: 0,
        scheduled_at: ScheduleAt::Interval(interval),
    });

    ctx.db.scheduled_emails().insert(ScheduledEmails {
        scheduled_id: 0,
        scheduled_at: ScheduleAt::Interval(interval),
    });

    ctx.db.cleanup_schedule().insert(CleanupSchedule {
        scheduled_id: 0,
        scheduled_at: ScheduleAt::Interval(TimeDuration::from_micros(300_000_000)),
    });
}

// 客户端连接处理
#[spacetimedb::reducer(client_connected)]
pub fn client_connected(_ctx: &ReducerContext) {
    log::info!("New client connected");
}

// 客户端断开连接处理
#[spacetimedb::reducer(client_disconnected)]
pub fn client_disconnected(_ctx: &ReducerContext) {
    log::info!("Client disconnected");
}

// 用户注册
#[spacetimedb::reducer]
pub fn register(ctx: &ReducerContext, username: String, domain: String, password_hash: String) {
    let user = User {
        username,
        domain,
        password_hash,
        iq: None,
        is_banned: false,
        is_admin: false,
        deleted_at: None,
        created_at: ctx.timestamp,
    };

    ctx.db.users().insert(user);
    log::info!("New user registered");
}

// 创建会话
#[spacetimedb::reducer]
pub fn create_session(
    ctx: &ReducerContext,
    user_id: i32,
    code: String,
    ip: Option<String>,
    user_agent: Option<String>,
) {
    let session = UserSecretCode {
        code,
        user_id,
        created_at: ctx.timestamp,
        ip,
        user_agent,
    };

    ctx.db.user_secret_codes().insert(session);
    log::info!("New session created for user {}", user_id);
}

// 发送邮件
#[spacetimedb::reducer]
#[allow(clippy::too_many_arguments)]
pub fn send_email(
    ctx: &ReducerContext,
    from_address: String,
    from_domain: String,
    to_address: String,
    to_domain: String,
    subject: Option<String>,
    body: Option<String>,
    content_type: String,
    html_body: Option<String>,
    hashcash: String,
    scheduled_at: Option<Timestamp>,
    reply_to_id: Option<i32>,
    thread_id: Option<i32>,
    expires_at: Option<Timestamp>,
    self_destruct: bool,
) -> Result<(), String> {
    // 验证 Hashcash
    let bits = verify_hashcash(ctx, &hashcash, &to_address)?;

    // 确定邮件状态
    let status = if bits >= HASHCASH_THRESHOLDS.0 {
        EmailStatus::Pending
    } else if bits >= HASHCASH_THRESHOLDS.1 {
        EmailStatus::Spam
    } else {
        return Err(format!(
            "Insufficient proof of work. Please retry with at least {} bits.",
            HASHCASH_THRESHOLDS.2
        ));
    };

    // 验证发送者
    let sender = ctx
        .db
        .users()
        .iter()
        .find(|u| u.username == from_address && u.domain == from_domain)
        .ok_or_else(|| "Sender not found".to_string())?;

    // 检查词汇（如果是纯文本邮件）
    if content_type == "text/plain" {
        if let Some(body) = &body {
            check_vocabulary(body, sender.iq)?;
        }
    }

    // 分类邮件
    let classification = classify_email(
        subject.as_deref().unwrap_or(""),
        body.as_deref().unwrap_or(""),
        html_body.as_deref(),
    );

    // 创建邮件记录
    let email = Email {
        id: 0,
        from_address,
        from_domain,
        to_address,
        to_domain,
        subject,
        body,
        content_type,
        html_body,
        sent_at: ctx.timestamp,
        error_message: None,
        status,
        snooze_until: None,
        read_at: None,
        scheduled_at,
        classification,
        reply_to_id,
        thread_id,
        expires_at,
        self_destruct,
    };

    ctx.db.emails().insert(email);
    Ok(())
}

// 邮件投递状态更新
#[spacetimedb::reducer]
pub fn update_email_status(
    ctx: &ReducerContext,
    email_id: i32,
    new_status: EmailStatus,
    error_message: Option<String>,
) -> Result<(), String> {
    let email = ctx
        .db
        .emails()
        .iter()
        .find(|e| e.id == email_id)
        .ok_or_else(|| "Email not found".to_string())?;

    let mut updated_email = email.clone();
    updated_email.status = new_status;
    updated_email.error_message = error_message;

    if new_status == EmailStatus::Sent {
        updated_email.sent_at = ctx.timestamp;
    }

    ctx.db.emails().id().update(updated_email);
    Ok(())
}

// 处理待发送的邮件
#[spacetimedb::reducer]
pub fn process_pending_emails(ctx: &ReducerContext, _schedule: EmailSchedule) {
    log::info!("Start process_pending_emails");

    let pending_emails = ctx
        .db
        .emails()
        .iter()
        .filter(|e| e.status == EmailStatus::Pending)
        .collect::<Vec<_>>();

    for email in pending_emails {
        // 更新状态为发送中
        let mut updated_email = email.clone();
        updated_email.status = EmailStatus::Sending;
        ctx.db.emails().insert(updated_email);

        // 如果是本地邮件，直接标记为已发送
        let is_local_user = ctx
            .db
            .users()
            .iter()
            .any(|u| u.username == email.to_address && u.domain == email.to_domain);

        if is_local_user {
            let mut sent_email = email.clone();
            sent_email.status = EmailStatus::Sent;
            sent_email.sent_at = ctx.timestamp;
            ctx.db.emails().insert(sent_email);
            continue;
        }

        // TODO: 实现远程邮件投递
        // 这里需要实现 SHARP 协议的远程投递逻辑
    }
}

// 处理定时发送的邮件
#[spacetimedb::reducer]
pub fn process_scheduled_emails(ctx: &ReducerContext, _schedule: ScheduledEmails) {
    log::info!("Start process_scheduled_emails");

    let now = ctx.timestamp;
    let scheduled_emails = ctx
        .db
        .emails()
        .iter()
        .filter(|e| e.status == EmailStatus::Scheduled && e.scheduled_at.unwrap_or(now) <= now)
        .collect::<Vec<_>>();

    for email in scheduled_emails {
        let mut updated_email = email.clone();
        updated_email.status = EmailStatus::Pending;
        ctx.db.emails().insert(updated_email);
    }
}

// 清理过期的邮件
#[spacetimedb::reducer]
pub fn cleanup_expired_emails(ctx: &ReducerContext, _schedule: CleanupSchedule) {
    log::info!("Start cleanup_expired_emails");

    let now = ctx.timestamp;
    let expired_emails = ctx
        .db
        .emails()
        .iter()
        .filter(|e| e.expires_at.unwrap_or(now) <= now)
        .collect::<Vec<_>>();

    for email in expired_emails {
        // 删除相关的附件
        let attachments = ctx
            .db
            .attachments()
            .iter()
            .filter(|a| a.email_id == email.reply_to_id)
            .collect::<Vec<_>>();

        for attachment in attachments {
            ctx.db.attachments().delete(attachment);
        }

        // 删除邮件
        ctx.db.emails().delete(email);
    }
}
