mod tables;
pub use tables::*;

mod reducers;
pub use reducers::*;

mod utils;
pub use utils::*;

use spacetimedb::{ReducerContext, ScheduleAt, Table, TimeDuration, Timestamp};

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

// 处理待发送的邮件
#[spacetimedb::reducer]
pub fn process_pending_emails(ctx: &ReducerContext, _schedule: EmailSchedule) {
    log::info!("Processing pending emails");

    let now = ctx.timestamp;
    let thirty_seconds = TimeDuration::from_micros(30_000_000);

    // 处理超时的待发送邮件
    let pending_emails = ctx
        .db
        .emails()
        .iter()
        .filter(|e| e.status == EmailStatus::Pending && e.sent_at + thirty_seconds < now)
        .collect::<Vec<_>>();

    for email in pending_emails {
        let mut updated_email = email.clone();
        updated_email.status = EmailStatus::Failed;
        updated_email.error_message = Some("Timed out while pending".to_string());
        ctx.db.emails().id().update(updated_email);
    }
}

// 处理定时发送的邮件
#[spacetimedb::reducer]
pub fn process_scheduled_emails(ctx: &ReducerContext, _schedule: ScheduledEmails) {
    log::info!("Processing scheduled emails");

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
        ctx.db.emails().id().update(updated_email);
    }
}

// 清理过期的邮件
#[spacetimedb::reducer]
pub fn cleanup_expired_emails(ctx: &ReducerContext, _schedule: CleanupSchedule) {
    log::info!("Cleaning up expired emails");

    let now = ctx.timestamp;

    // 查找所有过期的邮件
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
            .filter(|a| a.email_id == Some(email.id))
            .collect::<Vec<_>>();

        for attachment in attachments {
            ctx.db.attachments().id().delete(attachment.id);
        }

        // 删除邮件
        ctx.db.emails().id().delete(email.id);
    }
}

// 初始化函数
#[spacetimedb::reducer(init)]
pub fn init(ctx: &ReducerContext) {
    log::info!("Initializing SHARP server");

    // 设置定时任务
    let one_minute = TimeDuration::from_micros(60_000_000);
    let five_minutes = TimeDuration::from_micros(300_000_000);

    // 处理待发送邮件的定时任务
    ctx.db.email_schedule().insert(EmailSchedule {
        scheduled_id: 0,
        scheduled_at: ScheduleAt::Interval(one_minute),
    });

    // 处理定时发送邮件的定时任务
    ctx.db.scheduled_emails().insert(ScheduledEmails {
        scheduled_id: 0,
        scheduled_at: ScheduleAt::Interval(one_minute),
    });

    // 清理过期邮件的定时任务
    ctx.db.cleanup_schedule().insert(CleanupSchedule {
        scheduled_id: 0,
        scheduled_at: ScheduleAt::Interval(five_minutes),
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
        id: 0,
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
