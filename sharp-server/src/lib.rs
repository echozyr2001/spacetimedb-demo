mod tables;
pub use tables::*;

mod reducers;
pub use reducers::*;

mod utils;
pub use utils::*;

use spacetimedb::{ReducerContext, ScheduleAt, Table, TimeDuration};

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
