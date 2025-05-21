#![allow(unused_variables)]

use crate::tables::*;
use crate::{
    check_vocabulary, classify_email, parse_sharp_address, parse_sharp_message, verify_hashcash,
    EmailClassification, EmailStatus, SharpMessageType, PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};
use spacetimedb::{ReducerContext, Table, Timestamp};

// Hashcash 阈值常量
const HASHCASH_THRESHOLDS: (u32, u32, u32) = (18, 10, 5); // (GOOD, WEAK, TRIVIAL)

// Email Star 相关操作
#[spacetimedb::reducer]
pub fn create_email_star(ctx: &ReducerContext, email_id: i32, user_id: i32) -> Result<(), String> {
    // 检查 email 是否存在
    let email = ctx
        .db
        .emails()
        .id()
        .find(email_id)
        .ok_or_else(|| "Email not found".to_string())?;

    // 检查 user 是否存在
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 检查是否已经存在相同的 star
    let existing_star = ctx
        .db
        .email_stars()
        .iter()
        .find(|star| star.email_id == email_id && star.user_id == user_id);

    if existing_star.is_some() {
        return Err("Email already starred by this user".to_string());
    }

    // 创建新的 star
    ctx.db.email_stars().insert(EmailStar {
        id: 0, // 自增
        email_id,
        user_id,
        starred_at: Timestamp::now(),
    });

    Ok(())
}

#[spacetimedb::reducer]
pub fn remove_email_star(ctx: &ReducerContext, email_id: i32, user_id: i32) -> Result<(), String> {
    // 查找对应的 star
    let star = ctx
        .db
        .email_stars()
        .iter()
        .find(|star| star.email_id == email_id && star.user_id == user_id)
        .ok_or_else(|| "Email star not found".to_string())?;

    // 删除 star
    ctx.db.email_stars().id().delete(star.id);

    Ok(())
}

// Email Draft 相关操作
#[spacetimedb::reducer]
pub fn create_email_draft(
    ctx: &ReducerContext,
    user_id: i32,
    to_address: Option<String>,
    subject: Option<String>,
    body: Option<String>,
    content_type: String,
    html_body: Option<String>,
) -> Result<(), String> {
    // 检查 user 是否存在
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 创建新的草稿
    ctx.db.email_drafts().insert(EmailDraft {
        id: 0, // 自增
        user_id,
        to_address,
        subject,
        body,
        content_type,
        html_body,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    });

    Ok(())
}

// Contact 相关操作
#[spacetimedb::reducer]
pub fn create_contact(
    ctx: &ReducerContext,
    user_id: i32,
    full_name: String,
    email_address: String,
    tag: Option<String>,
) -> Result<(), String> {
    // 检查 user 是否存在
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 检查是否已存在相同的联系人
    let existing_contact = ctx
        .db
        .contacts()
        .iter()
        .find(|contact| contact.user_id == user_id && contact.email_address == email_address);

    if existing_contact.is_some() {
        return Err("Contact already exists".to_string());
    }

    // 创建新的联系人
    ctx.db.contacts().insert(Contact {
        id: 0, // 自增
        user_id,
        full_name,
        email_address,
        tag,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    });

    Ok(())
}

// 用户认证相关操作
#[spacetimedb::reducer]
pub fn login(
    ctx: &ReducerContext,
    username: String,
    domain: String,
    password_hash: String,
) -> Result<(), String> {
    // 查找用户
    let user = ctx
        .db
        .users()
        .iter()
        .find(|u| u.username == username && u.domain == domain)
        .ok_or_else(|| "User not found".to_string())?;

    // 验证密码
    if user.password_hash != password_hash {
        return Err("Invalid password".to_string());
    }

    // 检查用户是否被封禁
    if user.is_banned {
        return Err("Account is banned".to_string());
    }

    // 生成会话代码
    let session_code = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}{}{}",
                username,
                domain,
                ctx.timestamp.to_micros_since_unix_epoch()
            )
            .as_bytes()
        )
    );

    // 创建会话
    ctx.db.user_secret_codes().insert(UserSecretCode {
        code: session_code.clone(),
        user_id: user.id,
        created_at: ctx.timestamp,
        ip: None,
        user_agent: None,
    });

    Ok(())
}

// 附件相关操作
#[spacetimedb::reducer]
pub fn create_attachment(
    ctx: &ReducerContext,
    user_id: i32,
    key: String,
    filename: String,
    size: i32,
    file_type: String,
) -> Result<(), String> {
    // 检查用户是否存在
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 检查存储限制
    let storage_limit = ctx
        .db
        .user_storage_limits()
        .user_id()
        .find(user_id)
        .map(|limit| limit.storage_limit)
        .unwrap_or(1_073_741_824); // 默认 1GB

    // 计算当前存储使用量
    let current_usage: i64 = ctx
        .db
        .attachments()
        .iter()
        .filter(|a| a.user_id == Some(user_id) && a.status != "failed")
        .map(|a| a.size as i64)
        .sum();

    // 检查是否超出限制
    if current_usage + size as i64 > storage_limit {
        return Err("Storage limit exceeded".to_string());
    }

    // 创建附件记录
    ctx.db.attachments().insert(Attachment {
        id: 0,
        user_id: Some(user_id),
        key,
        filename,
        size,
        file_type,
        created_at: ctx.timestamp,
        expires_at: None,
        email_id: None,
        status: "pending".to_string(),
    });

    Ok(())
}

#[spacetimedb::reducer]
pub fn update_attachment_status(
    ctx: &ReducerContext,
    attachment_id: i32,
    new_status: String,
    email_id: Option<i32>,
) -> Result<(), String> {
    let attachment = ctx
        .db
        .attachments()
        .id()
        .find(attachment_id)
        .ok_or_else(|| "Attachment not found".to_string())?;

    let mut updated_attachment = attachment.clone();
    updated_attachment.status = new_status;
    updated_attachment.email_id = email_id;

    ctx.db.attachments().id().update(updated_attachment);
    Ok(())
}

// 邮件分类相关操作
#[spacetimedb::reducer]
pub fn update_email_classification(
    ctx: &ReducerContext,
    email_id: i32,
    new_classification: EmailClassification,
) -> Result<(), String> {
    let email = ctx
        .db
        .emails()
        .id()
        .find(email_id)
        .ok_or_else(|| "Email not found".to_string())?;

    let mut updated_email = email.clone();
    updated_email.classification = new_classification;

    ctx.db.emails().id().update(updated_email);
    Ok(())
}

// 邮件状态更新
#[spacetimedb::reducer]
pub fn mark_email_as_read(ctx: &ReducerContext, email_id: i32, user_id: i32) -> Result<(), String> {
    let email = ctx
        .db
        .emails()
        .id()
        .find(email_id)
        .ok_or_else(|| "Email not found".to_string())?;

    // 验证用户是否有权限读取该邮件
    if email.to_address
        != format!(
            "{}#{}",
            ctx.db
                .users()
                .id()
                .find(user_id)
                .ok_or_else(|| "User not found".to_string())?
                .username,
            email.to_domain
        )
    {
        return Err("Unauthorized".to_string());
    }

    let mut updated_email = email.clone();
    updated_email.read_at = Some(ctx.timestamp);

    ctx.db.emails().id().update(updated_email);
    Ok(())
}

// 邮件草稿相关操作
#[spacetimedb::reducer]
pub fn update_email_draft(
    ctx: &ReducerContext,
    draft_id: i32,
    to_address: Option<String>,
    subject: Option<String>,
    body: Option<String>,
    content_type: String,
    html_body: Option<String>,
) -> Result<(), String> {
    let draft = ctx
        .db
        .email_drafts()
        .id()
        .find(draft_id)
        .ok_or_else(|| "Draft not found".to_string())?;

    let mut updated_draft = draft.clone();
    updated_draft.to_address = to_address;
    updated_draft.subject = subject;
    updated_draft.body = body;
    updated_draft.content_type = content_type;
    updated_draft.html_body = html_body;
    updated_draft.updated_at = ctx.timestamp;

    ctx.db.email_drafts().id().update(updated_draft);
    Ok(())
}

// User Storage Limit 相关操作
#[spacetimedb::reducer]
pub fn create_user_storage_limit(
    ctx: &ReducerContext,
    user_id: i32,
    storage_limit: i64,
) -> Result<(), String> {
    // 检查 user 是否存在
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 检查是否已存在存储限制
    let existing_limit = ctx.db.user_storage_limits().user_id().find(user_id);

    if existing_limit.is_some() {
        return Err("Storage limit already exists for this user".to_string());
    }

    // 创建新的存储限制
    ctx.db.user_storage_limits().insert(UserStorageLimit {
        user_id,
        storage_limit,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    });

    Ok(())
}

// User Settings 相关操作
#[spacetimedb::reducer]
pub fn create_user_settings(
    ctx: &ReducerContext,
    user_id: i32,
    notifications_enabled: bool,
) -> Result<(), String> {
    // 检查 user 是否存在
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 检查是否已存在设置
    let existing_settings = ctx.db.user_settings().user_id().find(user_id);

    if existing_settings.is_some() {
        return Err("Settings already exist for this user".to_string());
    }

    // 创建新的用户设置
    ctx.db.user_settings().insert(UserSettings {
        user_id,
        notifications_enabled,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    });

    Ok(())
}

// 计算用户存储空间使用量
#[spacetimedb::reducer]
pub fn calculate_user_storage(ctx: &ReducerContext, user_id: i32) -> Result<(), String> {
    // 检查用户是否存在
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 构建用户邮箱地址
    let user_email = format!("{}#{}", user.username, user.domain);

    // 计算存储空间
    let total_size: i64 = ctx
        .db
        .attachments()
        .iter()
        .filter(|attachment| {
            // 只计算非失败状态的附件
            attachment.status != "failed"
                && (
                    // 附件直接属于用户
                    attachment.user_id == Some(user_id) ||
                // 或附件属于用户的邮件
                attachment.email_id.is_some_and( |email_id| {
                    ctx.db.emails().id().find(email_id).is_some_and(|email| {
                        email.from_address == user_email || email.to_address == user_email
                    })
                })
                )
        })
        .map(|attachment| attachment.size as i64)
        .sum();

    // 更新用户的存储限制记录
    if let Some(mut limit) = ctx.db.user_storage_limits().user_id().find(user_id) {
        // 更新现有记录
        limit.storage_limit = total_size;
        limit.updated_at = Timestamp::now();
        ctx.db.user_storage_limits().user_id().update(limit);
    } else {
        // 创建新记录
        ctx.db.user_storage_limits().insert(UserStorageLimit {
            user_id,
            storage_limit: total_size,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        });
    }

    Ok(())
}

// 用户设置相关操作
#[spacetimedb::reducer]
pub fn update_user_settings(
    ctx: &ReducerContext,
    user_id: i32,
    notifications_enabled: bool,
) -> Result<(), String> {
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    if let Some(mut settings) = ctx.db.user_settings().user_id().find(user_id) {
        settings.notifications_enabled = notifications_enabled;
        settings.updated_at = ctx.timestamp;
        ctx.db.user_settings().user_id().update(settings);
    } else {
        ctx.db.user_settings().insert(UserSettings {
            user_id,
            notifications_enabled,
            created_at: ctx.timestamp,
            updated_at: ctx.timestamp,
        });
    }

    Ok(())
}

// 用户存储限制相关操作
#[spacetimedb::reducer]
pub fn update_user_storage_limit(
    ctx: &ReducerContext,
    user_id: i32,
    storage_limit: i64,
) -> Result<(), String> {
    let user = ctx
        .db
        .users()
        .id()
        .find(user_id)
        .ok_or_else(|| "User not found".to_string())?;

    if let Some(mut limit) = ctx.db.user_storage_limits().user_id().find(user_id) {
        limit.storage_limit = storage_limit;
        limit.updated_at = ctx.timestamp;
        ctx.db.user_storage_limits().user_id().update(limit);
    } else {
        ctx.db.user_storage_limits().insert(UserStorageLimit {
            user_id,
            storage_limit,
            created_at: ctx.timestamp,
            updated_at: ctx.timestamp,
        });
    }

    Ok(())
}

// 邮件草稿相关操作
#[spacetimedb::reducer]
pub fn delete_email_draft(ctx: &ReducerContext, draft_id: i32, user_id: i32) -> Result<(), String> {
    let draft = ctx
        .db
        .email_drafts()
        .id()
        .find(draft_id)
        .ok_or_else(|| "Draft not found".to_string())?;

    // 验证用户是否有权限删除该草稿
    if draft.user_id != user_id {
        return Err("Unauthorized".to_string());
    }

    ctx.db.email_drafts().id().delete(draft_id);
    Ok(())
}

// 联系人相关操作
#[spacetimedb::reducer]
pub fn update_contact(
    ctx: &ReducerContext,
    contact_id: i32,
    user_id: i32,
    full_name: String,
    email_address: String,
    tag: Option<String>,
) -> Result<(), String> {
    let contact = ctx
        .db
        .contacts()
        .id()
        .find(contact_id)
        .ok_or_else(|| "Contact not found".to_string())?;

    // 验证用户是否有权限更新该联系人
    if contact.user_id != user_id {
        return Err("Unauthorized".to_string());
    }

    let mut updated_contact = contact.clone();
    updated_contact.full_name = full_name;
    updated_contact.email_address = email_address;
    updated_contact.tag = tag;
    updated_contact.updated_at = ctx.timestamp;

    ctx.db.contacts().id().update(updated_contact);
    Ok(())
}

#[spacetimedb::reducer]
pub fn delete_contact(ctx: &ReducerContext, contact_id: i32, user_id: i32) -> Result<(), String> {
    let contact = ctx
        .db
        .contacts()
        .id()
        .find(contact_id)
        .ok_or_else(|| "Contact not found".to_string())?;

    // 验证用户是否有权限删除该联系人
    if contact.user_id != user_id {
        return Err("Unauthorized".to_string());
    }

    ctx.db.contacts().id().delete(contact_id);
    Ok(())
}

// 用户管理相关操作
#[spacetimedb::reducer]
pub fn ban_user(ctx: &ReducerContext, admin_id: i32, target_user_id: i32) -> Result<(), String> {
    // 验证管理员权限
    let admin = ctx
        .db
        .users()
        .id()
        .find(admin_id)
        .ok_or_else(|| "Admin not found".to_string())?;

    if !admin.is_admin {
        return Err("Unauthorized".to_string());
    }

    // 查找目标用户
    let mut target_user = ctx
        .db
        .users()
        .id()
        .find(target_user_id)
        .ok_or_else(|| "Target user not found".to_string())?;

    // 更新用户状态
    target_user.is_banned = true;
    ctx.db.users().id().update(target_user);

    Ok(())
}

#[spacetimedb::reducer]
pub fn unban_user(ctx: &ReducerContext, admin_id: i32, target_user_id: i32) -> Result<(), String> {
    // 验证管理员权限
    let admin = ctx
        .db
        .users()
        .id()
        .find(admin_id)
        .ok_or_else(|| "Admin not found".to_string())?;

    if !admin.is_admin {
        return Err("Unauthorized".to_string());
    }

    // 查找目标用户
    let mut target_user = ctx
        .db
        .users()
        .id()
        .find(target_user_id)
        .ok_or_else(|| "Target user not found".to_string())?;

    // 更新用户状态
    target_user.is_banned = false;
    ctx.db.users().id().update(target_user);

    Ok(())
}

#[spacetimedb::reducer]
pub fn update_user_iq(
    ctx: &ReducerContext,
    admin_id: i32,
    target_user_id: i32,
    new_iq: i32,
) -> Result<(), String> {
    // 验证管理员权限
    let admin = ctx
        .db
        .users()
        .id()
        .find(admin_id)
        .ok_or_else(|| "Admin not found".to_string())?;

    if !admin.is_admin {
        return Err("Unauthorized".to_string());
    }

    // 查找目标用户
    let mut target_user = ctx
        .db
        .users()
        .id()
        .find(target_user_id)
        .ok_or_else(|| "Target user not found".to_string())?;

    // 更新用户 IQ
    target_user.iq = Some(new_iq);
    ctx.db.users().id().update(target_user);

    Ok(())
}

// 邮件相关操作
#[spacetimedb::reducer]
pub fn snooze_email(
    ctx: &ReducerContext,
    email_id: i32,
    user_id: i32,
    snooze_until: Timestamp,
) -> Result<(), String> {
    let email = ctx
        .db
        .emails()
        .id()
        .find(email_id)
        .ok_or_else(|| "Email not found".to_string())?;

    // 验证用户是否有权限操作该邮件
    if email.to_address
        != format!(
            "{}#{}",
            ctx.db
                .users()
                .id()
                .find(user_id)
                .ok_or_else(|| "User not found".to_string())?
                .username,
            email.to_domain
        )
    {
        return Err("Unauthorized".to_string());
    }

    let mut updated_email = email.clone();
    updated_email.snooze_until = Some(snooze_until);

    ctx.db.emails().id().update(updated_email);
    Ok(())
}

#[spacetimedb::reducer]
pub fn mark_email_as_spam(ctx: &ReducerContext, email_id: i32, user_id: i32) -> Result<(), String> {
    let email = ctx
        .db
        .emails()
        .id()
        .find(email_id)
        .ok_or_else(|| "Email not found".to_string())?;

    // 验证用户是否有权限操作该邮件
    if email.to_address
        != format!(
            "{}#{}",
            ctx.db
                .users()
                .id()
                .find(user_id)
                .ok_or_else(|| "User not found".to_string())?
                .username,
            email.to_domain
        )
    {
        return Err("Unauthorized".to_string());
    }

    let mut updated_email = email.clone();
    updated_email.classification = EmailClassification::Primary;

    ctx.db.emails().id().update(updated_email);
    Ok(())
}

// 邮件发送相关操作
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

// SHARP 协议交互
#[spacetimedb::reducer]
pub fn handle_sharp_message(ctx: &ReducerContext, raw_message: String) -> Result<(), String> {
    // 解析消息
    let message = parse_sharp_message(&raw_message)?;

    match message.message_type {
        SharpMessageType::Hello => {
            // 验证协议版本
            if message.protocol.as_deref() != Some(PROTOCOL_VERSION) {
                return Err(format!(
                    "Unsupported protocol version: {}",
                    message.protocol.unwrap_or_default()
                ));
            }

            // 验证发送者身份
            let server_id = message.server_id.ok_or("Missing server_id")?;
            let (username, domain, _) = parse_sharp_address(&server_id)?;

            // 验证用户存在且未被封禁
            let user = ctx
                .db
                .users()
                .iter()
                .find(|u| u.username == username && u.domain == domain)
                .ok_or("Sender not found or banned")?;

            if user.is_banned {
                return Err("Sender account is banned".to_string());
            }

            // 创建会话
            let session_code = format!(
                "{:x}",
                Sha256::digest(
                    format!(
                        "{}{}{}",
                        username,
                        domain,
                        ctx.timestamp.to_micros_since_unix_epoch()
                    )
                    .as_bytes()
                )
            );

            ctx.db.user_secret_codes().insert(UserSecretCode {
                code: session_code.clone(),
                user_id: user.id,
                created_at: ctx.timestamp,
                ip: None,
                user_agent: None,
            });

            Ok(())
        }

        SharpMessageType::MailTo => {
            // 验证收件人地址
            let address = message.address.ok_or("Missing address")?;
            let (username, domain, _) = parse_sharp_address(&address)?;

            // 验证收件人存在
            let recipient_exists = ctx
                .db
                .users()
                .iter()
                .any(|u| u.username == username && u.domain == domain);

            if !recipient_exists {
                return Err("Recipient not found".to_string());
            }

            Ok(())
        }

        SharpMessageType::Data => {
            // 准备接收邮件内容
            Ok(())
        }

        SharpMessageType::EmailContent => {
            // 验证邮件内容
            let subject = message.subject.ok_or("Missing subject")?;
            let body = message.body.ok_or("Missing body")?;
            let content_type = message
                .content_type
                .unwrap_or_else(|| "text/plain".to_string());
            let html_body = message.html_body;
            let attachments = message.attachments.unwrap_or_default();

            // 验证词汇
            if content_type == "text/plain" {
                let server_id = message.server_id.ok_or("Missing server_id")?;
                let (username, domain, _) = parse_sharp_address(&server_id)?;

                let user = ctx
                    .db
                    .users()
                    .iter()
                    .find(|u| u.username == username && u.domain == domain)
                    .ok_or("Sender not found")?;

                if let Some(iq) = user.iq {
                    check_vocabulary(&body, Some(iq))?;
                }
            }

            // 处理附件
            if !attachments.is_empty() {
                for key in attachments {
                    if let Some(attachment) = ctx.db.attachments().iter().find(|a| a.key == key) {
                        let mut updated_attachment = attachment.clone();
                        updated_attachment.status = "processing".to_string();
                        ctx.db.attachments().id().update(updated_attachment);
                    }
                }
            }

            Ok(())
        }

        SharpMessageType::EndData => {
            // 处理邮件完成
            Ok(())
        }

        _ => Err("Unexpected message type".to_string()),
    }
}
