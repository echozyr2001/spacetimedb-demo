use crate::tables::*;
use spacetimedb::{ReducerContext, Table, Timestamp};

// Email Star 相关操作
#[spacetimedb::reducer]
pub fn create_email_star(ctx: &ReducerContext, email_id: i32, user_id: i32) -> Result<(), String> {
    // 检查 email 是否存在
    let email = ctx
        .db
        .emails()
        .id()
        .find(&email_id)
        .ok_or_else(|| "Email not found".to_string())?;

    // 检查 user 是否存在
    let user = ctx
        .db
        .users()
        .id()
        .find(&user_id)
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
    ctx.db.email_stars().id().delete(&star.id);

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
        .find(&user_id)
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
        .find(&user_id)
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

// Attachment 相关操作
#[spacetimedb::reducer]
pub fn create_attachment(
    ctx: &ReducerContext,
    user_id: Option<i32>,
    key: String,
    filename: String,
    size: i32,
    file_type: String,
    email_id: Option<i32>,
) -> Result<(), String> {
    // 如果提供了 user_id，检查用户是否存在
    if let Some(user_id) = user_id {
        let user = ctx
            .db
            .users()
            .id()
            .find(&user_id)
            .ok_or_else(|| "User not found".to_string())?;
    }

    // 如果提供了 email_id，检查邮件是否存在
    if let Some(email_id) = email_id {
        let email = ctx
            .db
            .emails()
            .id()
            .find(&email_id)
            .ok_or_else(|| "Email not found".to_string())?;
    }

    // 创建新的附件
    ctx.db.attachments().insert(Attachment {
        id: 0, // 自增
        user_id,
        key,
        filename,
        size,
        file_type,
        created_at: Timestamp::now(),
        expires_at: None,
        email_id,
        status: "pending".to_string(),
    });

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
        .find(&user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 检查是否已存在存储限制
    let existing_limit = ctx.db.user_storage_limits().user_id().find(&user_id);

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
        .find(&user_id)
        .ok_or_else(|| "User not found".to_string())?;

    // 检查是否已存在设置
    let existing_settings = ctx.db.user_settings().user_id().find(&user_id);

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
        .find(&user_id)
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
                attachment.email_id.map_or(false, |email_id| {
                    ctx.db.emails().id().find(&email_id).map_or(false, |email| {
                        email.from_address == user_email || email.to_address == user_email
                    })
                })
                )
        })
        .map(|attachment| attachment.size as i64)
        .sum();

    // 更新用户的存储限制记录
    if let Some(mut limit) = ctx.db.user_storage_limits().user_id().find(&user_id) {
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
