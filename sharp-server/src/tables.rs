use serde::{Deserialize, Serialize};
use spacetimedb::{SpacetimeType, Timestamp};

// Email Status Enum
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, SpacetimeType)]
pub enum EmailStatus {
    Pending,   // Initial state
    Sending,   // Transmission in progress
    Sent,      // Successfully delivered
    Failed,    // Transmission failed
    Rejected,  // Explicitly rejected by remote server
    Scheduled, // Scheduled for future delivery
    Spam,      // Marked as spam by the system
}

// Email Classification Enum
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, SpacetimeType)]
pub enum EmailClassification {
    Primary,
    Promotions,
    Social,
    Forums,
    Updates,
}

// User Table
#[spacetimedb::table(name = users)]
#[derive(Clone)]
pub struct User {
    #[primary_key]
    #[auto_inc]
    pub id: i32,
    #[index(btree)]
    pub username: String,
    pub domain: String,
    pub password_hash: String,
    pub iq: Option<i32>,
    pub is_banned: bool,
    pub is_admin: bool,
    pub deleted_at: Option<Timestamp>,
    pub created_at: Timestamp,
}

// User Secret Code Table
#[spacetimedb::table(name = user_secret_codes)]
#[derive(Clone)]
pub struct UserSecretCode {
    #[primary_key]
    pub code: String,
    #[index(btree)]
    pub user_id: i32,
    pub created_at: Timestamp,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

// Email Table
#[spacetimedb::table(name = emails)]
#[derive(Clone)]
pub struct Email {
    #[primary_key]
    #[auto_inc]
    pub id: i32,
    #[index(btree)]
    pub from_address: String,
    #[index(btree)]
    pub to_address: String,
    pub from_domain: String,
    pub to_domain: String,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub content_type: String,
    pub html_body: Option<String>,
    pub sent_at: Timestamp,
    pub error_message: Option<String>,
    #[index(btree)]
    pub status: EmailStatus,
    pub snooze_until: Option<Timestamp>,
    pub read_at: Option<Timestamp>,
    pub scheduled_at: Option<Timestamp>,
    pub classification: EmailClassification,
    pub reply_to_id: Option<i32>,
    #[index(btree)]
    pub thread_id: Option<i32>,
    pub expires_at: Option<Timestamp>,
    pub self_destruct: bool,
}

// Email Star Table - Using a single primary key instead of composite key
#[spacetimedb::table(name = email_stars)]
#[derive(Clone)]
pub struct EmailStar {
    #[primary_key]
    #[auto_inc]
    pub id: i32,
    #[index(btree)]
    pub email_id: i32,
    #[index(btree)]
    pub user_id: i32,
    pub starred_at: Timestamp,
}

// Email Draft Table
#[spacetimedb::table(name = email_drafts)]
#[derive(Clone)]
pub struct EmailDraft {
    #[primary_key]
    #[auto_inc]
    pub id: i32,
    #[index(btree)]
    pub user_id: i32,
    pub to_address: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub content_type: String,
    pub html_body: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

// Contact Table
#[spacetimedb::table(name = contacts)]
#[derive(Clone)]
pub struct Contact {
    #[primary_key]
    #[auto_inc]
    pub id: i32,
    #[index(btree)]
    pub user_id: i32,
    pub full_name: String,
    #[index(btree)]
    pub email_address: String,
    pub tag: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

// Attachment Table
#[spacetimedb::table(name = attachments)]
#[derive(Clone)]
pub struct Attachment {
    #[primary_key]
    #[auto_inc]
    pub id: i32,
    #[index(btree)]
    pub user_id: Option<i32>,
    pub key: String,
    pub filename: String,
    pub size: i32,
    pub file_type: String,
    pub created_at: Timestamp,
    #[index(btree)]
    pub expires_at: Option<Timestamp>,
    #[index(btree)]
    pub email_id: Option<i32>,
    pub status: String,
}

// User Storage Limit Table
#[spacetimedb::table(name = user_storage_limits)]
#[derive(Clone)]
pub struct UserStorageLimit {
    #[primary_key]
    pub user_id: i32,
    pub storage_limit: i64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

// User Setting Table
#[spacetimedb::table(name = user_settings)]
#[derive(Clone)]
pub struct UserSettings {
    #[primary_key]
    pub user_id: i32,
    pub notifications_enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}
