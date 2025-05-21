use std::collections::HashMap;

use sha2::{Digest, Sha256};
use spacetimedb::{ReducerContext, TimeDuration, Timestamp};

use crate::EmailClassification;

// SHARP 协议常量
pub const PROTOCOL_VERSION: &str = "SHARP/1.2";
pub const SHARP_PORT: u16 = 5000;
pub const HTTP_PORT: u16 = 5001;

// Hashcash 阈值常量
pub const HASHCASH_THRESHOLDS: (u32, u32, u32) = (18, 10, 5); // (GOOD, WEAK, TRIVIAL)

// 协议消息类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharpMessageType {
    Hello,
    MailTo,
    Data,
    EmailContent,
    EndData,
    Ok,
    Error,
}

// 协议消息
#[derive(Debug, Clone)]
pub struct SharpMessage {
    pub message_type: SharpMessageType,
    pub server_id: Option<String>,
    pub protocol: Option<String>,
    pub address: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub content_type: Option<String>,
    pub html_body: Option<String>,
    pub attachments: Option<Vec<String>>,
    pub message: Option<String>,
}

// 邮件分类关键词
const KEYWORDS: &[(&str, EmailClassification)] = &[
    // Promotions
    ("sale", EmailClassification::Promotions),
    ("discount", EmailClassification::Promotions),
    ("buy now", EmailClassification::Promotions),
    ("limited time", EmailClassification::Promotions),
    ("offer", EmailClassification::Promotions),
    ("free shipping", EmailClassification::Promotions),
    ("coupon", EmailClassification::Promotions),
    ("deal", EmailClassification::Promotions),
    ("save", EmailClassification::Promotions),
    ("special", EmailClassification::Promotions),
    // Social
    ("friend request", EmailClassification::Social),
    ("mentioned you", EmailClassification::Social),
    ("liked your post", EmailClassification::Social),
    ("new follower", EmailClassification::Social),
    ("connection", EmailClassification::Social),
    ("following", EmailClassification::Social),
    // Forums
    ("digest", EmailClassification::Forums),
    ("thread", EmailClassification::Forums),
    ("post reply", EmailClassification::Forums),
    ("new topic", EmailClassification::Forums),
    ("unsubscribe from this group", EmailClassification::Forums),
    ("mailing list", EmailClassification::Forums),
    // Updates
    ("receipt", EmailClassification::Updates),
    ("order confirmation", EmailClassification::Updates),
    ("invoice", EmailClassification::Updates),
    ("payment received", EmailClassification::Updates),
    ("shipping update", EmailClassification::Updates),
    ("account update", EmailClassification::Updates),
];

// 邮件分类函数
pub fn classify_email(subject: &str, body: &str, html_body: Option<&str>) -> EmailClassification {
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
pub fn check_vocabulary(text: &str, iq: Option<i32>) -> Result<(), String> {
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

// Hashcash 验证函数
pub fn verify_hashcash(ctx: &ReducerContext, header: &str, resource: &str) -> Result<u32, String> {
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
pub fn parse_hashcash_date(date_str: &str) -> Result<Timestamp, String> {
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
pub fn count_leading_zeros(hash: &[u8]) -> u32 {
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

// 协议处理函数
pub fn parse_sharp_message(raw: &str) -> Result<SharpMessage, String> {
    let json: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("Invalid JSON format: {}", e))?;

    let message_type = match json.get("type").and_then(|t| t.as_str()) {
        Some("HELLO") => SharpMessageType::Hello,
        Some("MAIL_TO") => SharpMessageType::MailTo,
        Some("DATA") => SharpMessageType::Data,
        Some("EMAIL_CONTENT") => SharpMessageType::EmailContent,
        Some("END_DATA") => SharpMessageType::EndData,
        Some("OK") => SharpMessageType::Ok,
        Some("ERROR") => SharpMessageType::Error,
        _ => return Err("Unknown message type".to_string()),
    };

    Ok(SharpMessage {
        message_type,
        server_id: json
            .get("server_id")
            .and_then(|s| s.as_str())
            .map(String::from),
        protocol: json
            .get("protocol")
            .and_then(|p| p.as_str())
            .map(String::from),
        address: json
            .get("address")
            .and_then(|a| a.as_str())
            .map(String::from),
        subject: json
            .get("subject")
            .and_then(|s| s.as_str())
            .map(String::from),
        body: json.get("body").and_then(|b| b.as_str()).map(String::from),
        content_type: json
            .get("content_type")
            .and_then(|c| c.as_str())
            .map(String::from),
        html_body: json
            .get("html_body")
            .and_then(|h| h.as_str())
            .map(String::from),
        attachments: json
            .get("attachments")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            }),
        message: json
            .get("message")
            .and_then(|m| m.as_str())
            .map(String::from),
    })
}

pub fn create_sharp_response(message_type: SharpMessageType, message: Option<String>) -> String {
    let mut response = serde_json::Map::new();
    response.insert(
        "type".to_string(),
        serde_json::Value::String(match message_type {
            SharpMessageType::Ok => "OK".to_string(),
            SharpMessageType::Error => "ERROR".to_string(),
            _ => return String::new(),
        }),
    );

    if let Some(msg) = message {
        response.insert("message".to_string(), serde_json::Value::String(msg));
    }

    serde_json::to_string(&response).unwrap_or_default()
}

pub fn parse_sharp_address(address: &str) -> Result<(String, String, Option<u16>), String> {
    let parts: Vec<&str> = address.split('#').collect();
    if parts.len() != 2 {
        return Err("Invalid SHARP address format".to_string());
    }

    let username = parts[0].to_lowercase();
    let domain_parts: Vec<&str> = parts[1].split(':').collect();
    let domain = domain_parts[0].to_lowercase();
    let port = domain_parts.get(1).and_then(|p| p.parse::<u16>().ok());

    Ok((username, domain, port))
}
