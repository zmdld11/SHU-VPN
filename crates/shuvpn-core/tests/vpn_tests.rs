//! VPN management 层离线单测：行解析（STATE/NeedAuth/VerificationFailed/CRV1）、
//! 应答构造（SCRV1 打包 / FORMAT 拼接 / CRV1 模板回传 / 转义）、cr-response。
//! 全部为纯函数测试，不触网、不启动进程。

use shuvpn_core::vpn::{
    auth_response_lines, cr_response_line, escape_mgmt, parse_crv1, parse_mgmt_line, MgmtEvent,
    NeedAuth, StaticChallenge,
};

fn plain_need() -> NeedAuth {
    NeedAuth {
        username_only: false,
        static_challenge: None,
    }
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

#[test]
fn parse_state_connected() {
    match parse_mgmt_line(">STATE:1710000000,CONNECTED,SUCCESS,10.8.0.6,1.2.3.4,1194,,") {
        MgmtEvent::State { name, reason } => {
            assert_eq!(name, "CONNECTED");
            assert_eq!(reason.as_deref(), Some("SUCCESS"));
        }
        other => panic!("期望 State，得到 {other:?}"),
    }
}

#[test]
fn parse_state_reconnecting_with_reason() {
    match parse_mgmt_line(">STATE:1710000000,RECONNECTING,resolve error,,") {
        MgmtEvent::State { name, reason } => {
            assert_eq!(name, "RECONNECTING");
            assert_eq!(reason.as_deref(), Some("resolve error"));
        }
        other => panic!("期望 State，得到 {other:?}"),
    }
}

#[test]
fn parse_need_auth_plain() {
    match parse_mgmt_line(">PASSWORD:Need 'Auth' username/password") {
        MgmtEvent::NeedAuth(need) => {
            assert!(!need.username_only);
            assert_eq!(need.static_challenge, None);
        }
        other => panic!("期望 NeedAuth，得到 {other:?}"),
    }
}

#[test]
fn parse_need_auth_static_challenge() {
    match parse_mgmt_line(">PASSWORD:Need 'Auth' username/password SC:1,请输入 OTP 令牌") {
        MgmtEvent::NeedAuth(need) => {
            assert_eq!(
                need.static_challenge,
                Some(StaticChallenge {
                    flag: 1,
                    text: "请输入 OTP 令牌".into()
                })
            );
        }
        other => panic!("期望 NeedAuth(SC)，得到 {other:?}"),
    }
}

#[test]
fn parse_need_auth_username_only() {
    match parse_mgmt_line(">PASSWORD:Need 'Auth' username") {
        MgmtEvent::NeedAuth(need) => assert!(need.username_only),
        other => panic!("期望 NeedAuth(username-only)，得到 {other:?}"),
    }
}

#[test]
fn parse_verification_failed_with_crv1() {
    // 挑战文本里带冒号（官方文档允许）
    let line = ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter: token PIN']";
    match parse_mgmt_line(line) {
        MgmtEvent::VerificationFailed { reason, dynamic } => {
            assert_eq!(reason, "Auth");
            let d = dynamic.expect("CRV1");
            assert_eq!(d.flags, "R,E");
            assert_eq!(d.opaque, "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l");
            assert_eq!(d.username_b64, "Y3Ix");
            assert_eq!(d.text, "Please enter: token PIN");
        }
        other => panic!("期望 VerificationFailed，得到 {other:?}"),
    }
}

#[test]
fn parse_verification_failed_plain() {
    match parse_mgmt_line(">PASSWORD:Verification Failed: 'custom server string'") {
        MgmtEvent::VerificationFailed { reason, dynamic } => {
            assert_eq!(reason, "custom server string");
            assert_eq!(dynamic, None);
        }
        other => panic!("期望 VerificationFailed，得到 {other:?}"),
    }
}

#[test]
fn parse_non_realtime_line_is_other() {
    assert!(matches!(
        parse_mgmt_line("SUCCESS: log on"),
        MgmtEvent::Other(_)
    ));
    assert!(matches!(parse_mgmt_line(""), MgmtEvent::Other(_)));
}

// ---------------------------------------------------------------------------
// 应答构造
// ---------------------------------------------------------------------------

#[test]
fn escape_mgmt_handles_backslash_and_quote() {
    assert_eq!(escape_mgmt("a\\b"), "a\\\\b");
    assert_eq!(escape_mgmt("a\"b"), "a\\\"b");
    assert_eq!(escape_mgmt("plain"), "plain");
}

#[test]
fn auth_response_plain_quotes_credentials() {
    let lines = auth_response_lines("25120000", "p@\"ss\\w", "", &plain_need(), None);
    assert_eq!(
        lines,
        vec![
            "username \"Auth\" \"25120000\"",
            "password \"Auth\" \"p@\\\"ss\\\\w\""
        ]
    );
}

#[test]
fn auth_response_static_format0_packs_scrv1() {
    let need = NeedAuth {
        username_only: false,
        static_challenge: Some(StaticChallenge {
            flag: 0,
            text: "请输入 OTP 令牌".into(),
        }),
    };
    let lines = auth_response_lines("u", "bar", "8675309", &need, None);
    // 官方文档示例：bar → YmFy，8675309 → ODY3NTMwOQ==
    assert_eq!(lines[0], "username \"Auth\" \"u\"");
    assert_eq!(lines[1], "password \"Auth\" \"SCRV1:YmFy:ODY3NTMwOQ==\"");
}

#[test]
fn auth_response_static_format1_concatenates() {
    let need = NeedAuth {
        username_only: false,
        static_challenge: Some(StaticChallenge {
            flag: 2,
            text: "PIN".into(),
        }),
    };
    let lines = auth_response_lines("u", "bar", "8675309", &need, None);
    assert_eq!(lines[1], "password \"Auth\" \"bar8675309\"");
}

#[test]
fn auth_response_dynamic_crv1_echoes_challenge_fields() {
    let need = plain_need();
    let challenge =
        parse_crv1("CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN");
    let lines = auth_response_lines("25120000", "pw", "8675309", &need, Some(&challenge));
    // Y3Ix → "cr1"（挑战携带的用户名 b64）
    assert_eq!(lines[0], "username \"Auth\" \"cr1\"");
    assert_eq!(
        lines[1],
        "password \"Auth\" \"CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:8675309\""
    );
}

#[test]
fn auth_response_username_only_single_line() {
    let need = NeedAuth {
        username_only: true,
        static_challenge: None,
    };
    let lines = auth_response_lines("u", "p", "", &need, None);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0], "username \"Auth\" \"u\"");
}

#[test]
fn cr_response_encodes_otp() {
    // "123456" → MTIzNDU2
    assert_eq!(cr_response_line("123456"), "cr-response MTIzNDU2");
}
