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
fn parse_hold_notification() {
    assert!(matches!(
        parse_mgmt_line(">HOLD:Waiting for hold release:0"),
        MgmtEvent::Hold
    ));
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

// ---------------------------------------------------------------------------
// PUSH_REPLY 路由解析（分流模式网段学习）
// ---------------------------------------------------------------------------

use shuvpn_core::vpn::parse_push_routes;

#[test]
fn push_routes_parses_school_nets() {
    // 模拟真实 PUSH_REPLY：校内段 + dhcp-option + redirect-gateway def1 展开的默认路由
    let line = ">LOG:1763780000,I,PUSH: Received control message: 'PUSH_REPLY,route 10.60.0.0 255.255.0.0,route 172.16.0.0 255.240.0.0 vpn_gateway,dhcp-option DNS 10.10.10.10,redirect-gateway def1,route 0.0.0.0 128.0.0.0,route 128.0.0.0 128.0.0.0'";
    let routes = parse_push_routes(line);
    assert_eq!(
        routes,
        vec![
            ("10.60.0.0".to_string(), "255.255.0.0".to_string()),
            ("172.16.0.0".to_string(), "255.240.0.0".to_string()),
        ]
    );
}

#[test]
fn push_routes_accepts_stdout_prefix_and_ignores_other_lines() {
    assert_eq!(
        parse_push_routes(
            "[out] PUSH: Received control message: 'PUSH_REPLY,route 10.1.2.0 255.255.255.0'"
        ),
        vec![("10.1.2.0".to_string(), "255.255.255.0".to_string())]
    );
    assert!(parse_push_routes(">LOG:1,I,Initialization Sequence Completed").is_empty());
    assert!(parse_push_routes("").is_empty());
}

#[test]
fn push_routes_handles_truncated_line() {
    // 行尾引号缺失（截断）时条目仍应完整解析
    let line = "PUSH: Received control message: 'PUSH_REPLY,route 10.7.0.0 255.0.0.0";
    assert_eq!(
        parse_push_routes(line),
        vec![("10.7.0.0".to_string(), "255.0.0.0".to_string())]
    );
}

// ---------------------------------------------------------------------------
// 自定义规则文件解析（分流模式附加路由）
// ---------------------------------------------------------------------------

use shuvpn_core::vpn::{parse_custom_rules, prefix_to_mask, CustomRules};

#[test]
fn prefix_to_mask_values() {
    assert_eq!(prefix_to_mask(0).unwrap(), "0.0.0.0");
    assert_eq!(prefix_to_mask(8).unwrap(), "255.0.0.0");
    assert_eq!(prefix_to_mask(16).unwrap(), "255.255.0.0");
    assert_eq!(prefix_to_mask(24).unwrap(), "255.255.255.0");
    assert_eq!(prefix_to_mask(32).unwrap(), "255.255.255.255");
    assert!(prefix_to_mask(33).is_none());
}

#[test]
fn custom_rules_parses_all_forms() {
    let text = "# 注释行\n\
                10.60.0.0/16\n\
                172.20.3.0 255.255.255.0\n\
                route 192.168.7.0 255.255.255.0\n\
                HOST CNKI.net\n\
                \n\
                host web.library.shu.edu.cn\n";
    let r = parse_custom_rules(text);
    assert_eq!(
        r.routes,
        vec![
            ("10.60.0.0".to_string(), "255.255.0.0".to_string()),
            ("172.20.3.0".to_string(), "255.255.255.0".to_string()),
            ("192.168.7.0".to_string(), "255.255.255.0".to_string()),
        ]
    );
    assert_eq!(r.hosts, vec!["cnki.net", "web.library.shu.edu.cn"]);
    assert!(r.errors.is_empty());
}

#[test]
fn custom_rules_reports_bad_lines_with_numbers() {
    let text = "10.0.0.0/8\n\
                999.1.2.3/24\n\
                10.2.0.0/33\n\
                HOST notadomain\n\
                10.3.0.0\n\
                route 10.4.0.0 255.0.0.0 extra\n\
                HOST\n";
    let r = parse_custom_rules(text);
    // 合法行不受非法行影响
    assert_eq!(r.routes.len(), 1);
    assert!(r.hosts.is_empty());
    assert_eq!(r.errors.len(), 6);
    assert!(r.errors[0].contains("第2行"));
    assert!(r.errors[1].contains("第3行"));
    assert!(r.errors[5].contains("第7行"));
}

#[test]
fn custom_rules_empty_and_inline_comment() {
    assert_eq!(parse_custom_rules(""), CustomRules::default());
    assert_eq!(
        parse_custom_rules("   \n#only comment\n"),
        CustomRules::default()
    );
    let r = parse_custom_rules("10.9.0.0/16 # 行内注释");
    assert_eq!(r.routes.len(), 1);
    assert!(r.errors.is_empty());
}
