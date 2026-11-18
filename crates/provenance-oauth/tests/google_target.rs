use provenance_oauth::{Enrollment, Target};

#[test]
fn target_pairs_and_old_openai_document() {
    let old = r#"{"version":1,"target":{"host":"atlas","user":"root","provider":"openai","profile":"chatgpt","account":"default"},"generation":1,"grant":{"accessToken":"a","refreshToken":"r","expiresAt":123,"accountId":"id"}}"#;
    let enrollment: Enrollment = serde_json::from_str(old).unwrap();
    enrollment.validate(&enrollment.target).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(old).unwrap(),
        serde_json::to_value(&enrollment).unwrap()
    );
    let mut target: Target = enrollment.target;
    target.provider = "google".into();
    assert!(target.validate().is_err());
    target.profile = "drive-file".into();
    assert!(target.validate().is_ok());
    target.provider = "openai".into();
    assert!(target.validate().is_err());
}

#[test]
fn google_client_credentials_reject_ini_metacharacters() {
    let mut enrollment: Enrollment = serde_json::from_str(r#"{"version":1,"target":{"host":"atlas","user":"root","provider":"google","profile":"drive-file","account":"default"},"generation":1,"grant":{"accessToken":"a","refreshToken":"r","expiresAt":123,"accountId":"id","client":{"clientId":"123-abc.apps.googleusercontent.com","clientSecret":"GOCSPX-secret"}}}"#).unwrap();
    assert!(enrollment.validate(&enrollment.target).is_ok());
    for bad in ["%(type)s", "\"quoted\"", "", &"a".repeat(257)] {
        let client = enrollment.grant.client.as_mut().unwrap();
        client.client_id = bad.into();
        assert!(enrollment.validate(&enrollment.target).is_err());
        let client = enrollment.grant.client.as_mut().unwrap();
        client.client_id = "valid".into();
        client.client_secret.0 = bad.into();
        assert!(enrollment.validate(&enrollment.target).is_err());
        enrollment.grant.client.as_mut().unwrap().client_secret.0 = "valid".into();
    }
}
