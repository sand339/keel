#![doc = "The provider a run authenticates with is the one it named."]

use keel_secrets::bedrock_selected;

#[test]
fn a_named_provider_outranks_every_credential_that_happens_to_be_exported() {
    // The regression this exists for: an operator holding both credentials got
    // whichever one the environment implied, so a run meant for one account
    // spent the other's budget and the audit recorded no disagreement.
    assert_eq!(
        bedrock_selected(Some("api-key"), true, Some("bedrock")),
        Ok(false),
        "a named API key lost to an exported bearer token"
    );
    assert_eq!(
        bedrock_selected(Some("bedrock"), false, None),
        Ok(true),
        "a named regional provider was not selected"
    );
}

#[test]
fn an_unnamed_provider_is_still_inferred_from_configuration() {
    assert_eq!(bedrock_selected(None, false, None), Ok(false));
    assert_eq!(
        bedrock_selected(None, true, None),
        Ok(true),
        "the bearer token exists for nothing else and must still select"
    );
    assert_eq!(bedrock_selected(None, false, Some("bedrock")), Ok(true));
    assert_eq!(
        bedrock_selected(None, false, Some("anthropic")),
        Ok(false),
        "an unrecognized provider name selected the regional endpoint"
    );
}

#[test]
fn an_unreadable_choice_is_refused_rather_than_guessed() {
    // The choice decides which credential this run holds. A typo in it must not
    // resolve to a provider by being closer to one than the other.
    let error = bedrock_selected(Some("bedrock-sso"), true, Some("bedrock"))
        .expect_err("a misspelled provider was accepted");
    assert!(
        error.contains("bedrock-sso"),
        "the refusal did not name the value: {error}"
    );
}
