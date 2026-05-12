#!/bin/bash
sed -i '' -e 's/    facts_url: Option<String>,/    facts_url: Option<String>,\n    #[serde(default)]\n    content_type: Option<String>,\n    #[serde(default)]\n    body_b64: Option<String>,/g' src/main.rs

sed -i '' -e 's/    signed_response: Option<SignedResponseHeaders>,/    signed_response: Option<SignedResponseHeaders>,\n    #[serde(skip_serializing_if = "Option::is_none")]\n    status: Option<u16>,\n    #[serde(skip_serializing_if = "Option::is_none")]\n    body_b64: Option<String>,/g' src/main.rs

