//! The single action definition drives every transport and generated schema.
use crate::{
    error::{Error, Result},
    service::Door,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::HeaderMap,
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Admin,
    Root,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Public,
    Member,
    Admin,
    Root,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Both,
    Global,
    Community,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Check,
    Record,
}
#[derive(Clone, Copy)]
pub struct Action {
    pub name: &'static str,
    pub description: &'static str,
    pub access: Access,
    pub scope: Scope,
    pub effect: Effect,
    pub request: fn() -> Value,
    pub response: fn() -> Value,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterStart {
    /// Required for an operator; never a role supplied by the caller.
    pub bootstrap: Option<String>,
    /// Community-only, verified passport enrolment ticket.
    pub ticket: Option<String>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Ceremony {
    pub ceremony: String,
    pub user: String,
    pub options: Value,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinish {
    pub ceremony: String,
    #[schema(value_type = Object)]
    pub credential: cpky::RegisterPublicKeyCredential,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub user: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginFinish {
    pub ceremony: String,
    #[schema(value_type = Object)]
    pub credential: cpky::PublicKeyCredential,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub token: String,
    pub user: String,
    pub role: Role,
    pub expires: u64,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Bytes {
    pub bytes: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PassportIssue {
    pub challenge: Vec<u8>,
    pub request: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GlobalPublic {
    pub key_ring: Vec<u8>,
    pub issuer: Vec<u8>,
    pub status: Vec<u8>,
}
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Suspend {
    pub user: String,
    pub until: u64,
}

fn schema<T: ToSchema>() -> Value {
    let mut schemas = Vec::new();
    T::schemas(&mut schemas);
    let mut root = serde_json::to_value(T::schema()).expect("Rust schema is serializable");
    let defs: serde_json::Map<String, Value> = schemas
        .into_iter()
        .map(|(name, schema)| {
            (
                name,
                serde_json::to_value(schema).expect("Rust schema is serializable"),
            )
        })
        .collect();
    // OpenAPI components and MCP use the same self-contained JSON Schema.
    fn refs(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(reference)) = map.get_mut("$ref") {
                    *reference = reference.replace("#/components/schemas/", "#/$defs/");
                }
                for value in map.values_mut() {
                    refs(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    refs(value);
                }
            }
            _ => {}
        }
    }
    if !defs.is_empty() {
        root["$defs"] = Value::Object(defs);
    }
    refs(&mut root);
    root
}

macro_rules! actions {
    ($( $(#[$attr:meta])* $name:ident($request:ty) -> $response:ty, $access:ident, $scope:ident, $effect:ident, $description:literal; )*) => {
        pub static ACTIONS: &[Action] = &[$(
            $(#[$attr])* Action { name: stringify!($name), description: $description,
                access: Access::$access, scope: Scope::$scope, effect: Effect::$effect,
                request: schema::<$request>, response: schema::<$response> },
        )*];
        pub fn router(door: Door) -> Router {
            let mut router = Router::new();
            $( $(#[$attr])* {
                router = router.route(concat!("/v1/", stringify!($name)), post(
                    |State(door): State<Door>, headers: HeaderMap, body: std::result::Result<Json<$request>, axum::extract::rejection::JsonRejection>| async move {
                        let ctx = door.authorize(action(stringify!($name)).expect("registered action"), &headers).await?;
                        let Json(request) = body.map_err(|_| Error::Invalid)?;
                        let response: $response = door.$name(ctx, request).await?;
                        Ok::<_, Error>(Json(response))
                    }
                ));
            } )*
            router.layer(DefaultBodyLimit::max(256 * 1024)).with_state(door)
        }
    }
}

actions! {
    register_begin(RegisterStart) -> Ceremony, Public, Both, Record, "Begin UV-required passkey registration";
    register_finish(RegisterFinish) -> User, Public, Both, Record, "Verify and store the first passkey";
    login_begin(User) -> Ceremony, Public, Both, Check, "Begin account-first passkey authentication";
    login_finish(LoginFinish) -> Session, Public, Both, Record, "Verify user and counter; create an ephemeral session";
    logout(Empty) -> Empty, Member, Both, Check, "End this ephemeral session";
    global_public(Empty) -> GlobalPublic, Public, Global, Check, "Read authenticated global issuer material";
    passport_challenge(Empty) -> Bytes, Member, Global, Record, "Reserve a blind passport issuance challenge";
    passport_issue(PassportIssue) -> Bytes, Member, Global, Record, "Issue a blind passport after global policy checks";
    global_warn(User) -> Empty, Root, Global, Record, "Record the warning preceding temporary suspension";
    global_suspend(Suspend) -> Empty, Root, Global, Record, "Temporarily suspend and advance the global epoch";
    #[cfg(feature = "development-gate")]
    development_gate(Empty) -> Empty, Member, Global, Record, "Pass the development-only synthetic uniqueness gate";
}

pub fn action(name: &str) -> Option<&'static Action> {
    ACTIONS.iter().find(|a| a.name == name)
}
pub fn openapi() -> utoipa::openapi::OpenApi {
    let paths: serde_json::Map<String, Value> = ACTIONS.iter().map(|action| {
        let role = format!("{:?}", action.access).to_lowercase();
        (format!("/v1/{}", action.name), json!({"post": {
            "operationId": action.name, "summary": action.description,
            "x-role": role, "x-effect": format!("{:?}", action.effect).to_lowercase(),
            "requestBody": {"required": true, "content": {"application/json": {"schema": (action.request)()}}},
            "responses": {"200": {"description": "Success", "content": {"application/json": {"schema": (action.response)()}}},
                "default": {"description": "Fixed redacted error category"}},
            "security": if action.access == Access::Public { json!([]) } else { json!([{"session": []}]) }
        }}))
    }).collect();
    serde_json::from_value(json!({"openapi":"3.1.0", "info":{"title":"cvld", "version":"0.2.0"},
        "paths": paths, "components":{"securitySchemes":{"session":{"type":"http", "scheme":"bearer"}}}}))
        .expect("registry builds valid OpenAPI")
}
