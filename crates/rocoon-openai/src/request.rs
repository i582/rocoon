use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub fn deserialize_flat_request<'de, T, N, D>(
    deserializer: D,
    disabled_fields: &[&str],
) -> Result<(T, N), D::Error>
where
    T: DeserializeOwned,
    N: DeserializeOwned,
    D: Deserializer<'de>,
{
    let mut value = Value::deserialize(deserializer)?;
    remove_disabled_fields(&mut value, disabled_fields);

    let openai = serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
    let non_standard = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
    Ok((openai, non_standard))
}

pub fn serialize_flat_request<T, N, S>(
    openai: &T,
    non_standard: &N,
    disabled_fields: &[&str],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    N: Serialize,
    S: Serializer,
{
    let mut value = serde_json::to_value(openai).map_err(serde::ser::Error::custom)?;
    remove_disabled_fields(&mut value, disabled_fields);
    merge_object_fields(
        &mut value,
        serde_json::to_value(non_standard).map_err(serde::ser::Error::custom)?,
    );
    value.serialize(serializer)
}

fn remove_disabled_fields(value: &mut Value, disabled_fields: &[&str]) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for field in disabled_fields {
        object.remove(*field);
    }
}

fn merge_object_fields(target: &mut Value, source: Value) {
    let (Some(target), Value::Object(source)) = (target.as_object_mut(), source) else {
        return;
    };
    target.extend(source);
}
