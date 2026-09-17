pub mod option_chrono_04_datetime {

    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Serializer, Deserializer};

    pub fn serialize<S>(date: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        match date {
            Some(inner) => {
                let s = inner.timestamp();
                serializer.serialize_i64(s)
            },
            None => {
                serializer.serialize_none()
            }
        }
    }

    pub fn deserialize<'de, D>( deserializer: D ) -> Result<Option<DateTime<Utc>>, D::Error>
    where D: Deserializer<'de>,
    {
        let s: Option<bson::datetime::DateTime> = Option::deserialize(deserializer)?;
        match s {
            Some(inner) =>  {
                let dt = chrono::DateTime::<Utc>::from_timestamp_millis(inner.timestamp_millis());
                Ok(dt)
            },
            None => Ok(None)
        }
    }
}
