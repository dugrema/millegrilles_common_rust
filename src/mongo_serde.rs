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

pub mod map_opt_chrono_datetime_as_bson_datetime {
    use chrono::Utc;
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    #[derive(Serialize, Deserialize)]
    struct Helper(
        #[serde(with = "crate::mongo_serde::option_chrono_04_datetime")]
        Option<chrono::DateTime<Utc>>,
    );

    pub fn serialize<S>(
        value: &Option<HashMap<String, Option<chrono::DateTime<Utc>>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(inner ) => {
                let mut map = serializer.serialize_map(Some(inner.len()))?;
                for (k, v) in inner.iter() {
                    let helper = Helper(v.to_owned());
                    map.serialize_entry(k, &helper)?;
                }
                map.end()
            },
            None => None::<usize>.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<HashMap<String, Option<chrono::DateTime<Utc>>>>, D::Error>
    where
        D: Deserializer<'de>,
    {

        #[derive(Deserialize)]
        struct OptionalDateHelper(
            #[serde(with = "crate::mongo_serde::option_chrono_04_datetime")]
            Option<chrono::DateTime<Utc>>,
        );

        impl Into<Option<chrono::DateTime<Utc>>> for OptionalDateHelper {
            fn into(self) -> Option<chrono::DateTime<Utc>> {
                match self.0 {
                    Some(inner) => Some(inner),
                    None => None
                }
            }
        }

        #[derive(Deserialize)]
        struct MapHelper(
            HashMap<String, OptionalDateHelper>,
        );

        let map_helper: Option<MapHelper> = Option::deserialize(deserializer)?;
        match map_helper {
            Some(inner) => {
                let mut final_map: HashMap<String, Option<chrono::DateTime<Utc>>> = HashMap::new();
                for (k, v) in inner.0.into_iter() {
                    final_map.insert(k, v.into());
                }
                Ok(Some(final_map))
            },
            None => Ok(None),
        }

    }
}
