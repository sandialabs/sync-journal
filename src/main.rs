use journal_sdk::{Config, JOURNAL};
use log::info;
use rocket::config::Config as RocketConfig;
use rocket::data::{Limits, ToByteUnit};
use rocket::response::content::RawHtml;
use rocket::serde::json::Json;
use rocket::{get, post, routes};
use serde_json::Value;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MICRO: f64 = 1000000.0;

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html>
    <head>
 <h2>Journal SDK Home</h2>
    </head>
    <body style="padding: 0 20px; font-family: 'Consolas'">
 <ul>
     <li><a href="/interface">LISP Interface</a></li>
     <li><a href="/interface/json">JSON Interface</a></li>
 </ul>
    </body>
</html>
"#;

const INTERFACE_HTML: &str = r#"<!DOCTYPE html>
<html>
    <head>
 <h2>{}</h2>
    </head>
    <body style="padding: 0 20px; font-family: 'Consolas'">
 <textarea id="query" rows="8" cols="128" spellcheck="false"></textarea>
 </br>
 </br>
 <button type="button" onclick="customSubmit()">Evaluate</button>
 </br>
 <ul id="history">
 </ul>
 <script>
     function customSubmit() {
  let query = document.getElementById('query').value;
  fetch('', {
      method: 'POST',
      body: query,
  }).then(response => {
      return response.text();
  }).catch(error => {
      return "Error: uh oh, not sure what happened";
  }).then(result => {
      let history = document.getElementById('history');
      history.innerHTML = `<li style="list-style: '&#8594; '; color: green">
   <span style="color: gray">
       ${query.slice(0, 512)}
       ${query.length > 512 ? " ..." : ""}
   </span>
      </li>
      <li style="list-style: '  '">
          ${result.replace(/</g, '&lt').replace(/>/g, '&gt')}
      </li>` + history.innerHTML;
  })
     }
 </script>
    </body>
</html>
"#;

#[get("/")]
async fn index() -> RawHtml<String> {
    RawHtml(String::from(INDEX_HTML))
}

#[get("/interface", format = "text/html")]
async fn inform_lisp() -> RawHtml<String> {
    RawHtml(INTERFACE_HTML.replace("{}", "LISP Interface"))
}

#[post("/interface", data = "<query>", rank = 1)]
async fn evaluate_lisp(query: &str) -> String {
    JOURNAL.evaluate(query)
}

#[get("/interface/json", format = "text/html")]
async fn inform_json() -> RawHtml<String> {
    RawHtml(INTERFACE_HTML.replace("{}", "JSON Interface"))
}

#[post("/interface/json", data = "<request>", format = "json", rank = 1)]
async fn evaluate_json(request: Json<Value>) -> Json<Value> {
    let result = JOURNAL.evaluate_json(request.into_inner());
    Json(result)
}

#[rocket::main]
async fn main() {
    let config = Config::new();

    env_logger::init();

    if &config.boot != "" {
        let result = JOURNAL.evaluate(&config.boot);
        info!("Boot: {}", result);
    }

    if &config.evaluate != "" {
        let result = JOURNAL.evaluate(&config.evaluate);
        println!("{}", result);
        return;
    }

    let mut rocket_config = RocketConfig::default();
    rocket_config.port = config.port;
    rocket_config.address = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    rocket_config.limits = Limits::new().limit("string", 1_i32.mebibytes());

    let period = 2_f64.powi(config.periodicity);

    if config.step != "" {
        tokio::spawn(async move {
            let mut step = 0;
            let start = ((SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Failed to get system time")
                .as_micros() as f64
                / (period * MICRO))
                .ceil()
                * (period * MICRO)) as u128;

            loop {
                let until = start + step * (period * MICRO) as u128;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Failed to get system time")
                    .as_micros();
                if now < until {
                    tokio::time::sleep(Duration::from_micros(
                        (until - now)
                            .try_into()
                            .expect("Failed to convert duration"),
                    ))
                    .await;
                }
                let result = JOURNAL.evaluate(&config.step);
                info!("Step ({:.6}): {}", until as f64 / MICRO, result);
                step += 1;
            }
        });
    }

    let _ = rocket::build()
        .mount(
            "/",
            routes![
                index,
                inform_lisp,
                evaluate_lisp,
                inform_json,
                evaluate_json
            ],
        )
        .configure(rocket_config)
        .launch()
        .await;
}
