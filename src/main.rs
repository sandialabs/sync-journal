use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use log::info;
use std::net::{IpAddr, Ipv6Addr};
use rocket::data::{Limits, ToByteUnit};
use rocket::{get, post, routes};
use rocket::response::content::RawHtml;
use rocket::config::Config as RocketConfig;
use journal_sdk::{Config, JOURNAL};

const MICRO: f64 = 1000000.0;

#[get("/")]
async fn index() -> RawHtml<String> {
    RawHtml(format!(
        r#"<!DOCTYPE html>
<html>
    <head>
 <h2>Journal SDK Home</h2>
    </head>
    <body style="padding: 0 20px; font-family: 'Consolas'">
 <ul>
     <li><a href="/interface">Interface</a></li>
 </ul>
    </body>
</html>
"#,
    ))
}

#[get("/interface", format = "text/html")]
async fn inform() -> RawHtml<String> {
    RawHtml(String::from(r#"<!DOCTYPE html>
<html>
    <head>
 <h2>Interface</h2>
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
"#))
}

#[post("/interface", data = "<query>", rank = 1)]
async fn evaluate(query: &str) -> String {
    JOURNAL.evaluate(query)
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
        return
    }

    let mut rocket_config = RocketConfig::default();
    rocket_config.port = config.port;
    rocket_config.address = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    rocket_config.limits = Limits::new().limit("string", 1_i32.mebibytes());

    let period = 2_f64.powi(config.periodicity);

    if config.step != "" {
        thread::spawn(move || {
            let mut step = 0;
            let start = ((
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as f64 /
                    (period * MICRO)
            ).ceil() * (period * MICRO)) as u128;
            loop {
                let until = start + step * (period * MICRO) as u128;
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
                if now < until {
                    thread::sleep(Duration::from_micros((until - now).try_into().unwrap()));
                }
                let result = JOURNAL.evaluate(&config.step);
                info!("Step ({:.6}): {}", until as f64 / MICRO, result);
                step += 1;
            }
        });
    }

    let _ = rocket::build()
        .mount("/", routes![
            index,
            inform,
            evaluate,
        ])
        .configure(rocket_config)
        .launch()
        .await;
}
