use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

pub struct CircuitBreaker {
    threshold: usize,

    cooldown: Duration,

    failures: AtomicUsize,

    open_at: AtomicU64,

    open_flag: AtomicBool,
}

impl CircuitBreaker {
    pub fn new(threshold: usize, cooldown: Duration) -> Self {
        Self {
            threshold,
            cooldown,
            failures: AtomicUsize::new(0),
            open_at: AtomicU64::new(0),
            open_flag: AtomicBool::new(false),
        }
    }

    pub fn allow(&self) -> bool {
        if !self.open_flag.load(Ordering::Acquire) {
            return true;
        }

        let open_ms: u64 = self.open_at.load(Ordering::Acquire);
        if open_ms == 0 {
            return true;
        }

        let now_ms: u64 = millis_since_epoch();
        if now_ms.wrapping_sub(open_ms) >= self.cooldown.as_millis() as u64 {
            self.open_flag.store(false, Ordering::Release);
            self.failures.store(0, Ordering::Release);
            self.open_at.store(0, Ordering::Release);
            return true;
        }

        false
    }

    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Release);
        self.open_flag.store(false, Ordering::Release);
        self.open_at.store(0, Ordering::Release);
    }

    pub fn record_failure(&self) {
        let prev: usize = self.failures.fetch_add(1, Ordering::AcqRel);
        if prev + 1 >= self.threshold {
            self.open_flag.store(true, Ordering::Release);
            self.open_at.store(millis_since_epoch(), Ordering::Release);
        }
    }
}

fn millis_since_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

fn is_transient(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

fn is_transient_status(code: u16) -> bool {
    matches!(code, 500 | 502 | 503 | 504 | 429 | 408)
}

pub async fn retry<F, Fut>(
    max_retries: usize,
    mut f: F,
) -> Result<reqwest::Response, reqwest::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let mut attempt: usize = 0;
    loop {
        match f().await {
            Ok(resp) => {
                let status: u16 = resp.status().as_u16();

                if attempt < max_retries && is_transient_status(status) {
                    attempt += 1;

                    let delay: u64 = 100u64 << attempt.min(6);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    continue;
                }
                return Ok(resp);
            }

            Err(e) => {
                if attempt < max_retries && is_transient(&e) {
                    attempt += 1;
                    let delay: u64 = 100u64 << attempt.min(6);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    continue;
                }
                return Err(e);
            }
        }
    }
}

pub fn build_http_client(insecure: bool) -> Result<reqwest::Client, reqwest::Error> {
    let mut b: reqwest::ClientBuilder = reqwest::Client::builder()
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Duration::from_secs(90))
        .timeout(Duration::from_secs(30));

    if insecure {
        b = b.danger_accept_invalid_certs(true);
    }

    b.build()
}
