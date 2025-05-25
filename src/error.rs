// TODO: handle all types of errors here
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmtError {
    #[error("Target PID does not exist: {0}")]
    NoSuchPid(i32),
}
