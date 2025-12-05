use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmtError {
    #[error("Target PID does not exist: {0}")]
    InvalidPid(i32),

    #[error("Tracer is already running")]
    AlreadyRunning,

    #[error("Thread join failed")]
    ThreadJoinError,

    #[error("BPF error: {0}")]
    Bpf(#[from] libbpf_rs::Error),

    #[error("BPF program not found at: {0}")]
    BpfNotFound(String),

    #[error("Failed to open BPF object file: {0}")]
    OpenBpfError(String),

    #[error("Failed to load BPF object file: {0}")]
    LoadBpfError(String),

    #[error("Failed to attach BPF probe {0}")]
    AttachProbeFailed(String, #[source] libbpf_rs::Error),

    #[error("Map error: {0}")]
    MapError(String),

    #[error("Ring buffer initialization failed: {0}")]
    RingBufInit(String),

    #[error("Ring buffer not initialized")]
    RingBufNotInitialized,

    #[error("Ptrace error: {0}")]
    PtraceError(String),

    #[error("Other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, EmtError>;
