
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TracePoint {
  TraceToLxc = 0,
	TraceToProxy,
	TraceToHost,
	TraceToStack,
	TraceToOverlay,
	TraceFromLxc,
	TraceFromProxy,
	TraceFromHost,
	TraceFromStack,
	TraceFromOverlay,
	TraceFromNetwork,
	TraceToNetwork,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TraceReason {
	TraceReasonPolicy = CTStatus::CtNew as u8,
	TraceReasonCtEstablished = CTStatus::CtEstablished as u8,
	TraceReasonCtReply = CTStatus::CtReply as u8,
	TraceReasonCtRelated = CTStatus::CtRelated as u8,
	TraceReasonCtReopened = CTStatus::CtReopened as u8,
	TraceReasonUnknown,
	TraceReasonSrv6Encap,
	TraceReasonSrv6Decap,
	TraceReasonEncryptOverlay,
	/// Note: TraceReasonEncrypted is used as a mask. Beware if you add
	/// new values below it, they would match with that mask.
	TraceReasonEncrypted = 0x80,
} 

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CTDir {
	CtEgress = 0,
	CtIngress,
	CtService,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CTStatus {
	CtNew = 0,
	CtEstablished,
	CtReply,
	CtRelated,
	CtReopened,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TraceCtx{
  pub reason: TraceReason,
  /// Monitor length for number of bytes to forward in trace message. 0 means do not monitor.
  pub monitor: u32,
}

impl Default for TraceCtx {
  fn default() -> Self {
    Self {
      reason: TraceReason::TraceReasonUnknown,
      monitor: 0,
    }
  }
}