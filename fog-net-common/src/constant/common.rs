/// Capture notifications version. Must be incremented when format changes.
pub const NOTIFY_CAPTURE_VER: u16 = 1;
pub const TRACE_PAYLOAD_LEN: u64 = 128;
pub const BPF_F_PSEUDO_HDR: u64 = 1 << 4;

/// Return value to indicate that proxy redirection is required
pub const POLICY_ACT_PROXY_REDIRECT: u64 = 1 << 16;

/* Cilium error codes, must NOT overlap with TC return codes.
 * These also serve as drop reasons for metrics,
 * where reason > 0 corresponds to -(DROP_*)
 *
 * These are shared with pkg/monitor/api/drop.go and api/v1/flow/flow.proto.
 * When modifying any of the below, those files should also be updated.
 */
pub const DROP_UNUSED1: i32 = -130;
pub const DROP_UNUSED2: i32 = -131;
pub const DROP_INVALID_SIP: i32 = -132;
pub const DROP_POLICY: i32 = -133;
pub const DROP_INVALID: i32 = -134;
pub const DROP_CT_INVALID_HDR: i32 = -135;
pub const DROP_FRAG_NEEDED: i32 = -136;
pub const DROP_CT_UNKNOWN_PROTO: i32 = -137;
pub const DROP_UNUSED4: i32 = -138;
pub const DROP_UNKNOWN_L3: i32 = -139;
pub const DROP_MISSED_TAIL_CALL: i32 = -140;
pub const DROP_WRITE_ERROR: i32 = -141;
pub const DROP_UNKNOWN_L4: i32 = -142;
pub const DROP_UNKNOWN_ICMP_CODE: i32 = -143;
pub const DROP_UNKNOWN_ICMP_TYPE: i32 = -144;
pub const DROP_UNKNOWN_ICMP6_CODE: i32 = -145;
pub const DROP_UNKNOWN_ICMP6_TYPE: i32 = -146;
pub const DROP_NO_TUNNEL_KEY: i32 = -147;
pub const DROP_UNUSED5: i32 = -148;
pub const DROP_UNUSED6: i32 = -149;
pub const DROP_UNKNOWN_TARGET: i32 = -150;
pub const DROP_UNROUTABLE: i32 = -151;
pub const DROP_UNUSED7: i32 = -152;
pub const DROP_CSUM_L3: i32 = -153;
pub const DROP_CSUM_L4: i32 = -154;
pub const DROP_CT_CREATE_FAILED: i32 = -155;
pub const DROP_INVALID_EXTHDR: i32 = -156;
pub const DROP_FRAG_NOSUPPORT: i32 = -157;
pub const DROP_NO_SERVICE: i32 = -158;
pub const DROP_UNSUPP_SERVICE_PROTO: i32 = -159;
pub const DROP_NO_TUNNEL_ENDPOINT: i32 = -160;
pub const DROP_NAT_46X64_DISABLED: i32 = -161;
pub const DROP_EDT_HORIZON: i32 = -162;
pub const DROP_UNKNOWN_CT: i32 = -163;
pub const DROP_HOST_UNREACHABLE: i32 = -164;
pub const DROP_NO_CONFIG: i32 = -165;
pub const DROP_UNSUPPORTED_L2: i32 = -166;
pub const DROP_NAT_NO_MAPPING: i32 = -167;
pub const DROP_NAT_UNSUPP_PROTO: i32 = -168;
pub const DROP_NO_FIB: i32 = -169;
pub const DROP_ENCAP_PROHIBITED: i32 = -170;
pub const DROP_INVALID_IDENTITY: i32 = -171;
pub const DROP_UNKNOWN_SENDER: i32 = -172;
pub const DROP_NAT_NOT_NEEDED: i32 = -173; /* Mapped as drop code, though drop not necessary. */
pub const DROP_IS_CLUSTER_IP: i32 = -174;
pub const DROP_FRAG_NOT_FOUND: i32 = -175;
pub const DROP_FORBIDDEN_ICMP6: i32 = -176;
pub const DROP_NOT_IN_SRC_RANGE: i32 = -177;
pub const DROP_PROXY_LOOKUP_FAILED: i32 = -178;
pub const DROP_PROXY_SET_FAILED: i32 = -179;
pub const DROP_PROXY_UNKNOWN_PROTO: i32 = -180;
pub const DROP_POLICY_DENY: i32 = -181;
pub const DROP_VLAN_FILTERED: i32 = -182;
pub const DROP_INVALID_VNI: i32 = -183;
pub const DROP_INVALID_TC_BUFFER: i32 = -184;
pub const DROP_NO_SID: i32 = -185;
pub const DROP_MISSING_SRV6_STATE: i32 = -186;
pub const DROP_NAT46: i32 = -187;
pub const DROP_NAT64: i32 = -188;
pub const DROP_POLICY_AUTH_REQUIRED: i32 = -189;
pub const DROP_CT_NO_MAP_FOUND: i32 = -190;
pub const DROP_SNAT_NO_MAP_FOUND: i32 = -191;
pub const DROP_INVALID_CLUSTER_ID: i32 = -192;
pub const DROP_DSR_ENCAP_UNSUPP_PROTO: i32 = -193;
pub const DROP_NO_EGRESS_GATEWAY: i32 = -194;
pub const DROP_UNENCRYPTED_TRAFFIC: i32 = -195;
pub const DROP_TTL_EXCEEDED: i32 = -196;
pub const DROP_NO_NODE_ID: i32 = -197;
pub const DROP_RATE_LIMITED: i32 = -198;
pub const DROP_IGMP_HANDLED: i32 = -199;
pub const DROP_IGMP_SUBSCRIBED: i32 = -200;
pub const DROP_MULTICAST_HANDLED: i32 = -201;
pub const DROP_HOST_NOT_READY: i32 = -202;
pub const DROP_EP_NOT_READY: i32 = -203;