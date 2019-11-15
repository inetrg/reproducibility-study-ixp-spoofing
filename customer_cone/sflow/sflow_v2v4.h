/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon
 * sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_V2V4_H
#define SFLOW_V2V4_H 1

#if defined(__cplusplus)
extern "C" {
#endif

enum INMAddress_type { INMADDRESSTYPE_IP_V4 = 1, INMADDRESSTYPE_IP_V6 = 2 };

typedef union _INMAddress_value {
  SFLIPv4 ip_v4;
  SFLIPv6 ip_v6;
} INMAddress_value;

typedef struct _INMAddress {
  u_int32_t type; /* enum INMAddress_type */
  INMAddress_value address;
} INMAddress;

/* Packet header data */

#define INM_MAX_HEADER_SIZE 256 /* The maximum sampled header size. */
#define INM_DEFAULT_HEADER_SIZE 128
#define INM_DEFAULT_COLLECTOR_PORT 6343
#define INM_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum INMHeader_protocol {
  INMHEADER_ETHERNET_ISO8023 = 1,
  INMHEADER_ISO88024_TOKENBUS = 2,
  INMHEADER_ISO88025_TOKENRING = 3,
  INMHEADER_FDDI = 4,
  INMHEADER_FRAME_RELAY = 5,
  INMHEADER_X25 = 6,
  INMHEADER_PPP = 7,
  INMHEADER_SMDS = 8,
  INMHEADER_AAL5 = 9,
  INMHEADER_AAL5_IP = 10, /* e.g. Cisco AAL5 mux */
  INMHEADER_IPv4 = 11,
  INMHEADER_IPv6 = 12
};

typedef struct _INMSampled_header {
  u_int32_t header_protocol; /* (enum INMHeader_protocol) */
  u_int32_t frame_length;    /* Original length of packet before sampling */
  u_int32_t header_length;   /* length of sampled header bytes to follow */
  u_int8_t header[INM_MAX_HEADER_SIZE]; /* Header bytes */
} INMSampled_header;

/* Packet IP version 4 data */

typedef struct _INMSampled_ipv4 {
  u_int32_t length;    /* The length of the IP packet
                          excluding lower layer encapsulations */
  u_int32_t protocol;  /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv4 src_ip;      /* Source IP Address */
  SFLIPv4 dst_ip;      /* Destination IP Address */
  u_int32_t src_port;  /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;  /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags; /* TCP flags */
  u_int32_t tos;       /* IP type of service */
} INMSampled_ipv4;

/* Packet IP version 6 data */

typedef struct _INMSampled_ipv6 {
  u_int32_t length;    /* The length of the IP packet
                          excluding lower layer encapsulations */
  u_int32_t protocol;  /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv6 src_ip;      /* Source IP Address */
  SFLIPv6 dst_ip;      /* Destination IP Address */
  u_int32_t src_port;  /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;  /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags; /* TCP flags */
  u_int32_t tos;       /* IP type of service */
} INMSampled_ipv6;

typedef union _INMPacket_data_type {
  INMSampled_header header;
  INMSampled_ipv4 ipv4;
  INMSampled_ipv6 ipv6;
} INMPacket_data_type;

/* Extended data types */

/* Extended switch data */

typedef struct _INMExtended_switch {
  u_int32_t src_vlan;     /* The 802.1Q VLAN id of incomming frame */
  u_int32_t src_priority; /* The 802.1p priority */
  u_int32_t dst_vlan;     /* The 802.1Q VLAN id of outgoing frame */
  u_int32_t dst_priority; /* The 802.1p priority */
} INMExtended_switch;

/* Extended router data */

typedef struct _INMExtended_router {
  INMAddress nexthop; /* IP address of next hop router */
  u_int32_t src_mask; /* Source address prefix mask bits */
  u_int32_t dst_mask; /* Destination address prefix mask bits */
} INMExtended_router;

/* Extended gateway data */

enum INMExtended_as_path_segment_type {
  INMEXTENDED_AS_SET = 1,     /* Unordered set of ASs */
  INMEXTENDED_AS_SEQUENCE = 2 /* Ordered sequence of ASs */
};

typedef struct _INMExtended_as_path_segment {
  u_int32_t type;   /* enum INMExtended_as_path_segment_type */
  u_int32_t length; /* number of AS numbers in set/sequence */
  union {
    u_int32_t* set;
    u_int32_t* seq;
  } as;
} INMExtended_as_path_segment;

/* note: the INMExtended_gateway structure has changed between v2 and v4.
   Here is the old version first... */

typedef struct _INMExtended_gateway_v2 {
  u_int32_t as;                 /* AS number for this gateway */
  u_int32_t src_as;             /* AS number of source (origin) */
  u_int32_t src_peer_as;        /* AS number of source peer */
  u_int32_t dst_as_path_length; /* number of AS numbers in path */
  u_int32_t* dst_as_path;
} INMExtended_gateway_v2;

/* now here is the new version... */

typedef struct _INMExtended_gateway_v4 {
  u_int32_t as;                             /* AS number for this gateway */
  u_int32_t src_as;                         /* AS number of source (origin) */
  u_int32_t src_peer_as;                    /* AS number of source peer */
  u_int32_t dst_as_path_segments;           /* number of segments in path */
  INMExtended_as_path_segment* dst_as_path; /* list of seqs or sets */
  u_int32_t communities_length;             /* number of communities */
  u_int32_t* communities;                   /* set of communities */
  u_int32_t localpref; /* LocalPref associated with this route */
} INMExtended_gateway_v4;

/* Extended user data */
typedef struct _INMExtended_user {
  u_int32_t src_user_len;
  char* src_user;
  u_int32_t dst_user_len;
  char* dst_user;
} INMExtended_user;
enum INMExtended_url_direction {
  INMEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  INMEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _INMExtended_url {
  u_int32_t direction; /* enum INMExtended_url_direction */
  u_int32_t url_len;
  char* url;
} INMExtended_url;

/* Extended data */

enum INMExtended_information_type {
  INMEXTENDED_SWITCH = 1,  /* Extended switch information */
  INMEXTENDED_ROUTER = 2,  /* Extended router information */
  INMEXTENDED_GATEWAY = 3, /* Extended gateway router information */
  INMEXTENDED_USER = 4,    /* Extended TACAS/RADIUS user information */
  INMEXTENDED_URL = 5      /* Extended URL information */
};

/* Format of a single sample */

typedef struct _INMFlow_sample {
  u_int32_t sequence_number; /* Incremented with each flow sample
                                generated */
  u_int32_t source_id;       /* fsSourceId */
  u_int32_t sampling_rate;   /* fsPacketSamplingRate */
  u_int32_t sample_pool;     /* Total number of packets that could have been
                                sampled (i.e. packets skipped by sampling
                                process + total number of samples) */
  u_int32_t drops;           /* Number of times a packet was dropped due to
                                lack of resources */
  u_int32_t input;           /* SNMP ifIndex of input interface.
                                0 if interface is not known. */
  u_int32_t output;          /* SNMP ifIndex of output interface,
                                0 if interface is not known.
                                Set most significant bit to indicate
                                multiple destination interfaces
                                (i.e. in case of broadcast or multicast)
                                and set lower order bits to indicate
                                number of destination interfaces.
                                Examples:
                                0x00000002  indicates ifIndex = 2
                                0x00000000  ifIndex unknown.
                                0x80000007  indicates a packet sent
                                to 7 interfaces.
                                0x80000000  indicates a packet sent to
                                an unknown number of
                                interfaces greater than 1.*/
  u_int32_t packet_data_tag; /* enum INMPacket_information_type */
  INMPacket_data_type packet_data; /* Information about sampled packet */

  /* in the sFlow packet spec the next field is the number of extended objects
     followed by the data for each one (tagged with the type).  Here we just
     provide space for each one, and flags to enable them.  The correct format
     is then put together by the serialization code */
  int gotSwitch;
  INMExtended_switch switchDevice;
  int gotRouter;
  INMExtended_router router;
  int gotGateway;
  union {
    INMExtended_gateway_v2 v2; /* make the version explicit so that there is */
    INMExtended_gateway_v4 v4; /* less danger of mistakes when upgrading code */
  } gateway;
  int gotUser;
  INMExtended_user user;
  int gotUrl;
  INMExtended_url url;
} INMFlow_sample;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _INMIf_counters {
  u_int32_t ifIndex;
  u_int32_t ifType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection; /* Derived from MAU MIB (RFC 2239)
                            0 = unknown, 1 = full-duplex,
                            2 = half-duplex, 3 = in, 4 = out */
  u_int32_t ifStatus;    /* bit field with the following bits assigned:
                            bit 0 = ifAdminStatus (0 = down, 1 = up)
                            bit 1 = ifOperStatus (0 = down, 1 = up) */
  u_int64_t ifInOctets;
  u_int32_t ifInUcastPkts;
  u_int32_t ifInMulticastPkts;
  u_int32_t ifInBroadcastPkts;
  u_int32_t ifInDiscards;
  u_int32_t ifInErrors;
  u_int32_t ifInUnknownProtos;
  u_int64_t ifOutOctets;
  u_int32_t ifOutUcastPkts;
  u_int32_t ifOutMulticastPkts;
  u_int32_t ifOutBroadcastPkts;
  u_int32_t ifOutDiscards;
  u_int32_t ifOutErrors;
  u_int32_t ifPromiscuousMode;
} INMIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _INMEthernet_specific_counters {
  u_int32_t dot3StatsAlignmentErrors;
  u_int32_t dot3StatsFCSErrors;
  u_int32_t dot3StatsSingleCollisionFrames;
  u_int32_t dot3StatsMultipleCollisionFrames;
  u_int32_t dot3StatsSQETestErrors;
  u_int32_t dot3StatsDeferredTransmissions;
  u_int32_t dot3StatsLateCollisions;
  u_int32_t dot3StatsExcessiveCollisions;
  u_int32_t dot3StatsInternalMacTransmitErrors;
  u_int32_t dot3StatsCarrierSenseErrors;
  u_int32_t dot3StatsFrameTooLongs;
  u_int32_t dot3StatsInternalMacReceiveErrors;
  u_int32_t dot3StatsSymbolErrors;
} INMEthernet_specific_counters;

typedef struct _INMEthernet_counters {
  INMIf_counters generic;
  INMEthernet_specific_counters ethernet;
} INMEthernet_counters;

/* FDDI interface counters - see RFC 1512 */
typedef struct _INMFddi_counters {
  INMIf_counters generic;
} INMFddi_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _INMTokenring_specific_counters {
  u_int32_t dot5StatsLineErrors;
  u_int32_t dot5StatsBurstErrors;
  u_int32_t dot5StatsACErrors;
  u_int32_t dot5StatsAbortTransErrors;
  u_int32_t dot5StatsInternalErrors;
  u_int32_t dot5StatsLostFrameErrors;
  u_int32_t dot5StatsReceiveCongestions;
  u_int32_t dot5StatsFrameCopiedErrors;
  u_int32_t dot5StatsTokenErrors;
  u_int32_t dot5StatsSoftErrors;
  u_int32_t dot5StatsHardErrors;
  u_int32_t dot5StatsSignalLoss;
  u_int32_t dot5StatsTransmitBeacons;
  u_int32_t dot5StatsRecoverys;
  u_int32_t dot5StatsLobeWires;
  u_int32_t dot5StatsRemoves;
  u_int32_t dot5StatsSingles;
  u_int32_t dot5StatsFreqErrors;
} INMTokenring_specific_counters;

typedef struct _INMTokenring_counters {
  INMIf_counters generic;
  INMTokenring_specific_counters tokenring;
} INMTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _INMVg_specific_counters {
  u_int32_t dot12InHighPriorityFrames;
  u_int64_t dot12InHighPriorityOctets;
  u_int32_t dot12InNormPriorityFrames;
  u_int64_t dot12InNormPriorityOctets;
  u_int32_t dot12InIPMErrors;
  u_int32_t dot12InOversizeFrameErrors;
  u_int32_t dot12InDataErrors;
  u_int32_t dot12InNullAddressedFrames;
  u_int32_t dot12OutHighPriorityFrames;
  u_int64_t dot12OutHighPriorityOctets;
  u_int32_t dot12TransitionIntoTrainings;
  u_int64_t dot12HCInHighPriorityOctets;
  u_int64_t dot12HCInNormPriorityOctets;
  u_int64_t dot12HCOutHighPriorityOctets;
} INMVg_specific_counters;

typedef struct _INMVg_counters {
  INMIf_counters generic;
  INMVg_specific_counters vg;
} INMVg_counters;

/* WAN counters */

typedef struct _INMWan_counters {
  INMIf_counters generic;
} INMWan_counters;

typedef struct _INMVlan_counters {
  u_int32_t vlan_id;
  u_int64_t octets;
  u_int32_t ucastPkts;
  u_int32_t multicastPkts;
  u_int32_t broadcastPkts;
  u_int32_t discards;
} INMVlan_counters;

/* Counters data */

enum INMCounters_version {
  INMCOUNTERSVERSION_GENERIC = 1,
  INMCOUNTERSVERSION_ETHERNET = 2,
  INMCOUNTERSVERSION_TOKENRING = 3,
  INMCOUNTERSVERSION_FDDI = 4,
  INMCOUNTERSVERSION_VG = 5,
  INMCOUNTERSVERSION_WAN = 6,
  INMCOUNTERSVERSION_VLAN = 7
};

typedef union _INMCounters_type {
  INMIf_counters generic;
  INMEthernet_counters ethernet;
  INMTokenring_counters tokenring;
  INMFddi_counters fddi;
  INMVg_counters vg;
  INMWan_counters wan;
  INMVlan_counters vlan;
} INMCounters_type;

typedef struct _INMCounters_sample_hdr {
  u_int32_t sequence_number;   /* Incremented with each counters sample
                                  generated by this source_id */
  u_int32_t source_id;         /* fsSourceId */
  u_int32_t sampling_interval; /* fsCounterSamplingInterval */
} INMCounters_sample_hdr;

typedef struct _INMCounters_sample {
  INMCounters_sample_hdr hdr;
  u_int32_t counters_type_tag; /* Enum INMCounters_version */
  INMCounters_type counters;   /* Counter set for this interface type */
} INMCounters_sample;

typedef union _INMSample_type {
  INMFlow_sample flowsample;
  INMCounters_sample counterssample;
} INMSample_type;

/* Format of a sample datagram */

enum INMDatagram_version { INMDATAGRAM_VERSION2 = 2, INMDATAGRAM_VERSION4 = 4 };

typedef struct _INMSample_datagram_hdr {
  u_int32_t datagram_version; /* (enum INMDatagram_version) = VERSION4 */
  INMAddress agent_address;   /* IP address of sampling agent */
  u_int32_t sequence_number;  /* Incremented with each sample datagram
                                 generated */
  u_int32_t uptime;           /* Current time (in milliseconds since device
                                 last booted). Should be set as close to
                                 datagram transmission time as possible.*/
  u_int32_t num_samples; /* Number of flow and counters samples to follow */
} INMSample_datagram_hdr;

#define INM_MAX_DATAGRAM_SIZE 1500
#define INM_MIN_DATAGRAM_SIZE 200
#define INM_DEFAULT_DATAGRAM_SIZE 1400

#define INM_DATA_PAD 400

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* SFLOW_V2V4_H */
