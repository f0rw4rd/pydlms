"""COSEM interface-class registry (IEC 62056-6-2, Blue Book Part 2).

Maps ``(class_id, version)`` to the attribute and method names, so a GET result
can be labelled (Register attribute 2 is ``value``, 3 is ``scaler_unit``) and a
caller can address an attribute by name.

Hand-authored from the Blue Book class descriptions (clause 4.x of
IEC 62056-6-2 / Blue Book Ed. 12+). Only the attribute/method *names and
indices* are recorded; they are interface facts, not copied tables. Where a
class has several versions with the same leading attributes, only the version
this library has been checked against is listed, and :func:`lookup` falls back
to the highest known version not above the requested one. It never presents a
higher version as the requested one: when only higher versions are known, the
result is marked :attr:`InterfaceClass.approximate` (names usable, attribute
count unknown).

Lower versions are listed where the attribute count changed and two
independent implementations agree on it: Association LN v0 (8 attributes,
4 methods), v1 (adds ``security_setup_reference``) and v2 (adds
``user_list``, ``current_user`` and methods 5-6), and Security setup v0
(5 attributes, methods 1-2). Evidence: Gurux.DLMS.Net
``GXDLMSAssociationLogicalName.GetAttributeCount`` / ``GetMethodCount`` and
``GXDLMSSecuritySetup.GetNames`` / ``GetMethodNames`` (version-dependent), and
the jDLMS ``AssociationLnAttribute`` (9) / ``AssociationLnMethod`` (4) and
Security setup enums (5 / 2); both read as behavioural references only. The
Blue Book class-version clauses themselves were not checked.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import IntEnum

__all__ = ["ClassId", "InterfaceClass", "lookup", "attribute_name", "attribute_index", "REGISTRY"]


class ClassId(IntEnum):
    """Interface class identifiers (IEC 62056-6-2)."""

    DATA = 1
    REGISTER = 3
    EXTENDED_REGISTER = 4
    DEMAND_REGISTER = 5
    REGISTER_ACTIVATION = 6
    PROFILE_GENERIC = 7
    CLOCK = 8
    SCRIPT_TABLE = 9
    SCHEDULE = 10
    SPECIAL_DAYS_TABLE = 11
    ASSOCIATION_SN = 12
    ASSOCIATION_LN = 15
    SAP_ASSIGNMENT = 17
    IMAGE_TRANSFER = 18
    IEC_LOCAL_PORT_SETUP = 19
    ACTIVITY_CALENDAR = 20
    REGISTER_MONITOR = 21
    SINGLE_ACTION_SCHEDULE = 22
    IEC_HDLC_SETUP = 23
    IEC_TWISTED_PAIR_SETUP = 24
    MBUS_PORT_SETUP = 25
    UTILITY_TABLES = 26
    MODEM_CONFIGURATION = 27
    AUTO_ANSWER = 28
    AUTO_CONNECT = 29
    PUSH_SETUP = 40
    TCP_UDP_SETUP = 41
    IPV4_SETUP = 42
    MAC_ADDRESS_SETUP = 43
    PPP_SETUP = 44
    GPRS_MODEM_SETUP = 45
    SMTP_SETUP = 46
    GSM_DIAGNOSTIC = 47
    IPV6_SETUP = 48
    REGISTER_TABLE = 61
    COMPACT_DATA = 62
    STATUS_MAPPING = 63
    SECURITY_SETUP = 64
    PARAMETER_MONITOR = 65
    SENSOR_MANAGER = 67
    ARBITRATOR = 68
    DISCONNECT_CONTROL = 70
    LIMITER = 71
    MBUS_CLIENT = 72
    WIRELESS_MODE_Q_CHANNEL = 73
    MBUS_MASTER_PORT_SETUP = 74
    DLMS_MBUS_PORT_SETUP = 76
    MBUS_DIAGNOSTIC = 77
    ACCOUNT = 111
    CREDIT = 112
    CHARGE = 113
    TOKEN_GATEWAY = 115
    NTP_SETUP = 100
    DATA_PROTECTION = 30
    # Known by id and name only (no layout recorded; reads use attribute_<n>
    # names and raw Data): S-FSK, LLC, class 66 and ZigBee.
    # Class 66 id and name: Blue Book Ed. 17 Part 2 excerpt contents, 4.3.11.
    SFSK_PHY_MAC_SETUP = 50
    SFSK_ACTIVE_INITIATOR = 51
    SFSK_MAC_SYNC_TIMEOUTS = 52
    SFSK_MAC_COUNTERS = 53
    IEC_61334_4_32_LLC_SETUP = 55
    SFSK_REPORTING_SYSTEM_LIST = 56
    LLC_TYPE1_SETUP = 57
    LLC_TYPE2_SETUP = 58
    LLC_TYPE3_SETUP = 59
    MEASUREMENT_DATA_MONITORING = 66
    LLC_SSCS_SETUP = 80
    # PRIME (81-85) and G3-PLC (90-92) have layouts, single source (Gurux).
    PRIME_PHY_COUNTERS = 81
    PRIME_MAC_SETUP = 82
    PRIME_MAC_FUNCTIONAL_PARAMETERS = 83
    PRIME_MAC_COUNTERS = 84
    PRIME_MAC_NETWORK_ADMINISTRATION = 85
    # Class 86 is "PRIME NB OFDM PLC Application identification": DLMS UA
    # Blue Book Ed. 13 excerpt 4.12.11 (p. 101) and Ed. 17 Part 2 excerpt
    # contents; the PRIME MAC address setup is class 43 (MAC_ADDRESS_SETUP).
    # pydlms called 86 "PRIME MAC address setup" until 2026-10. No layout is
    # registered: the excerpts do not give the attributes.
    PRIME_APPLICATION_IDENTIFICATION = 86
    G3_MAC_COUNTERS = 90
    G3_MAC_SETUP = 91
    G3_6LOWPAN_SETUP = 92
    ZIGBEE_SAS_STARTUP = 101
    ZIGBEE_SAS_JOIN = 102
    ZIGBEE_SAS_APS_FRAGMENTATION = 103
    ZIGBEE_NETWORK_CONTROL = 104
    ZIGBEE_TUNNEL_SETUP = 105


@dataclass(frozen=True)
class InterfaceClass:
    """Attribute and method names of one interface-class version.

    Index 1 is always ``logical_name`` and is included in ``attributes``.
    """

    class_id: int
    version: int
    name: str
    attributes: tuple[str, ...]
    methods: tuple[str, ...] = ()
    _attr_index: dict[str, int] = field(default_factory=dict, compare=False, repr=False)
    #: True when :func:`lookup` had only a higher version than the requested
    #: one: the names label the shared attributes, the count is unknown.
    approximate: bool = field(default=False, compare=False)

    @property
    def attribute_count(self) -> int | None:
        """Number of attributes (``logical_name`` included); None if unknown."""
        return None if self.approximate else len(self.attributes)

    def __post_init__(self) -> None:
        self._attr_index.update({n: i for i, n in enumerate(self.attributes, start=1)})

    def attribute_name(self, index: int) -> str:
        if 1 <= index <= len(self.attributes):
            return self.attributes[index - 1]
        return f"attribute_{index}"

    def method_name(self, index: int) -> str:
        if 1 <= index <= len(self.methods):
            return self.methods[index - 1]
        return f"method_{index}"

    def attribute_index(self, name: str) -> int:
        try:
            return self._attr_index[name]
        except KeyError:
            raise KeyError(f"{self.name} v{self.version} has no attribute {name!r}") from None

    def method_index(self, name: str) -> int:
        try:
            return self.methods.index(name) + 1
        except ValueError:
            raise KeyError(f"{self.name} v{self.version} has no method {name!r}") from None


def _ic(class_id, version, name, attributes, methods=()):
    return InterfaceClass(int(class_id), version, name, ("logical_name", *attributes), methods)


_C = ClassId
#: G3-PLC 6LoWPAN setup attribute names (without logical_name), newest version.
_G3_6LOWPAN = [
    "max_hops",
    "weak_lqi_value",
    "security_level",
    "prefix_table",
    "routing_configuration",
    "broadcast_log_table_entry_ttl",
    "routing_table",
    "context_information_table",
    "blacklist_table",
    "broadcast_log_table",
    "group_table",
    "max_join_wait_time",
    "path_discovery_time",
    "active_key_index",
    "metric_type",
    "coord_short_address",
    "disable_default_routing",
    "device_type",
    "default_coord_route_enabled",
    "destination_address",
    "low_lqi",
    "high_lqi",
]

_CLASSES = [
    _ic(_C.DATA, 0, "Data", ["value"]),
    _ic(_C.REGISTER, 0, "Register", ["value", "scaler_unit"], ["reset"]),
    _ic(
        _C.EXTENDED_REGISTER,
        0,
        "Extended register",
        ["value", "scaler_unit", "status", "capture_time"],
        ["reset"],
    ),
    _ic(
        _C.DEMAND_REGISTER,
        0,
        "Demand register",
        [
            "current_average_value",
            "last_average_value",
            "scaler_unit",
            "status",
            "capture_time",
            "start_time_current",
            "period",
            "number_of_periods",
        ],
        ["reset", "next_period"],
    ),
    _ic(
        _C.REGISTER_ACTIVATION,
        0,
        "Register activation",
        ["register_assignment", "mask_list", "active_mask"],
        ["add_register", "add_mask", "delete_mask"],
    ),
    _ic(
        _C.PROFILE_GENERIC,
        1,
        "Profile generic",
        [
            "buffer",
            "capture_objects",
            "capture_period",
            "sort_method",
            "sort_object",
            "entries_in_use",
            "profile_entries",
        ],
        ["reset", "capture", "reserved_3", "reserved_4"],
    ),
    _ic(
        _C.CLOCK,
        0,
        "Clock",
        [
            "time",
            "time_zone",
            "status",
            "daylight_savings_begin",
            "daylight_savings_end",
            "daylight_savings_deviation",
            "daylight_savings_enabled",
            "clock_base",
        ],
        [
            "adjust_to_quarter",
            "adjust_to_measuring_period",
            "adjust_to_minute",
            "adjust_to_preset_time",
            "preset_adjusting_time",
            "shift_time",
        ],
    ),
    _ic(_C.SCRIPT_TABLE, 0, "Script table", ["scripts"], ["execute"]),
    _ic(_C.SCHEDULE, 0, "Schedule", ["entries"], ["enable_disable", "insert", "delete"]),
    _ic(_C.SPECIAL_DAYS_TABLE, 0, "Special days table", ["entries"], ["insert", "delete"]),
    _ic(
        _C.ASSOCIATION_SN,
        4,
        "Association SN",
        [
            "object_list",
            "access_rights_list",
            "security_setup_reference",
            "user_list",
            "current_user",
        ],
        # Method ids cross-checked with jDLMS (AssociationSnMethod: 3..6, 8)
        # and Gurux (8 SN method slots); 1, 2 and 7 are reserved.
        [
            "reserved_1",
            "reserved_2",
            "read_by_logicalname",
            "get_attributes_and_methods",
            "change_lls_secret",
            "change_hls_secret",
            "reserved_7",
            "reply_to_hls_authentication",
        ],
    ),
    *(
        _ic(
            _C.ASSOCIATION_LN,
            version,
            "Association LN",
            [
                "object_list",
                "associated_partners_id",
                "application_context_name",
                "xdlms_context_info",
                "authentication_mechanism_name",
                "secret",
                "association_status",
                *(["security_setup_reference"] if version >= 1 else []),
                *(["user_list", "current_user"] if version >= 2 else []),
            ],
            [
                "reply_to_hls_authentication",
                "change_hls_secret",
                "add_object",
                "remove_object",
                *(["add_user", "remove_user"] if version >= 2 else []),
            ],
        )
        for version in (0, 1, 2)
    ),
    _ic(
        _C.ASSOCIATION_LN,
        3,
        "Association LN",
        [
            "object_list",
            "associated_partners_id",
            "application_context_name",
            "xdlms_context_info",
            "authentication_mechanism_name",
            "secret",
            "association_status",
            "security_setup_reference",
            "user_list",
            "current_user",
        ],
        [
            "reply_to_hls_authentication",
            "change_hls_secret",
            "add_object",
            "remove_object",
            "add_user",
            "remove_user",
        ],
    ),
    _ic(
        _C.SAP_ASSIGNMENT, 0, "SAP assignment", ["sap_assignment_list"], ["connect_logical_device"]
    ),
    _ic(
        _C.IMAGE_TRANSFER,
        0,
        "Image transfer",
        [
            "image_block_size",
            "image_transferred_blocks_status",
            "image_first_not_transferred_block_number",
            "image_transfer_enabled",
            "image_transfer_status",
            "image_to_activate_info",
        ],
        ["image_transfer_initiate", "image_block_transfer", "image_verify", "image_activate"],
    ),
    _ic(
        _C.IEC_LOCAL_PORT_SETUP,
        1,
        "IEC local port setup",
        [
            "default_mode",
            "default_baud",
            "prop_baud",
            "response_time",
            "device_addr",
            "pass_p1",
            "pass_p2",
            "pass_w5",
        ],
    ),
    _ic(
        _C.ACTIVITY_CALENDAR,
        0,
        "Activity calendar",
        [
            "calendar_name_active",
            "season_profile_active",
            "week_profile_table_active",
            "day_profile_table_active",
            "calendar_name_passive",
            "season_profile_passive",
            "week_profile_table_passive",
            "day_profile_table_passive",
            "activate_passive_calendar_time",
        ],
        ["activate_passive_calendar"],
    ),
    _ic(
        _C.REGISTER_MONITOR,
        0,
        "Register monitor",
        ["thresholds", "monitored_value", "actions"],
    ),
    _ic(
        _C.SINGLE_ACTION_SCHEDULE,
        0,
        "Single action schedule",
        ["executed_script", "type", "execution_time"],
    ),
    _ic(
        _C.IEC_HDLC_SETUP,
        1,
        "IEC HDLC setup",
        [
            "comm_speed",
            "window_size_transmit",
            "window_size_receive",
            "max_info_field_length_transmit",
            "max_info_field_length_receive",
            "inter_octet_time_out",
            "inactivity_time_out",
            "device_address",
        ],
    ),
    _ic(
        _C.UTILITY_TABLES,
        0,
        "Utility tables",
        ["table_id", "length", "buffer"],
    ),
    _ic(
        _C.AUTO_CONNECT,
        2,
        "Auto connect",
        ["mode", "repetitions", "repetition_delay", "calling_window", "destination_list"],
        ["connect"],
    ),
    _ic(
        _C.PUSH_SETUP,
        2,
        "Push setup",
        [
            "push_object_list",
            "send_destination_and_method",
            "communication_window",
            "randomisation_start_interval",
            "number_of_retries",
            "repetition_delay",
            "port_reference",
            "push_client_sap",
            "push_protection_parameters",
            "push_operation_method",
            "confirmation_parameters",
            "last_confirmation_date_time",
        ],
        ["push", "reset"],
    ),
    _ic(
        _C.TCP_UDP_SETUP,
        0,
        "TCP-UDP setup",
        ["tcp_udp_port", "ip_reference", "mss", "nb_of_sim_conn", "inactivity_time_out"],
    ),
    _ic(
        _C.IPV4_SETUP,
        0,
        "IPv4 setup",
        [
            "dl_reference",
            "ip_address",
            "multicast_ip_address",
            "ip_options",
            "subnet_mask",
            "gateway_ip_address",
            "use_dhcp_flag",
            "primary_dns_address",
            "secondary_dns_address",
        ],
        ["add_mc_ip_address", "delete_mc_ip_address", "get_nbof_mc_ip_addresses"],
    ),
    _ic(_C.MAC_ADDRESS_SETUP, 0, "MAC address setup", ["mac_address"]),
    _ic(
        _C.GPRS_MODEM_SETUP,
        0,
        "GPRS modem setup",
        ["apn", "pin_code", "quality_of_service"],
    ),
    _ic(
        _C.GSM_DIAGNOSTIC,
        1,
        "GSM diagnostic",
        [
            "operator",
            "status",
            "cs_attachment",
            "ps_status",
            "cell_info",
            "adjacent_cells",
            "capture_time",
        ],
    ),
    _ic(
        _C.REGISTER_TABLE,
        0,
        "Register table",
        ["table_cell_values", "table_cell_definition", "scaler_unit"],
        ["reset", "capture"],
    ),
    _ic(
        _C.COMPACT_DATA,
        1,
        "Compact data",
        [
            "compact_buffer",
            "capture_objects",
            "template_id",
            "template_description",
            "capture_method",
        ],
        ["reset", "capture"],
    ),
    _ic(_C.STATUS_MAPPING, 0, "Status mapping", ["status_word", "mapping_table"]),
    _ic(
        _C.SECURITY_SETUP,
        0,
        "Security setup",
        ["security_policy", "security_suite", "client_system_title", "server_system_title"],
        ["security_activate", "key_transfer"],
    ),
    _ic(
        _C.SECURITY_SETUP,
        1,
        "Security setup",
        [
            "security_policy",
            "security_suite",
            "client_system_title",
            "server_system_title",
            "certificates",
        ],
        [
            "security_activate",
            "key_transfer",
            "key_agreement",
            "generate_key_pair",
            "generate_certificate_request",
            "import_certificate",
            "export_certificate",
            "remove_certificate",
        ],
    ),
    _ic(
        _C.DISCONNECT_CONTROL,
        0,
        "Disconnect control",
        ["output_state", "control_state", "control_mode"],
        ["remote_disconnect", "remote_reconnect"],
    ),
    _ic(
        _C.LIMITER,
        0,
        "Limiter",
        [
            "monitored_value",
            "threshold_active",
            "threshold_normal",
            "threshold_emergency",
            "min_over_threshold_duration",
            "min_under_threshold_duration",
            "emergency_profile",
            "emergency_profile_group_id_list",
            "emergency_profile_active",
            "actions",
        ],
    ),
    _ic(
        _C.MBUS_CLIENT,
        1,
        "M-Bus client",
        [
            "mbus_port_reference",
            "capture_definition",
            "capture_period",
            "primary_address",
            "identification_number",
            "manufacturer_id",
            "version",
            "device_type",
            "access_number",
            "status",
            "alarm",
            "configuration",
            "encryption_key_status",
        ],
        [
            "slave_install",
            "slave_deinstall",
            "capture",
            "reset_alarm",
            "synchronize_clock",
            "data_send",
            "set_encryption_key",
            "transfer_key",
        ],
    ),
    _ic(
        _C.NTP_SETUP,
        0,
        "NTP setup",
        [
            "activated",
            "server_address",
            "server_port",
            "authentication_method",
            "authentication_keys",
            "client_key",
        ],
        ["synchronize", "add_authentication_key", "delete_authentication_key"],
    ),
]

# Classes added from the Blue Book class descriptions (recollection; attribute
# order checked for internal consistency only - verify against the document
# before relying on an index).
_CLASSES += [
    _ic(
        _C.MBUS_PORT_SETUP,
        0,
        "M-Bus slave port setup",
        ["default_baud", "avail_baud", "addr_state", "bus_address"],
    ),
    _ic(
        _C.MODEM_CONFIGURATION,
        1,
        "Modem configuration",
        ["comm_speed", "initialization_string", "modem_profile"],
    ),
    _ic(
        _C.AUTO_ANSWER,
        2,
        "Auto answer",
        [
            "mode",
            "listening_window",
            "status",
            "number_of_calls",
            "number_of_rings",
            "list_of_allowed_callers",
        ],
    ),
    _ic(
        _C.PPP_SETUP,
        0,
        "PPP setup",
        ["phy_reference", "lcp_options", "ipcp_options", "ppp_authentication"],
    ),
    _ic(
        _C.SMTP_SETUP,
        0,
        "SMTP setup",
        ["server_port", "user_name", "login_password", "server_address", "sender_address"],
    ),
    _ic(
        _C.IPV6_SETUP,
        0,
        "IPv6 setup",
        [
            "dl_reference",
            "address_config_mode",
            "unicast_ipv6_addresses",
            "multicast_ipv6_addresses",
            "gateway_ipv6_addresses",
            "primary_dns_address",
            "secondary_dns_address",
            "traffic_class",
            "neighbor_discovery_setup",
        ],
        ["add_ipv6_address", "remove_ipv6_address"],
    ),
    _ic(
        _C.ARBITRATOR,
        0,
        "Arbitrator",
        [
            "actions",
            "permissions_table",
            "weightings_table",
            "most_recent_requests_table",
            "last_outcome",
        ],
        ["request_action", "reset"],
    ),
    _ic(_C.MBUS_MASTER_PORT_SETUP, 0, "M-Bus master port setup", ["comm_speed"]),
    _ic(
        _C.MBUS_DIAGNOSTIC,
        0,
        "M-Bus diagnostic",
        [
            "received_signal_strength",
            "channel_id",
            "link_status",
            "broadcast_frames_counter",
            "transmissions_counter",
            "frames_received_correctly",
            "failed_receptions",
            "capture_time",
        ],
        ["reset"],
    ),
    _ic(
        _C.ACCOUNT,
        0,
        "Account",
        [
            "account_mode_and_status",
            "current_credit_in_use",
            "current_credit_status",
            "available_credit",
            "amount_to_clear",
            "clearance_threshold",
            "aggregated_debt",
            "credit_reference_list",
            "charge_reference_list",
            "credit_charge_configuration",
            "token_gateway_configuration",
            "account_activation_time",
            "account_closure_time",
            "currency",
            "low_credit_threshold",
            "next_credit_available_threshold",
            "max_provision",
            "max_provision_period",
        ],
        ["activate_account", "close_account", "reset_account"],
    ),
    _ic(
        _C.CREDIT,
        0,
        "Credit",
        [
            "current_credit_amount",
            "credit_type",
            "priority",
            "warning_threshold",
            "limit",
            "credit_configuration",
            "credit_status",
            "preset_credit_amount",
            "credit_available_threshold",
            "period",
        ],
        ["update_amount", "set_amount_to_value", "invoke_credit"],
    ),
    _ic(
        _C.CHARGE,
        0,
        "Charge",
        [
            "total_amount_paid",
            "charge_type",
            "priority",
            "unit_charge_active",
            "unit_charge_passive",
            "unit_charge_activation_time",
            "period",
            "charge_configuration",
            "last_collection_time",
            "last_collection_amount",
            "total_amount_remaining",
            "proportion",
        ],
        [
            "update_unit_charge",
            "activate_passive_unit_charge",
            "collect",
            "update_total_amount_remaining",
            "set_total_amount_remaining",
        ],
    ),
    _ic(
        _C.TOKEN_GATEWAY,
        0,
        "Token gateway",
        ["token", "token_time", "token_description", "token_delivery_method", "token_status"],
        ["enter"],
    ),
    # --- data protection, PRIME and G3-PLC ---------------------------------
    # Sources: Gurux.DLMS.Net Development/Objects GXDLMS*.cs and the Gurux C
    # library gxobjects.c (counts and order; one vendor, two code bases, so not
    # independent). Class 30 is also confirmed by Wireshark packet-cosem.c.
    # Class 30 attributes and methods, class 91 version 2 attributes 1-9 and
    # 11-25, and class 92 version 2 attributes 1-21 agree with DLMS UA 1000-1
    # Ed. 13 Excerpt 4.4.9.2 and 4.13.4/4.13.5 (Ed. 13 names attribute 10 of
    # class 91 v2 mac_POS_table_entry_TTL). Class 91 v3 (attribute 26), class
    # 92 v0/v1/v3 and the PRIME attribute lists are not in the public
    # excerpts: single source, unverified. DLMS UA 1000-1 Ed. 11 Excerpt
    # 4.11.5-4.11.9 confirms the PRIME class ids 81-85, version 0 each, and
    # that the attributes of 81 and 84 are read only and reset by the reset
    # method. The names are hand-written snake_case.
    _ic(
        _C.DATA_PROTECTION,
        0,
        "Data protection",
        [
            "protection_buffer",
            "protection_object_list",
            "protection_parameters_get",
            "protection_parameters_set",
            "required_protection",
        ],
        ["get_protected_attributes", "set_protected_attributes", "invoke_protected_method"],
    ),
    _ic(
        _C.PRIME_PHY_COUNTERS,
        0,
        "PRIME NB OFDM PLC physical layer counters",
        ["crc_incorrect_count", "crc_failed_count", "tx_drop_count", "rx_drop_count"],
        ["reset"],
    ),
    _ic(
        _C.PRIME_MAC_SETUP,
        0,
        "PRIME NB OFDM PLC MAC setup",
        [
            "mac_min_switch_search_time",
            "mac_max_promotion_pdu",
            "mac_promotion_pdu_tx_period",
            "mac_beacons_per_frame",
            "mac_scp_max_tx_attempts",
            "mac_ctl_re_tx_timer",
            "mac_max_ctl_re_tx",
        ],
    ),
    _ic(
        _C.PRIME_MAC_FUNCTIONAL_PARAMETERS,
        0,
        "PRIME NB OFDM PLC MAC functional parameters",
        [
            "lnid",
            "lsid",
            "sid",
            "sna",
            "state",
            "scp_length",
            "node_hierarchy_level",
            "beacon_slot_count",
            "beacon_rx_slot",
            "beacon_tx_slot",
            "beacon_rx_frequency",
            "beacon_tx_frequency",
            "capabilities",
        ],
    ),
    _ic(
        _C.PRIME_MAC_COUNTERS,
        0,
        "PRIME NB OFDM PLC MAC counters",
        [
            "tx_data_pkt_count",
            "rx_data_pkt_count",
            "tx_ctrl_pkt_count",
            "rx_ctrl_pkt_count",
            "csma_fail_count",
            "csma_ch_busy_count",
        ],
        ["reset"],
    ),
    _ic(
        _C.PRIME_MAC_NETWORK_ADMINISTRATION,
        0,
        "PRIME NB OFDM PLC MAC network administration data",
        [
            "multicast_entries",
            "switch_table",
            "direct_table",
            "available_switches",
            "communications",
        ],
        ["reset"],
    ),
    _ic(
        _C.G3_MAC_COUNTERS,
        1,
        "G3-PLC MAC layer counters",
        [
            "tx_data_packet_count",
            "rx_data_packet_count",
            "tx_cmd_packet_count",
            "rx_cmd_packet_count",
            "csma_fail_count",
            "csma_no_ack_count",
            "bad_crc_count",
            "tx_data_broadcast_count",
            "rx_data_broadcast_count",
        ],
        ["reset"],
    ),
    # Only the newest version Gurux describes is registered: its older
    # counts (22 and 25 attributes) are given but which attributes they lack
    # is only implied, so lookup() marks lower versions approximate.
    _ic(
        _C.G3_MAC_SETUP,
        3,
        "G3-PLC MAC setup",
        [
            "mac_short_address",
            "mac_rc_coord",
            "mac_pan_id",
            "mac_key_table",
            "mac_frame_counter",
            "mac_tone_mask",
            "mac_tmr_ttl",
            "mac_max_frame_retries",
            "mac_neighbour_table_entry_ttl",
            "mac_neighbour_table",
            "mac_high_priority_window_size",
            "mac_csma_fairness_limit",
            "mac_beacon_randomization_window_length",
            "mac_a",
            "mac_k",
            "mac_min_cw_attempts",
            "mac_cenelec_legacy_mode",
            "mac_fcc_legacy_mode",
            "mac_max_be",
            "mac_max_csma_backoffs",
            "mac_min_be",
            "mac_broadcast_max_cw_enabled",
            "mac_transmit_atten",
            "mac_pos_table",
            "mac_duplicate_detection_ttl",
        ],
        ["mac_get_neighbour_table_entry", "mac_get_pos_table_entry"],
    ),
    # Versions 0-3 add trailing attributes only (16, 19, 21, 23 attributes).
    *[
        _ic(_C.G3_6LOWPAN_SETUP, version, "G3-PLC 6LoWPAN adaptation layer setup", names)
        for version, names in enumerate(
            (_G3_6LOWPAN[:15], _G3_6LOWPAN[:18], _G3_6LOWPAN[:20], _G3_6LOWPAN)
        )
    ],
]

#: ``(class_id, version) -> InterfaceClass``.
REGISTRY: dict[tuple[int, int], InterfaceClass] = {(c.class_id, c.version): c for c in _CLASSES}


def lookup(class_id: int, version: int | None = None) -> InterfaceClass | None:
    """Find the class description, falling back to the nearest lower version.

    Without ``version`` the newest known one. When every known version is
    higher than ``version`` the lowest is returned with ``approximate=True``.
    """
    candidates = sorted(v for (cid, v) in REGISTRY if cid == int(class_id))
    if not candidates:
        return None
    if version is None:
        return REGISTRY[(int(class_id), candidates[-1])]
    eligible = [v for v in candidates if v <= version]
    if not eligible:
        # Only higher versions are known: their extra attributes may not exist.
        return dataclasses.replace(REGISTRY[(int(class_id), candidates[0])], approximate=True)
    return REGISTRY[(int(class_id), eligible[-1])]


def attribute_name(class_id: int, index: int, version: int | None = None) -> str:
    """Name of attribute ``index``; ``attribute_<n>`` for unknown classes/indices."""
    ic = lookup(class_id, version)
    if ic is None:
        return "logical_name" if index == 1 else f"attribute_{index}"
    return ic.attribute_name(index)


def attribute_index(class_id: int, name: str, version: int | None = None) -> int:
    """Index of the named attribute; raises :class:`KeyError` if unknown."""
    ic = lookup(class_id, version)
    if ic is None:
        raise KeyError(f"unknown interface class {class_id}")
    return ic.attribute_index(name)
