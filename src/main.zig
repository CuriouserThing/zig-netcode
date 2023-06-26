const std = @import("std");

pub const Error = error{
    LibraryError,
    NegativeIndex,
    InvalidIpVersion,
};

// =====================================================================================================================
// DEFINES

pub const CONNECT_TOKEN_BYTES = 2048;
pub const KEY_BYTES = 32;
pub const MAC_BYTES = 16;
pub const USER_DATA_BYTES = 256;
pub const MAX_SERVERS_PER_CONNECT = 32;

pub const ClientState = enum(i16) {
    connect_token_expied = -6,
    invalid_connect_token = -5,
    connection_timed_out = -4,
    connection_response_timed_out = -3,
    connection_request_timed_out = -2,
    connection_denied = -1,
    disconnected = 0,
    sending_connection_request = 1,
    sending_connection_response = 2,
    connected = 3,

    pub fn isErrored(state: ClientState) bool {
        return @enumToInt(state) < 0;
    }
};

pub const MAX_CLIENTS = 256;
pub const MAX_PACKET_SIZE = 1200;

const LOG_LEVEL_NONE = 0;
const LOG_LEVEL_ERROR = 1;
const LOG_LEVEL_INFO = 2;
const LOG_LEVEL_DEBUG = 3;

const OK = 1;
const ERROR = 0;

const ADDRESS_NONE = 0;
const ADDRESS_IPV4 = 1;
const ADDRESS_IPV6 = 2;

// =====================================================================================================================
// GLOBAL EXTERN

extern fn netcode_init(...) c_int;
extern fn netcode_term(...) void;
const union_unnamed_1 = extern union {
    ipv4: [4]u8,
    ipv6: [8]u16,
};
const struct_netcode_address_t = extern struct {
    data: union_unnamed_1,
    port: u16,
    type: u8,
};
extern fn netcode_parse_address([*c]u8, [*c]struct_netcode_address_t) c_int;
extern fn netcode_address_to_string([*c]struct_netcode_address_t, [*c]u8) [*c]u8;
extern fn netcode_address_equal([*c]struct_netcode_address_t, [*c]struct_netcode_address_t) c_int;
const struct_netcode_network_simulator_t = opaque {};
const struct_netcode_client_config_t = extern struct {
    allocator_context: ?*anyopaque,
    allocate_function: ?*const fn (?*anyopaque, u64) callconv(.C) ?*anyopaque,
    free_function: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.C) void,
    network_simulator: ?*struct_netcode_network_simulator_t,
    callback_context: ?*anyopaque,
    state_change_callback: ?*const fn (?*anyopaque, c_int, c_int) callconv(.C) void,
    send_loopback_packet_callback: ?*const fn (?*anyopaque, c_int, [*c]u8, c_int, u64) callconv(.C) void,
    override_send_and_receive: c_int,
    send_packet_override: ?*const fn (?*anyopaque, [*c]struct_netcode_address_t, [*c]u8, c_int) callconv(.C) void,
    receive_packet_override: ?*const fn (?*anyopaque, [*c]struct_netcode_address_t, [*c]u8, c_int) callconv(.C) c_int,
};
extern fn netcode_default_client_config([*c]struct_netcode_client_config_t) void;
extern fn netcode_generate_connect_token(c_int, [*c][*c]u8, [*c][*c]u8, c_int, c_int, u64, u64, [*c]u8, [*c]u8, [*c]u8) c_int;
const struct_netcode_server_config_t = extern struct {
    protocol_id: u64,
    private_key: [32]u8,
    allocator_context: ?*anyopaque,
    allocate_function: ?*const fn (?*anyopaque, u64) callconv(.C) ?*anyopaque,
    free_function: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.C) void,
    network_simulator: ?*struct_netcode_network_simulator_t,
    callback_context: ?*anyopaque,
    connect_disconnect_callback: ?*const fn (?*anyopaque, c_int, c_int) callconv(.C) void,
    send_loopback_packet_callback: ?*const fn (?*anyopaque, c_int, [*c]u8, c_int, u64) callconv(.C) void,
    override_send_and_receive: c_int,
    send_packet_override: ?*const fn (?*anyopaque, [*c]struct_netcode_address_t, [*c]u8, c_int) callconv(.C) void,
    receive_packet_override: ?*const fn (?*anyopaque, [*c]struct_netcode_address_t, [*c]u8, c_int) callconv(.C) c_int,
};
extern fn netcode_default_server_config([*c]struct_netcode_server_config_t) void;
extern fn netcode_log_level(c_int) void;
extern fn netcode_set_printf_function(?*const fn ([*c]u8, ...) callconv(.C) c_int) void;
extern var netcode_assert_function: ?*const fn ([*c]u8, [*c]u8, [*c]u8, c_int) callconv(.C) void;
extern fn netcode_set_assert_function(?*const fn ([*c]u8, [*c]u8, [*c]u8, c_int) callconv(.C) void) void;
extern fn netcode_random_bytes([*c]u8, c_int) void;
extern fn netcode_sleep(f64) void;
extern fn netcode_time(...) f64;

// =====================================================================================================================

pub fn init() !void {
    if (netcode_init() != OK) return Error.LibraryError;
}

pub fn term() void {
    netcode_term();
}

const IpVersion = enum { ipv4, ipv6 };
pub const AddressData = union(IpVersion) {
    ipv4: [4]u8,
    ipv6: [8]u16,
};
pub const Address = struct {
    data: AddressData,
    port: u16,

    fn fromNative(address: struct_netcode_address_t) !Address {
        if (address.type == ADDRESS_IPV4) {
            return .{
                .data = .{ .ipv4 = address.data.ipv4 },
                .port = address.port,
            };
        } else if (address.type == ADDRESS_IPV6) {
            return .{
                .data = .{ .ipv6 = address.data.ipv6 },
                .port = address.port,
            };
        } else return Error.InvalidIpVersion;
    }

    fn toNative(address: Address) struct_netcode_address_t {
        return switch (AddressData) {
            .ipv4 => |ip| .{
                .data = .{ .ipv4 = ip },
                .port = address.port,
                .type = ADDRESS_IPV4,
            },
            .ipv6 => |ip| .{
                .data = .{ .ipv6 = ip },
                .port = address.port,
                .type = ADDRESS_IPV6,
            },
        };
    }
};

pub fn parseAddress(address_string_in: [*:0]u8) ?Address {
    var address: struct_netcode_address_t = undefined;
    if (netcode_parse_address(address_string_in, &address) == OK) {
        return Address.fromNative(address);
    } else {
        return null;
    }
}

pub fn addressToString(address: [*:0]u8, buffer: []u8) []const u8 {
    return netcode_address_to_string(address, buffer.ptr);
}

pub fn addressEqual(a: Address, b: Address) bool {
    return netcode_address_equal(Address.toNative(a), Address.toNative(b)) != 0;
}

pub const ClientConfig = struct_netcode_client_config_t;

pub fn defaultClientConfig() ClientConfig {
    var config: ClientConfig = undefined;
    netcode_default_client_config(&config);
    return config;
}

/// Errors if the public and internal address lists have different lengths.
pub fn generateConnectToken(
    public_server_addresses: []?[*:0]u8,
    internal_server_addresses: []?[*:0]u8,
    expire_seconds: i32,
    timeout_seconds: i32,
    client_id: u64,
    protocol_id: u64,
    private_key: *[KEY_BYTES]u8,
    user_data: *[USER_DATA_BYTES]u8,
    connect_token: *[CONNECT_TOKEN_BYTES]u8,
) !void {
    if (public_server_addresses.len != internal_server_addresses.len) return Error.LibraryError;
    const len = @intCast(c_int, public_server_addresses.len);
    const code = netcode_generate_connect_token(len, public_server_addresses.ptr, internal_server_addresses.ptr, expire_seconds, timeout_seconds, client_id, protocol_id, private_key, user_data, connect_token);
    if (code != OK) return Error.LibraryError;
}

pub const ServerConfig = struct_netcode_server_config_t;

pub fn defaultServerConfig() ServerConfig {
    var config: ServerConfig = undefined;
    netcode_default_server_config(&config);
    return config;
}

pub fn logLevel(level: ?std.log.Level) void {
    if (level) |l| {
        // netcode.io has no "warnings", so demote to info
        netcode_log_level(switch (l) {
            .err => LOG_LEVEL_ERROR,
            .warn, .info => LOG_LEVEL_INFO,
            .debug => LOG_LEVEL_DEBUG,
        });
    } else {
        netcode_log_level(LOG_LEVEL_NONE);
    }
}

pub fn setPrintfFunction(function: ?*const fn ([*c]u8, ...) callconv(.C) c_int) void {
    netcode_set_printf_function(function);
}

pub fn setAssertFunction(function: ?*const fn ([*c]u8, [*c]u8, [*c]u8, c_int) callconv(.C) void) void {
    netcode_set_assert_function(function);
}

pub fn randomBytes(data: []u8) void {
    netcode_random_bytes(data.ptr, @intCast(c_int, data.len));
}

pub fn sleep(seconds: f64) void {
    netcode_sleep(seconds);
}

pub fn time() f64 {
    return netcode_time();
}

// =====================================================================================================================
pub const Client = opaque {
    extern fn netcode_client_create([*c]u8, [*c]struct_netcode_client_config_t, f64) ?*Client;
    extern fn netcode_client_destroy(?*Client) void;
    extern fn netcode_client_connect(?*Client, [*c]u8) void;
    extern fn netcode_client_update(?*Client, f64) void;
    extern fn netcode_client_next_packet_sequence(?*Client) u64;
    extern fn netcode_client_send_packet(?*Client, [*c]u8, c_int) void;
    extern fn netcode_client_receive_packet(?*Client, [*c]c_int, [*c]u64) [*c]u8;
    extern fn netcode_client_free_packet(?*Client, ?*anyopaque) void;
    extern fn netcode_client_disconnect(?*Client) void;
    extern fn netcode_client_state(?*Client) c_int;
    extern fn netcode_client_index(?*Client) c_int;
    extern fn netcode_client_max_clients(?*Client) c_int;
    extern fn netcode_client_connect_loopback(?*Client, c_int, c_int) void;
    extern fn netcode_client_disconnect_loopback(?*Client) void;
    extern fn netcode_client_process_packet(?*Client, [*c]struct_netcode_address_t, [*c]u8, c_int) void;
    extern fn netcode_client_loopback(?*Client) c_int;
    extern fn netcode_client_process_loopback_packet(?*Client, [*c]u8, c_int, u64) void;
    extern fn netcode_client_get_port(?*Client) u16;
    extern fn netcode_client_server_address(?*Client) [*c]struct_netcode_address_t;

    pub fn create(address: [*:0]u8, config: *ClientConfig, timestamp: f64) ?*Client {
        return netcode_client_create(address, config, timestamp);
    }

    pub fn destroy(client: *Client) void {
        netcode_client_destroy(client);
    }

    pub fn connect(client: *Client, connect_token: *[CONNECT_TOKEN_BYTES]u8) void {
        netcode_client_connect(client, connect_token);
    }

    pub fn update(client: *Client, timestamp: f64) void {
        netcode_client_update(client, timestamp);
    }

    pub fn nextPacketSequence(client: *Client) u64 {
        return netcode_client_next_packet_sequence(client);
    }

    pub fn sendPacket(client: *Client, packet_data: []u8) void {
        netcode_client_send_packet(client, packet_data.ptr, @intCast(c_int, packet_data.len));
    }

    pub fn receivePacket(client: *Client, packet_sequence: *u64) !?[]u8 {
        var len: c_int = 0;
        var packet = netcode_client_receive_packet(client, &len, packet_sequence);
        if (len < 0) return Error.NegativeIndex;
        return if (packet == null) null else packet[0..@intCast(usize, len)];
    }

    pub fn freePacket(client: *Client, packet: []u8) void {
        netcode_client_free_packet(client, packet.ptr);
    }

    pub fn disconnect(client: *Client) void {
        netcode_client_disconnect(client);
    }

    pub fn state(client: *Client) ClientState {
        return @intToEnum(ClientState, netcode_client_state(client));
    }

    pub fn index(client: *Client) !usize {
        const idx = netcode_client_index(client);
        return if (idx < 0) Error.NegativeIndex else @intCast(usize, idx);
    }

    pub fn maxClients(client: *Client) usize {
        const max = netcode_client_max_clients(client);
        return if (max < 0) Error.NegativeIndex else return max;
    }

    pub fn connectLoopback(client: *Client, client_index: usize, max_clients: usize) void {
        netcode_client_connect_loopback(client, @intCast(c_int, client_index), @intCast(c_int, max_clients));
    }

    pub fn disconnectLoopback(client: *Client) void {
        netcode_client_disconnect_loopback(client);
    }

    pub fn processPacket(client: *Client, from: Address, packet_data: []u8) void {
        netcode_client_process_packet(client, &from.toNative(), packet_data.ptr, @intCast(c_int, packet_data.len));
    }

    pub fn loopback(client: *Client) bool {
        return netcode_client_loopback(client) != 0;
    }

    pub fn processLoopbackPacket(client: *Client, packet_data: []u8, packet_sequence: u64) void {
        netcode_client_process_loopback_packet(client, packet_data.ptr, @intCast(c_int, packet_data.len), packet_sequence);
    }

    pub fn getPort(client: *Client) u16 {
        return netcode_client_get_port(client);
    }

    pub fn serverAddress(client: *Client) !Address {
        if (netcode_client_server_address(client)) |address| {
            return Address.fromNative(address.*);
        } else {
            return Error.LibraryError;
        }
    }
};

// =====================================================================================================================
pub const Server = opaque {
    extern fn netcode_server_create([*c]u8, [*c]struct_netcode_server_config_t, f64) ?*Server;
    extern fn netcode_server_destroy(?*Server) void;
    extern fn netcode_server_start(?*Server, c_int) void;
    extern fn netcode_server_stop(?*Server) void;
    extern fn netcode_server_running(?*Server) c_int;
    extern fn netcode_server_max_clients(?*Server) c_int;
    extern fn netcode_server_update(?*Server, f64) void;
    extern fn netcode_server_client_connected(?*Server, c_int) c_int;
    extern fn netcode_server_client_id(?*Server, c_int) u64;
    extern fn netcode_server_client_address(?*Server, c_int) [*c]struct_netcode_address_t;
    extern fn netcode_server_disconnect_client(?*Server, c_int) void;
    extern fn netcode_server_disconnect_all_clients(?*Server) void;
    extern fn netcode_server_next_packet_sequence(?*Server, c_int) u64;
    extern fn netcode_server_send_packet(?*Server, c_int, [*c]u8, c_int) void;
    extern fn netcode_server_receive_packet(?*Server, c_int, [*c]c_int, [*c]u64) [*c]u8;
    extern fn netcode_server_free_packet(?*Server, ?*anyopaque) void;
    extern fn netcode_server_num_connected_clients(?*Server) c_int;
    extern fn netcode_server_client_user_data(?*Server, c_int) ?*anyopaque;
    extern fn netcode_server_process_packet(?*Server, [*c]struct_netcode_address_t, [*c]u8, c_int) void;
    extern fn netcode_server_connect_loopback_client(?*Server, c_int, u64, [*c]u8) void;
    extern fn netcode_server_disconnect_loopback_client(?*Server, c_int) void;
    extern fn netcode_server_client_loopback(?*Server, c_int) c_int;
    extern fn netcode_server_process_loopback_packet(?*Server, c_int, [*c]u8, c_int, u64) void;
    extern fn netcode_server_get_port(?*Server) u16;

    pub fn create(server_address: [*:0]u8, config: *ServerConfig, timestamp: f64) ?*Server {
        return netcode_server_create(server_address, config, timestamp);
    }

    pub fn destroy(server: *Server) void {
        netcode_server_destroy(server);
    }

    pub fn start(server: *Server, max_clients: usize) void {
        netcode_server_start(server, @intCast(c_int, max_clients));
    }

    pub fn stop(server: *Server) void {
        netcode_server_stop(server);
    }

    pub fn running(server: *Server) bool {
        return netcode_server_running(server) != 0;
    }

    pub fn maxClients(server: *Server) !usize {
        const max = netcode_server_max_clients(server);
        return if (max < 0) Error.NegativeIndex else return max;
    }

    pub fn update(server: *Server, timestamp: f64) void {
        netcode_server_update(server, timestamp);
    }

    pub fn clientConnected(server: *Server, client_index: usize) bool {
        return netcode_server_client_connected(server, @intCast(c_int, client_index)) != 0;
    }

    pub fn clientId(server: *Server, client_index: usize) u64 {
        return netcode_server_client_id(server, @intCast(c_int, client_index));
    }

    pub fn clientAddress(server: *Server, client_index: usize) [*c]struct_netcode_address_t {
        return netcode_server_client_address(server, @intCast(c_int, client_index));
    }

    pub fn disconnectClient(server: *Server, client_index: usize) void {
        netcode_server_disconnect_client(server, @intCast(c_int, client_index));
    }

    pub fn disconnectAllClients(server: *Server) void {
        netcode_server_disconnect_all_clients(server);
    }

    pub fn nextPacketSequence(server: *Server, client_index: usize) u64 {
        netcode_server_next_packet_sequence(server, @intCast(c_int, client_index));
    }

    pub fn sendPacket(server: *Server, client_index: usize, packet_data: []u8) void {
        netcode_server_send_packet(server, @intCast(c_int, client_index), packet_data.ptr, @intCast(c_int, packet_data.len));
    }

    pub fn receivePacket(server: *Server, client_index: usize, packet_sequence: *u64) !?[]u8 {
        var len: c_int = 0;
        var packet = netcode_server_receive_packet(server, @intCast(c_int, client_index), &len, packet_sequence);
        if (len < 0) return Error.NegativeIndex;
        return if (packet == null) null else packet[0..@intCast(usize, len)];
    }

    pub fn freePacket(server: *Server, packet: []u8) void {
        netcode_server_free_packet(server, packet);
    }

    pub fn numConnectedClients(server: *Server) !usize {
        const num = netcode_server_num_connected_clients(server);
        return if (num < 0) Error.NegativeIndex else num;
    }

    pub fn clientUserData(server: *Server, client_index: usize) ?*anyopaque {
        return netcode_server_client_user_data(server, @intCast(c_int, client_index));
    }

    pub fn processPacket(server: *Server, from: Address, packet_data: []u8) void {
        netcode_server_process_packet(server, &from.toNative(), packet_data.ptr, @intCast(c_int, packet_data.len));
    }

    pub fn connectLoopbackClient(server: *Server, client_index: usize, client_id: u64, user_data: *[USER_DATA_BYTES]u8) void {
        netcode_server_connect_loopback_client(server, @intCast(c_int, client_index), client_id, user_data);
    }

    pub fn disconnectLoopbackClient(server: *Server, client_index: usize) void {
        netcode_server_disconnect_loopback_client(server, @intCast(c_int, client_index));
    }

    pub fn clientLoopback(server: *Server, client_index: usize) bool {
        return netcode_server_client_loopback(server, @intCast(c_int, client_index)) != 0;
    }

    pub fn processLoopbackPacket(server: *Server, client_index: usize, packet_data: []u8, packet_sequence: u64) void {
        netcode_server_process_loopback_packet(server, @intCast(c_int, client_index), packet_data.ptr, @intCast(c_int, packet_data.len), packet_sequence);
    }

    pub fn getPort(server: *Server) u16 {
        return netcode_server_get_port(server);
    }
};
