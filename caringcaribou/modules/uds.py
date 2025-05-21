import argparse
import datetime
import time

from sys import stdout, stderr

from caringcaribou.utils.can_actions import auto_blacklist
from caringcaribou.utils.common import list_to_hex_str, parse_int_dec_or_hex
from caringcaribou.utils.constants import ARBITRATION_ID_MAX, ARBITRATION_ID_MAX_EXTENDED
from caringcaribou.utils.constants import ARBITRATION_ID_MIN
from caringcaribou.utils.iso14229_1 import Constants, Iso14229_1, NegativeResponseCodes, ServiceID, Services
from caringcaribou.utils.iso15765_2 import IsoTp

UDS_SERVICE_NAMES = {
    0x10: "DIAGNOSTIC_SESSION_CONTROL",
    0x11: "ECU_RESET",
    0x14: "CLEAR_DIAGNOSTIC_INFORMATION",
    0x19: "READ_DTC_INFORMATION",
    0x20: "RETURN_TO_NORMAL",
    0x22: "READ_DATA_BY_IDENTIFIER",
    0x23: "READ_MEMORY_BY_ADDRESS",
    0x24: "READ_SCALING_DATA_BY_IDENTIFIER",
    0x27: "SECURITY_ACCESS",
    0x28: "COMMUNICATION_CONTROL",
    0x29: "AUTHENTICATION",
    0x2A: "READ_DATA_BY_PERIODIC_IDENTIFIER",
    0x2C: "DYNAMICALLY_DEFINE_DATA_IDENTIFIER",
    0x2D: "DEFINE_PID_BY_MEMORY_ADDRESS",
    0x2E: "WRITE_DATA_BY_IDENTIFIER",
    0x2F: "INPUT_OUTPUT_CONTROL_BY_IDENTIFIER",
    0x31: "ROUTINE_CONTROL",
    0x34: "REQUEST_DOWNLOAD",
    0x35: "REQUEST_UPLOAD",
    0x36: "TRANSFER_DATA",
    0x37: "REQUEST_TRANSFER_EXIT",
    0x38: "REQUEST_FILE_TRANSFER",
    0x3D: "WRITE_MEMORY_BY_ADDRESS",
    0x3E: "TESTER_PRESENT",
    0x7F: "NEGATIVE_RESPONSE",
    0x83: "ACCESS_TIMING_PARAMETER",
    0x84: "SECURED_DATA_TRANSMISSION",
    0x85: "CONTROL_DTC_SETTING",
    0x86: "RESPONSE_ON_EVENT",
    0x87: "LINK_CONTROL"
}

NRC_NAMES = {
    0x00: "POSITIVE_RESPONSE",
    0x10: "GENERAL_REJECT",
    0x11: "SERVICE_NOT_SUPPORTED",
    0x12: "SUB_FUNCTION_NOT_SUPPORTED",
    0x13: "INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT",
    0x14: "RESPONSE_TOO_LONG",
    0x21: "BUSY_REPEAT_REQUEST",
    0x22: "CONDITIONS_NOT_CORRECT",
    0x24: "REQUEST_SEQUENCE_ERROR",
    0x25: "NO_RESPONSE_FROM_SUBNET_COMPONENT",
    0x26: "FAILURE_PREVENTS_EXECUTION_OF_REQUESTED_ACTION",
    0x31: "REQUEST_OUT_OF_RANGE",
    0x33: "SECURITY_ACCESS_DENIED",
    0x34: "AUTHENTICATION_REQUIRED",
    0x35: "INVALID_KEY",
    0x36: "EXCEEDED_NUMBER_OF_ATTEMPTS",
    0x37: "REQUIRED_TIME_DELAY_NOT_EXPIRED",
    0x70: "UPLOAD_DOWNLOAD_NOT_ACCEPTED",
    0x71: "TRANSFER_DATA_SUSPENDED",
    0x72: "GENERAL_PROGRAMMING_FAILURE",
    0x73: "WRONG_BLOCK_SEQUENCE_COUNTER",
    0x78: "REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING",
    0x7E: "SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION",
    0x7F: "SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION",
    0x81: "RPM_TOO_HIGH",
    0x82: "RPM_TOO_LOW",
    0x83: "ENGINE_IS_RUNNING",
    0x84: "ENGINE_IS_NOT_RUNNING",
    0x85: "ENGINE_RUN_TIME_TOO_LOW",
    0x86: "TEMPERATURE_TOO_HIGH",
    0x87: "TEMPERATURE_TOO_LOW",
    0x88: "VEHICLE_SPEED_TOO_HIGH",
    0x89: "VEHICLE_SPEED_TOO_LOW",
    0x8A: "THROTTLE_PEDAL_TOO_HIGH",
    0x8B: "THROTTLE_PEDAL_TOO_LOW",
    0x8C: "TRANSMISSION_RANGE_NOT_IN_NEUTRAL",
    0x8D: "TRANSMISSION_RANGE_NOT_IN_GEAR",
    0x8F: "BRAKE_SWITCHES_NOT_CLOSED",
    0x90: "SHIFT_LEVER_NOT_IN_PARK",
    0x91: "TORQUE_CONVERTER_CLUTCH_LOCKED",
    0x92: "VOLTAGE_TOO_HIGH",
    0x93: "VOLTAGE_TOO_LOW"
}

DELAY_DISCOVERY = 0.01
DELAY_TESTER_PRESENT = 0.5
DELAY_SECSEED_RESET = 0.01
TIMEOUT_SERVICES = 0.2
TIMEOUT_SUBSERVICES = 0.02

# Max number of arbitration IDs to backtrack during verification
VERIFICATION_BACKTRACK = 5
# Extra time in seconds to wait for responses during verification
VERIFICATION_EXTRA_DELAY = 0.5

BYTE_MIN = 0x00
BYTE_MAX = 0xFF

DUMP_DID_MIN = 0x0000
DUMP_DID_MAX = 0xFFFF
DUMP_DID_TIMEOUT = 0.2

DUMP_WRITABLE_DID_MIN = 0x0000
DUMP_WRITABLE_DID_MAX = 0xFFFF
DUMP_WRITABLE_DID_TIMEOUT = 0.2
DEFAULT_TEST_DATA_HEX = "00"

MEM_START_ADDR = 0
MEM_LEN = 0x100
MEM_SIZE = 0x10
ADDR_BYTE_SIZE = 4
MEM_LEN_BYTE_SIZE = 2

DEFAULT_REQUEST_UPLOAD_TIMEOUT = 2.0 # seconds for each step in upload
DEFAULT_COMPRESSION_ENCRYPTION = 0x00
DEFAULT_ADDRESS_LENGTH_FORMAT = 0x44

def get_negative_response_code_name(nrc):
    """
    Returns the name of the given Negative Response Code (NRC) value.

    :param nrc: NRC value
    :type nrc: int

    :return: NRC name of the given NRC value
    :rtype: str
    """
    nrc_name = NRC_NAMES.get(nrc, "Unknown NRC value")
    return nrc_name


def print_negative_response_code(nrc):
    """
    Prints the given Negative Response Code (NRC) value in a human-readable form.

    :param nrc: NRC value
    :type nrc: int

    :return: Nothing
    """
    nrc_name = get_negative_response_code_name(nrc)
    print(f"Negative Response Code (NRC): {hex(nrc)} - {nrc_name}")


def process_negative_response(response: list[int]) -> None:
    """
    Processes a UDS negative response.

    :param response: UDS response represented as list of integers
    :type response: list[int]

    :return: Nothing
    """
    if Iso14229_1.is_negative_response(response):
        print_negative_response_code(response[2])


def uds_discovery(min_id, max_id, blacklist_args, auto_blacklist_duration,
                  delay, verify, print_results=True):
    """
    Scans for diagnostics support by brute forcing session control
    messages to different arbitration IDs.

    Returns a list of all (client_arb_id, server_arb_id) pairs found.

    :param min_id: start arbitration ID value
    :param max_id: end arbitration ID value
    :param blacklist_args: blacklist for arbitration ID values
    :param auto_blacklist_duration: seconds to scan for interfering
      arbitration IDs to blacklist automatically
    :param delay: delay between each message
    :param verify: whether found arbitration IDs should be verified
    :param print_results: whether results should be printed to stdout
    :type min_id: int
    :type max_id: int
    :type blacklist_args: [int]
    :type auto_blacklist_duration: float
    :type delay: float
    :type verify: bool
    :type print_results: bool
    :return: list of (client_arbitration_id, server_arbitration_id) pairs
    :rtype [(int, int)]
    """
    # Set defaults
    if min_id is None:
        min_id = ARBITRATION_ID_MIN
    if max_id is None:
        if min_id <= ARBITRATION_ID_MAX:
            max_id = ARBITRATION_ID_MAX
        else:
            # If min_id is extended, use an extended default max_id as well
            max_id = ARBITRATION_ID_MAX_EXTENDED
    if auto_blacklist_duration is None:
        auto_blacklist_duration = 0
    if blacklist_args is None:
        blacklist_args = []

    # Sanity checks
    if max_id < min_id:
        raise ValueError("max_id must not be smaller than min_id -"
                         " got min:0x{0:x}, max:0x{1:x}".format(min_id, max_id))
    if auto_blacklist_duration < 0:
        raise ValueError("auto_blacklist_duration must not be smaller "
                         "than 0, got {0}".format(auto_blacklist_duration))

    diagnostic_session_control = Services.DiagnosticSessionControl
    service_id = diagnostic_session_control.service_id
    sub_function = diagnostic_session_control.DiagnosticSessionType.DEFAULT_SESSION
    session_control_data = [service_id, sub_function]

    valid_session_control_responses = [0x50, 0x7F]

    def is_valid_response(message):
        return (len(message.data) >= 2 and
                message.data[1] in valid_session_control_responses)

    found_arbitration_ids = []

    with IsoTp(None, None) as tp:
        blacklist = set(blacklist_args)
        # Perform automatic blacklist scan
        if auto_blacklist_duration > 0:
            auto_bl_arb_ids = auto_blacklist(tp.bus,
                                             auto_blacklist_duration,
                                             is_valid_response,
                                             print_results)
            blacklist |= auto_bl_arb_ids

        # Prepare session control frame
        sess_ctrl_frm = tp.get_frames_from_message(session_control_data)
        send_arb_id = min_id - 1
        while send_arb_id < max_id:
            send_arb_id += 1
            if print_results:
                print("\rSending Diagnostic Session Control to 0x{0:04x}"
                      .format(send_arb_id), end="")
                stdout.flush()
            # Send Diagnostic Session Control
            tp.transmit(sess_ctrl_frm, send_arb_id, None)
            end_time = time.time() + delay
            # Listen for response
            while time.time() < end_time:
                msg = tp.bus.recv(0)
                if msg is None:
                    # No response received
                    continue
                if msg.arbitration_id in blacklist:
                    # Ignore blacklisted arbitration IDs
                    continue
                if is_valid_response(msg):
                    # Valid response
                    if verify:
                        # Verification - backtrack the latest IDs and
                        # verify that the same response is received
                        verified = False
                        # Set filter to only receive messages for the
                        # arbitration ID being verified
                        tp.set_filter_single_arbitration_id(msg.arbitration_id)
                        if print_results:
                            print("\n  Verifying potential response from "
                                  "0x{0:04x}".format(send_arb_id))
                        verify_id_range = range(send_arb_id,
                                                send_arb_id - VERIFICATION_BACKTRACK,
                                                -1)
                        for verify_arb_id in verify_id_range:
                            if print_results:
                                print("    Resending 0x{0:0x}... "
                                      .format(verify_arb_id), end=" ")
                            tp.transmit(sess_ctrl_frm,
                                        verify_arb_id,
                                        None)
                            # Give some extra time for verification, in
                            # case of slow responses
                            verification_end_time = (time.time()
                                                     + delay
                                                     + VERIFICATION_EXTRA_DELAY)
                            while time.time() < verification_end_time:
                                verification_msg = tp.bus.recv(0)
                                if verification_msg is None:
                                    continue
                                if is_valid_response(verification_msg):
                                    # Verified
                                    verified = True
                                    # Update send ID - if server responds
                                    # slowly, initial value may be faulty.
                                    # Also ensures we resume searching on
                                    # the next arb ID after the actual
                                    # match, rather than the one after the
                                    # last potential match (which could lead
                                    # to false negatives if multiple servers
                                    # listen to adjacent arbitration IDs and
                                    # respond slowly)
                                    send_arb_id = verify_arb_id
                                    break
                            if print_results:
                                # Print result
                                if verified:
                                    print("Success")
                                else:
                                    print("No response")
                            if verified:
                                # Verification succeeded - stop checking
                                break
                        # Remove filter after verification
                        tp.clear_filters()
                        if not verified:
                            # Verification failed - move on
                            if print_results:
                                print("  False match - skipping")
                            continue
                    if print_results:
                        if not verify:
                            # Blank line needed
                            print()
                        print("Found diagnostics server "
                              "listening at 0x{0:04x}, "
                              "response at 0x{1:04x}"
                              .format(send_arb_id, msg.arbitration_id))
                    # Add found arbitration ID pair
                    found_arb_id_pair = (send_arb_id,
                                         msg.arbitration_id)
                    found_arbitration_ids.append(found_arb_id_pair)
        if print_results:
            print()
    return found_arbitration_ids


def __uds_discovery_wrapper(args):
    """Wrapper used to initiate a UDS discovery scan"""
    min_id = args.min
    max_id = args.max
    blacklist = args.blacklist
    auto_blacklist_duration = args.autoblacklist
    delay = args.delay
    verify = not args.skipverify
    print_results = True

    try:
        arb_id_pairs = uds_discovery(min_id, max_id, blacklist,
                                     auto_blacklist_duration,
                                     delay, verify, print_results)
        if len(arb_id_pairs) == 0:
            # No UDS discovered
            print("\nDiagnostics service could not be found.")
        else:
            # Print result table
            print("\nIdentified diagnostics:\n")
            table_line = "+------------+------------+"
            print(table_line)
            print("| CLIENT ID  | SERVER ID  |")
            print(table_line)
            for (client_id, server_id) in arb_id_pairs:
                print("| 0x{0:08x} | 0x{1:08x} |"
                      .format(client_id, server_id))
            print(table_line)
    except ValueError as e:
        print("Discovery failed: {0}".format(e))


def service_discovery(arb_id_request, arb_id_response, timeout,
                      min_id=BYTE_MIN, max_id=BYTE_MAX, print_results=True):
    """
    Scans for supported UDS services on the specified arbitration ID.
    Returns a list of found service IDs.

    :param arb_id_request: arbitration ID for requests
    :param arb_id_response: arbitration ID for responses
    :param timeout: delay between each request sent
    :param min_id: first service ID to scan
    :param max_id: last service ID to scan
    :param print_results: whether progress should be printed to stdout
    :type arb_id_request: int
    :type arb_id_response: int
    :type timeout: float
    :type min_id: int
    :type max_id: int
    :type print_results: bool
    :return: list of supported service IDs
    :rtype [int]
    """
    found_services = []

    with IsoTp(arb_id_request=arb_id_request,
               arb_id_response=arb_id_response) as tp:
        # Setup filter for incoming messages
        tp.set_filter_single_arbitration_id(arb_id_response)
        # Send requests
        try:
            for service_id in range(min_id, max_id + 1):
                tp.send_request([service_id])
                if print_results:
                    print("\rProbing service 0x{0:02x} ({0}/{1}): found {2}"
                          .format(service_id, max_id, len(found_services)),
                          end="")
                stdout.flush()
                # Get response
                msg = tp.bus.recv(timeout)
                if msg is None:
                    # No response received
                    continue
                # Parse response
                if len(msg.data) > 3:
                    # Since service ID is included in the response, mapping is correct even if response is delayed
                    response_id = msg.data[1]
                    response_service_id = msg.data[2]
                    status = msg.data[3]
                    if response_id != Constants.NR_SI:
                        request_id = Iso14229_1.get_service_request_id(response_id)
                        found_services.append(request_id)
                    elif status != NegativeResponseCodes.SERVICE_NOT_SUPPORTED:
                        # Any other response than "service not supported" counts
                        found_services.append(response_service_id)
            if print_results:
                print("\nDone!\n")
        except KeyboardInterrupt:
            if print_results:
                print("\nInterrupted by user!\n")
    return found_services


def __service_discovery_wrapper(args):
    """Wrapper used to initiate a service discovery scan"""
    arb_id_request = args.src
    arb_id_response = args.dst
    timeout = args.timeout
    # Probe services
    found_services = service_discovery(arb_id_request,
                                       arb_id_response, timeout)
    # Print results
    for service_id in found_services:
        service_name = UDS_SERVICE_NAMES.get(service_id, "Unknown service")
        print("Supported service 0x{0:02x}: {1}"
              .format(service_id, service_name))


def sub_discovery(arb_id_request, arb_id_response, diagnostic, service, timeout, print_results=True):
    """
    Scans for supported UDS Diagnostic Session Control subservices on the specified arbitration ID.
    Returns a list of found Diagnostic Session Control subservice IDs.

    :param arb_id_request: arbitration ID for requests
    :param arb_id_response: arbitration ID for responses
    :param timeout: delay between each request sent
    :param diagnostic: the diagnostic session control subfunction in which the target service is accessible
    :param service: the target service to be enumerated
    :param print_results: whether progress should be printed to stdout
    :type arb_id_request: int
    :type arb_id_response: int
    :type timeout: float
    :type diagnostic: int
    :type service: int
    :type print_results: bool
    :return: list of supported service IDs
    :rtype [int]
    """
    found_subservices = []
    subservice_status = []

    try:
        for i in range(0, 256):

            if service != Services.DiagnosticSessionControl:
                extended_session(arb_id_request, arb_id_response, diagnostic)
            else:
                extended_session(arb_id_request, arb_id_response, 1)

            time.sleep(0.1)

            response = raw_send(arb_id_request, arb_id_response, service, i)

            service_name = UDS_SERVICE_NAMES.get(service, "Unknown service")

            print("\rProbing sub-service ID 0x{0:02x} for service {1} (0x{2:02x}).".format(i, service_name, service),
                  end="")

            if response is None:
                # No response received
                continue

            # Parse response
            if len(response) >= 2:
                response_id = response[0]
                response_service_id = response[1]
                if len(response) >= 3:
                    status = response[2]
                else:
                    status = None
                if Iso14229_1.is_positive_response(response):
                    found_subservices.append(i)
                    subservice_status.append(0x00)
                elif (response_id == Constants.NR_SI and response_service_id == service and
                      status != NegativeResponseCodes.SUB_FUNCTION_NOT_SUPPORTED):
                    # Any other response than "service not supported" counts
                    found_subservices.append(i)
                    subservice_status.append(response_service_id)

            time.sleep(timeout)

    except KeyboardInterrupt:
        if print_results:
            print("\nInterrupted by user!\n")
    return found_subservices, subservice_status


def __sub_discovery_wrapper(args):
    """Wrapper used to initiate a subservice discovery scan"""
    arb_id_request = args.src
    arb_id_response = args.dst
    diagnostic = args.dsc
    service = args.service
    timeout = args.timeout

    # Probe subservices
    found_subservices, subservice_status = sub_discovery(arb_id_request,
                                                         arb_id_response, diagnostic, service, timeout)

    service_name = UDS_SERVICE_NAMES.get(service, "Unknown service")
    # Print results
    if len(found_subservices) == 0:
        print("\nNo Sub-Services were discovered for service {0:02x} - {1}.\n".format(service, service_name, end=" "))
    else:
        print("\nSub-Services Discovered for Service {0:02x} - {1}:\n".format(service, service_name, end=" "))
        for subservice_id in found_subservices:
            nrc = subservice_status[found_subservices.index(subservice_id)]
            nrc_name = get_negative_response_code_name(nrc)
            print("\n0x{0:02x} : {1}".format(subservice_id, nrc_name), end=" ")


def raw_send(arb_id_request, arb_id_response, service, session_type):
    with IsoTp(arb_id_request=arb_id_request,
               arb_id_response=arb_id_response) as tp:
        # Setup filter for incoming messages
        request = [0] * 2
        request[0] = service
        request[1] = session_type

        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds:
            tp.send_request(request)
            response = uds.receive_response(Iso14229_1.P3_CLIENT)
            return response


def tester_present(arb_id_request, delay, duration,
                   suppress_positive_response):
    """
    Sends TesterPresent messages to 'arb_id_request'. Stops automatically
    after 'duration' seconds or runs forever if this is None.

    :param arb_id_request: arbitration ID for requests
    :param delay: seconds between each request
    :param duration: seconds before automatically stopping, or None to
                     continue forever
    :param suppress_positive_response: whether positive responses should
                                       be suppressed
    :type arb_id_request: int
    :type delay: float
    :type duration: float or None
    :type suppress_positive_response: bool
    """
    # SPR simply tells the recipient not to send a positive response to
    # each TesterPresent message
    if suppress_positive_response:
        sub_function = 0x80
    else:
        sub_function = 0x00

    # Calculate end timestamp if the TesterPresent should automatically
    # stop after a given duration
    auto_stop = duration is not None
    end_time = None
    if auto_stop:
        end_time = (datetime.datetime.now()
                    + datetime.timedelta(seconds=duration))

    service_id = Services.TesterPresent.service_id
    message_data = [service_id, sub_function]
    print("Sending TesterPresent to arbitration ID {0} (0x{0:02x})"
          .format(arb_id_request))
    print("\nPress Ctrl+C to stop\n")
    with IsoTp(arb_id_request, None) as can_wrap:
        counter = 1
        while True:
            can_wrap.send_request(message_data)
            print("\rCounter:", counter, end="")
            stdout.flush()
            time.sleep(delay)
            counter += 1
            if auto_stop and datetime.datetime.now() >= end_time:
                break


def __tester_present_wrapper(args):
    """Wrapper used to initiate a TesterPresent session"""
    arb_id_request = args.src
    delay = args.delay
    duration = args.duration
    suppress_positive_response = args.spr

    tester_present(arb_id_request, delay, duration,
                   suppress_positive_response)


def ecu_reset(arb_id_request, arb_id_response, reset_type, timeout):
    """
    Sends an ECU Reset message to 'arb_id_request'. Returns the first
    response received from 'arb_id_response' within 'timeout' seconds
    or None otherwise.

    :param arb_id_request: arbitration ID for requests
    :param arb_id_response: arbitration ID for responses
    :param reset_type: value corresponding to a reset type
    :param timeout: seconds to wait for response before timeout, or None
                    for default UDS timeout
    :type arb_id_request: int
    :type arb_id_response int
    :type reset_type: int
    :type timeout: float or None
    :return: list of response byte values on success, None otherwise
    :rtype [int] or None
    """
    # Sanity checks
    if not BYTE_MIN <= reset_type <= BYTE_MAX:
        raise ValueError("reset type must be within interval "
                         "0x{0:02x}-0x{1:02x}"
                         .format(BYTE_MIN, BYTE_MAX))
    if isinstance(timeout, float) and timeout < 0.0:
        raise ValueError("timeout value ({0}) cannot be negative"
                         .format(timeout))

    with IsoTp(arb_id_request=arb_id_request,
               arb_id_response=arb_id_response) as tp:
        # Setup filter for incoming messages
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds:
            # Set timeout
            if timeout is not None:
                uds.P3_CLIENT = timeout

            response = uds.ecu_reset(reset_type=reset_type)
            return response


def __ecu_reset_wrapper(args):
    """Wrapper used to initiate ECU Reset"""
    arb_id_request = args.src
    arb_id_response = args.dst
    reset_type = args.reset_type
    timeout = args.timeout

    print("Sending ECU reset, type 0x{0:02x} to arbitration ID {1} "
          "(0x{1:02x})".format(reset_type, arb_id_request))
    try:
        response = ecu_reset(arb_id_request, arb_id_response,
                             reset_type, timeout)
    except ValueError as e:
        print("ValueError: {0}".format(e))
        return

    # Decode response
    if response is None:
        print("No response was received")
    else:
        response_length = len(response)
        if response_length == 0:
            # Empty response
            print("Received empty response")
        elif response_length == 1:
            # Invalid response length
            print("Received response [{0:02x}] (1 byte), expected at least "
                  "2 bytes".format(response[0], len(response)))
        elif Iso14229_1.is_positive_response(response):
            # Positive response handling
            response_service_id = response[0]
            subfunction = response[1]
            expected_response_id = \
                Iso14229_1.get_service_response_id(
                    Services.EcuReset.service_id)
            if (response_service_id == expected_response_id
                    and subfunction == reset_type):
                # Positive response
                pos_msg = "Received positive response"
                if response_length > 2:
                    # Additional data can be seconds left to reset
                    # (powerDownTime) or manufacturer specific
                    additional_data = list_to_hex_str(response[2:], ",")
                    pos_msg += (" with additional data: [{0}]"
                                .format(additional_data))
                print(pos_msg)
            else:
                # Service and/or subfunction mismatch
                print("Response service ID 0x{0:02x} and subfunction "
                      "0x{1:02x} do not match expected values 0x{2:02x} "
                      "and 0x{3:02x}".format(response_service_id,
                                             subfunction,
                                             Services.EcuReset.service_id,
                                             reset_type))
        else:
            # Negative response handling
            process_negative_response(response)


def __security_seed_wrapper(args):
    """Wrapper used to initiate security seed dump"""
    arb_id_request = args.src
    arb_id_response = args.dst
    reset_type = args.reset
    session_type = args.sess_type
    level = args.sec_level
    num_seeds = args.num
    reset_delay = args.delay

    seed_list = []
    try:
        print("Security seed dump started. Press Ctrl+C to stop.\n")
        while num_seeds > len(seed_list) or num_seeds == 0:
            # Extended diagnostics
            response = extended_session(arb_id_request,
                                        arb_id_response,
                                        session_type)
            if not Iso14229_1.is_positive_response(response):
                print("Unable to enter extended session. Retrying...\n")
                continue

            # Request seed
            response = request_seed(arb_id_request, arb_id_response,
                                    level, None, None)
            if response is None:
                print("\nInvalid response")
            elif Iso14229_1.is_positive_response(response):
                seed_list.append(list_to_hex_str(response[2:]))
                print("Seed received: {}\t(Total captured: {})"
                      .format(list_to_hex_str(response[2:]),
                              len(seed_list)), end="\r")
                stdout.flush()
            else:
                # Negative response handling
                process_negative_response(response)
                break
            if reset_type:
                ecu_reset(arb_id_request, arb_id_response, reset_type, None)
                time.sleep(reset_delay)
    except KeyboardInterrupt:
        print("Interrupted by user.")
    except ValueError as e:
        print(e)
        return

    if len(seed_list) > 0:
        print("\n")
        print("Security Access Seeds captured:")
        for seed in seed_list:
            print(seed)


def extended_session(arb_id_request, arb_id_response, session_type):
    with IsoTp(arb_id_request=arb_id_request,
               arb_id_response=arb_id_response) as tp:
        # Setup filter for incoming messages
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds:
            response = uds.diagnostic_session_control(session_type)
            return response


def request_seed(arb_id_request, arb_id_response, level,
                 data_record, timeout):
    """
    Sends a Request seed message to 'arb_id_request'. Returns the
    first response received from 'arb_id_response' within 'timeout'
    seconds or None otherwise.

    :param arb_id_request: arbitration ID for requests
    :param arb_id_response: arbitration ID for responses
    :param level: vehicle manufacturer specific access level to request
                  seed for
    :param data_record: optional vehicle manufacturer specific data to
                        transmit when requesting seed
    :param timeout: seconds to wait for response before timeout, or None
                    for default UDS timeout
    :type arb_id_request: int
    :type arb_id_response: int
    :type level: int
    :type data_record: [int] or None
    :type timeout: float or None
    :return: list of response byte values on success, None otherwise
    :rtype [int] or None
    """
    # Sanity checks
    if (not Services.SecurityAccess.RequestSeedOrSendKey()
            .is_valid_request_seed_level(level)):
        raise ValueError("Invalid request seed level")
    if isinstance(timeout, float) and timeout < 0.0:
        raise ValueError("Timeout value ({0}) cannot be negative"
                         .format(timeout))

    with IsoTp(arb_id_request=arb_id_request,
               arb_id_response=arb_id_response) as tp:
        # Setup filter for incoming messages
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds:
            # Set timeout
            if timeout is not None:
                uds.P3_CLIENT = timeout

            response = uds.security_access_request_seed(level, data_record)
            return response


def send_key(arb_id_request, arb_id_response, level, key, timeout):
    """
    Sends a Send key message to 'arb_id_request'.
    Returns the first response received from 'arb_id_response' within
    'timeout' seconds or None otherwise.

    :param arb_id_request: arbitration ID for requests
    :param arb_id_response: arbitration ID for responses
    :param level: vehicle manufacturer specific access level to send key for
    :param key: key to transmit
    :param timeout: seconds to wait for response before timeout, or None
                    for default UDS timeout
    :type arb_id_request: int
    :type arb_id_response: int
    :type level: int
    :type key: [int]
    :type timeout: float or None
    :return: list of response byte values on success, None otherwise
    :rtype [int] or None
    """
    # Sanity checks
    if (not Services.SecurityAccess.RequestSeedOrSendKey()
            .is_valid_send_key_level(level)):
        raise ValueError("Invalid send key level")
    if isinstance(timeout, float) and timeout < 0.0:
        raise ValueError("Timeout value ({0}) cannot be negative"
                         .format(timeout))

    with IsoTp(arb_id_request=arb_id_request,
               arb_id_response=arb_id_response) as tp:
        # Setup filter for incoming messages
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds:
            # Set timeout
            if timeout is not None:
                uds.P3_CLIENT = timeout

            response = uds.security_access_send_key(level=level, key=key)
            return response


def __dump_dids_wrapper(args):
    """Wrapper used to initiate data identifier dump"""
    arb_id_request = args.src
    arb_id_response = args.dst
    timeout = args.timeout
    min_did = args.min_did
    max_did = args.max_did
    print_results = True
    dump_dids(arb_id_request, arb_id_response, timeout, min_did, max_did,
              print_results)


def __auto_wrapper(args):
    """Wrapper used to initiate automated UDS scan"""
    min_id = args.min
    max_id = args.max
    blacklist = args.blacklist
    auto_blacklist_duration = args.autoblacklist
    delay = args.delay
    verify = not args.skipverify
    print_results = True
    timeout = args.timeout
    min_did = args.min_did
    max_did = args.max_did

    try:
        arb_id_pairs = uds_discovery(min_id, max_id, blacklist,
                                     auto_blacklist_duration,
                                     delay, verify, print_results)

        print("\n")
        if len(arb_id_pairs) == 0:
            # No UDS discovered
            print("\nDiagnostics service could not be found.")
        else:

            # Print result table
            print("\nIdentified diagnostics:\n")
            table_line = "+------------+------------+"
            print(table_line)
            print("| CLIENT ID  | SERVER ID  |")
            print(table_line)
            for (client_id, server_id) in arb_id_pairs:
                print("| 0x{0:08x} | 0x{1:08x} |"
                      .format(client_id, server_id))
            print(table_line)
            print("\n")

            # Enumerate each pair
            for (client_id, server_id) in arb_id_pairs:

                args.src = client_id
                args.dst = server_id

                # Print Client/Server result table
                print("\nTarget Diagnostic IDs:\n")
                table_line = "+------------+------------+"
                print(table_line)
                print("| CLIENT ID  | SERVER ID  |")
                print(table_line)
                print("| 0x{0:08x} | 0x{1:08x} |"
                      .format(client_id, server_id))
                print(table_line)

                print("\nEnumerating Services:\n")

                found_services = service_discovery(client_id, server_id, timeout)
                found_subservices = []

                print("\nIdentified services:\n")

                # Print available services result table
                for service_id in found_services:
                    service_name = UDS_SERVICE_NAMES.get(service_id, "Unknown service")
                    print("Supported service 0x{0:02x}: {1}"
                          .format(service_id, service_name))

                print("\n")

                dump_dids(client_id, server_id, timeout, min_did, max_did, print_results)

                if ServiceID.DIAGNOSTIC_SESSION_CONTROL in found_services:

                    print("\nEnumerating Diagnostic Session Control Service:\n")

                    found_subservices = []
                    subservice_status = []

                    for i in range(1, 256):

                        extended_session(client_id, server_id, 1)

                        response = extended_session(client_id, server_id, i)

                        print("\rProbing diagnostic session control sub-service 0x{0:02x}".format(i), end="")

                        if response is None:
                            # No response received
                            continue

                        # Parse response
                        if len(response) >= 3:
                            response_id = response[0]
                            response_service_id = response[1]
                            status = response[2]
                            if Iso14229_1.is_positive_response(response):
                                found_subservices.append(i)
                                subservice_status.append(0x00)
                            elif (response_id == Constants.NR_SI and response_service_id == 0x10 and
                                  status != NegativeResponseCodes.SUB_FUNCTION_NOT_SUPPORTED):
                                # Any other response than "service not supported" counts
                                found_subservices.append(i)
                                subservice_status.append(response_service_id)

                        time.sleep(timeout)

                    # Print results
                    if len(found_subservices) == 0:
                        print("\nNo Diagnostic Session Control Sub-Services were discovered\n", end=" ")
                    else:
                        print("\n")
                        print("\nDiscovered Diagnostic Session Control Sub-Services:\n", end=" ")
                        for subservice_id in found_subservices:
                            nrc = subservice_status[found_subservices.index(subservice_id)]
                            nrc_name = get_negative_response_code_name(nrc)
                            print("\n0x{0:02x} : {1}".format(subservice_id, nrc_name), end=" ")

                if ServiceID.ECU_RESET in found_services:

                    print("\n")
                    print("\nEnumerating ECUReset Service:\n")

                    found_subservices = []
                    subservice_status = []

                    for i in range(1, 5):

                        extended_session(client_id, server_id, 3)

                        response = raw_send(client_id, server_id, 17, i)

                        print("\rProbing ECUReset sub-service 0x{0:02x}".format(i), end="")

                        if response is None:
                            # No response received
                            continue

                        # Parse response
                        if len(response) >= 2:
                            response_id = response[0]
                            response_service_id = response[1]
                            if len(response) >= 3:
                                status = response[2]
                            else:
                                status = None
                            if Iso14229_1.is_positive_response(response):
                                found_subservices.append(i)
                                subservice_status.append(0x00)
                            elif (response_id == Constants.NR_SI and response_service_id == 0x11 and
                                  status != NegativeResponseCodes.SUB_FUNCTION_NOT_SUPPORTED):
                                # Any other response than "service not supported" counts
                                found_subservices.append(i)
                                subservice_status.append(response_service_id)

                        time.sleep(timeout)

                    # Print results
                    if len(found_subservices) == 0:
                        print("\nNo ECUReset Sub-Services were discovered.\n", end=" ")
                    else:
                        print("\n")
                        print("\nDiscovered ECUReset Sub-Services:\n", end=" ")
                        for subservice_id in found_subservices:
                            nrc = subservice_status[found_subservices.index(subservice_id)]
                            nrc_name = get_negative_response_code_name(nrc)
                            print("\n0x{0:02x} : {1}".format(subservice_id, nrc_name), end=" ")

                if ServiceID.SECURITY_ACCESS in found_services:

                    found_subdiag = []
                    found_subsec = []
                    print("\n")
                    for subservice_id in found_subservices:
                        for level in range(1, 256):
                            print(
                                "\rProbing security access sub-service "
                                "0x{0:02x} in diagnostic session 0x{1:02x}.".format(level, subservice_id), end=" ")
                            extended_session(client_id, server_id, 1)
                            extended_session(client_id, server_id, subservice_id)
                            response = raw_send(client_id, server_id, 39, level)

                            if response is None:
                                continue
                            elif Iso14229_1.is_positive_response(response):
                                found_subdiag.append(subservice_id)
                                found_subsec.append(level)
                    if len(found_subsec) == 0:
                        print("\nNo Security Access Sub-Services were discovered.\n")
                    else:
                        print("\n")
                        print("\nDiscovered Security Access Sub Services:\n")
                        print("\n")
                        table_line_sec = "+----------------------+-------------------+"
                        print(table_line_sec)
                        print("|  Diagnostic Session  |  Security Access  |")
                        print(table_line_sec)
                        for counter in range(len(found_subsec)):
                            diag = found_subdiag[counter]
                            sec = found_subsec[counter]
                            print("|         0x{0:02x}         |         0x{1:02x}      |"
                                  .format(diag, sec))
                            counter += 1
                        print(table_line_sec)

    except ValueError as e:
        print("\nDiscovery failed: {0}".format(e), end=" ")


def dump_dids(arb_id_request, arb_id_response, timeout,
              min_did=DUMP_DID_MIN, max_did=DUMP_DID_MAX, print_results=True):
    """
    Sends read data by identifier (DID) messages to 'arb_id_request'.
    Returns a list of positive responses received from 'arb_id_response' within
    'timeout' seconds or an empty list if no positive responses were received.

    :param arb_id_request: arbitration ID for requests
    :param arb_id_response: arbitration ID for responses
    :param timeout: seconds to wait for response before timeout, or None
                    for default UDS timeout
    :param min_did: minimum device identifier to read
    :param max_did: maximum device identifier to read
    :param print_results: whether progress should be printed to stdout
    :type arb_id_request: int
    :type arb_id_response: int
    :type timeout: float or None
    :type min_did: int
    :type max_did: int
    :type print_results: bool
    :return: list of tuples containing DID and response bytes on success,
             empty list if no responses
    :rtype [(int, [int])] or []
    """
    # Sanity checks
    if isinstance(timeout, float) and timeout < 0.0:
        raise ValueError("Timeout value ({0}) cannot be negative"
                         .format(timeout))

    if max_did < min_did:
        raise ValueError("max_did must not be smaller than min_did -"
                         " got min:0x{0:x}, max:0x{1:x}".format(min_did, max_did))

    responses = []
    with IsoTp(arb_id_request=arb_id_request,
               arb_id_response=arb_id_response) as tp:
        # Setup filter for incoming messages
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds:
            # Set timeout
            if timeout is not None:
                uds.P3_CLIENT = timeout

            if print_results:
                print("Dumping DIDs in range 0x{:04x}-0x{:04x}\n".format(
                    min_did, max_did))
                print("Identified DIDs:")
                print("DID    Value (hex)")
            for identifier in range(min_did, max_did + 1):
                if print_results:
                    print(f"0x{identifier:04x}", end="\r", file=stderr)
                response = uds.read_data_by_identifier(identifier=[identifier])

                # Only keep positive responses
                if not response:
                    continue
                if not Iso14229_1.is_positive_response(response):
                    continue
                # should be 4 byte minimum for 1 byte response
                # [response_code, DID_upper, DID_lower, data_0]
                if len(response) < 4:
                    continue

                if identifier != int(list_to_hex_str(response[1:3]), 16):
                    continue

                responses.append((identifier, response))
                # only display the data record portion of the payload
                # response[0] = response SID (0x62)
                # response[1:3] = Data Identifier (DID)
                # response[3:] = data
                if print_results:
                    print("0x{:04x}".format(identifier), list_to_hex_str(response[3:]))
            if print_results:
                print("\033[K", file=stderr)  # clear line
                print("Done!")
            return responses


def __read_mem_wrapper(args):
    """Wrapper used to initiate memory read"""
    arb_id_request = args.src
    arb_id_response = args.dst
    timeout = args.timeout
    start_addr = args.start_addr
    mem_length = args.mem_length
    mem_size = args.mem_size
    address_byte_size = args.address_byte_size
    memory_length_byte_size = args.memory_length_byte_size
    print_results = True
    outfile = args.outfile

    results = read_memory(arb_id_request, arb_id_response, timeout, start_addr, mem_length, mem_size, address_byte_size,
                          memory_length_byte_size, print_results)
    if outfile:
        with open(outfile, "w") as f:
            for addr, data in results:
                f.write(f"{addr:08x} {bytes(data[1:]).hex()}\n")


def read_memory(arb_id_request, arb_id_response, timeout,
                start_addr=MEM_START_ADDR, mem_length=MEM_LEN, mem_size=MEM_SIZE, address_byte_size=ADDR_BYTE_SIZE,
                memory_length_byte_size=MEM_LEN_BYTE_SIZE, print_results=True):
    """
    Sends read memory messages to 'arb_id_request'.
    Returns a list of positive responses received from 'arb_id_response' within
    'timeout' seconds or an empty list if no positive responses were received.
    :param arb_id_request: arbitration ID for requests
    :param arb_id_response: arbitration ID for responses
    :param timeout: seconds to wait for response before timeout, or None
                    for default UDS timeout
    :param start_addr: starting address to read
    :param mem_length: maximum device identifier to read
    :param mem_size: number of bytes to read from the controller
    :param address_byte_size: number of bytes of the memory address parameter
    :param memory_length_byte_size: number of bytes of the memory length parameter
    :param print_results: whether progress should be printed to stdout
    :type address_byte_size: int
    :type memory_length_byte_size: int
    :type arb_id_request: int
    :type arb_id_response: int
    :type timeout: float or None
    :type start_addr: int
    :type mem_length: int
    :type mem_size: int
    :type print_results: bool
    :return: list of tuples containing memory address and response bytes on success,
             empty list if no responses
    :rtype [(int, [int])] or []
    """
    _max_memory_space = (2 ** (8 * address_byte_size) - 1)
    # Sanity checks
    if isinstance(timeout, float) and timeout < 0.0:
        raise ValueError("Timeout value ({0}) cannot be negative"
                         .format(timeout))
    if start_addr < 0:
        raise ValueError("Start Address '{:x}' must be a positive integer".format(start_addr))
    if start_addr + mem_length > _max_memory_space:
        raise OverflowError("Start Address (0x{:x}) plus Memory Length (0x{:x}) "
                            "will exceed the maximum memory address space (0x{:x})"
                            .format(start_addr, mem_length, _max_memory_space))

    responses = []
    with IsoTp(arb_id_request=arb_id_request,
               arb_id_response=arb_id_response) as tp:

        # Setup filter for incoming messages
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds:
            # Set timeout
            if timeout is not None:
                uds.P3_CLIENT = timeout
            if print_results:
                print("Dumping Memory in range 0x{:08x}-0x{:08x}\n".format(
                    start_addr, start_addr + mem_length - 1))
                print("Identified Addresses:")
                print("Address    Value (hex)")
            expected_service_response_id = uds.get_service_response_id(ServiceID.READ_MEMORY_BY_ADDRESS)
            for identifier in range(start_addr, start_addr + mem_length, mem_size):
                address_and_length_format = (memory_length_byte_size << 4) + address_byte_size
                response = uds.read_memory_by_address(memory_address=identifier, memory_size=mem_size,
                                                      address_and_length_format=address_and_length_format)

                if response and Iso14229_1.is_positive_response(response):
                    # Filter extraneous results, ie keep only $23 responses
                    if response[0] == expected_service_response_id:
                        responses.append((identifier, response))
                        # response [0] = positive response SID (0x63)
                        # response [1:] = data returned from memory read
                        if print_results and len(response) >= 2:
                            print("0x{:08x}".format(identifier), list_to_hex_str(response[1:]))
                # Negative response handling
                elif response:
                    print(f"Could not dump 0x{mem_size:04x} bytes of memory from address 0x{identifier:08x} - "
                          f"received response: {bytes(response).hex(' ')}")
                    process_negative_response(response)
                    # This would be a good place to add code to unlock the ECU (if you know how and have the key)
                    # but to keep this general, we'll just notify user
            if print_results:
                print("\nDone!")
            return responses

def write_data_by_identifier(arb_id_request, arb_id_response, did, data_hex_str, timeout, print_results=True):
    """Sends a WriteDataByIdentifier request and prints the response."""
    if not (0x0000 <= did <= 0xFFFF):
        raise ValueError("DID must be between 0x0000 and 0xFFFF")

    # Handle both direct hex string input and file input
    data_bytes = []

    # Check if the input is a file path
    if data_hex_str.startswith("file:"):
        file_path = data_hex_str[5:].strip()
        try:
            with open(file_path, 'rb') as f:
                data_bytes = list(f.read())
        except FileNotFoundError:
            raise ValueError(f"File not found: {file_path}")
        except IOError as e:
            raise ValueError(f"Error reading file: {e}")
    else:
        # Process hex string with different possible formats:
        # - 0xAA.BB.CC
        # - AA.BB.CC
        # - AABBCC
        # - 0xAA BB CC
        # - AA BB CC
        try:
            # Remove 0x prefix if present
            clean_hex = data_hex_str.replace('0x', '')
            # Replace dots and spaces with nothing
            clean_hex = clean_hex.replace('.', '').replace(' ', '')
            data_bytes = list(bytes.fromhex(clean_hex))
        except ValueError:
            raise ValueError("Invalid data format. Use hex bytes separated by dots or spaces (e.g., AA.BB.CC or AA BB CC) or 'file:/path/to/file' to read from a file")

    if print_results:
        print(f"Attempting to write DID 0x{did:04X} with data {list_to_hex_str(data_bytes)} to 0x{arb_id_request:X} (response from 0x{arb_id_response:X})")

    with IsoTp(arb_id_request=arb_id_request, arb_id_response=arb_id_response) as tp:
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds_client:
            uds_client.P3_CLIENT = timeout # Use P3_CLIENT for response timeout after request
            # You'll need to add write_data_by_identifier to Iso14229_1 class
            response = uds_client.write_data_by_identifier(did, data_bytes)

            if print_results:
                if response:
                    if Iso14229_1.is_positive_response(response):
                        print(f"Positive response: {list_to_hex_str(response)}")
                    else:
                        nrc = response[2] if len(response) > 2 else None
                        nrc_name = get_negative_response_code_name(nrc) if nrc else "Unknown NRC"
                        print(f"Negative response: {list_to_hex_str(response)} (NRC: 0x{nrc:02X} - {nrc_name})")
                else:
                    print("No response received (timeout).")
            return response

def __write_did_wrapper(args):
    """Wrapper for WriteDataByIdentifier functionality"""
    try:
        write_data_by_identifier(args.src, args.dst, args.did, args.data, args.timeout)
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def discover_writable_dids(arb_id_request, arb_id_response, timeout,
                           min_did, max_did, test_data_hex_str, filter_nrc=None, print_results=True):
    """
    Scans for DIDs that can be written to using a test data pattern.
    Returns a list of DIDs that gave a positive response and a dictionary of DIDs with NRCs.

    :param arb_id_request: arbitration ID for requests
    :param arb_id_response: arbitration ID for responses
    :param timeout: seconds to wait for response before timeout
    :param min_did: minimum DID to scan
    :param max_did: maximum DID to scan
    :param test_data_hex_str: hex string of test data to write
    :param filter_nrc: list of NRC codes to filter out from results, or None to show all
    :param print_results: whether to print results to stdout
    """
    if isinstance(timeout, float) and timeout < 0.0:
        raise ValueError(f"Timeout value ({timeout}) cannot be negative")
    if max_did < min_did:
        raise ValueError(f"max_did (0x{max_did:04X}) must not be smaller than min_did (0x{min_did:04X})")

    writable_dids_positive = []
    dids_with_nrc = {}
    # DIDs that returned an INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT error
    dids_to_probe_length = []

    # Convert filter_nrc to a set for faster lookups
    filter_nrc_set = set(filter_nrc) if filter_nrc else set()

    try:
        clean_hex = test_data_hex_str.replace('0x', '').replace('.', '').replace(' ', '')
        if not clean_hex: # Handle empty string after cleaning
             raise ValueError("Test data cannot be empty.")
        test_data_bytes = list(bytes.fromhex(clean_hex))
    except ValueError as e:
        raise ValueError(f"Invalid test_data format: '{test_data_hex_str}'. Use hex bytes (e.g., '00' or 'AA.BB.CC'). Original error: {e}")

    if print_results:
        print(f"Scanning for writable DIDs in range 0x{min_did:04X}-0x{max_did:04X}")
        print(f"Using test data: {list_to_hex_str(test_data_bytes)} (from input: '{test_data_hex_str}')")
        if filter_nrc:
            filtered_nrc_names = [f"0x{nrc:02X} ({get_negative_response_code_name(nrc)})" for nrc in filter_nrc]
            print(f"Filtering out NRCs: {', '.join(filtered_nrc_names)}")
        print("\n--- Results ---")

    with IsoTp(arb_id_request=arb_id_request, arb_id_response=arb_id_response) as tp:
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds_client:
            if timeout is not None:
                uds_client.P3_CLIENT = timeout

            total_dids = max_did - min_did + 1
            dids_tested = 0
            positive_count = 0
            filtered_count = 0

            for did_to_test in range(min_did, max_did + 1):
                dids_tested += 1
                # 進捗を更新するが、詳細結果は表示しない
                if print_results:
                    progress_pct = (dids_tested / total_dids) * 100
                    print(f"Testing DID 0x{did_to_test:04X}... [{dids_tested}/{total_dids} - {progress_pct:.1f}%] Found: {len(writable_dids_positive)} writable DIDs",
                          end="\r", file=stderr)
                    stderr.flush()

                response = uds_client.write_data_by_identifier(did_to_test, test_data_bytes)

                if response:
                    if Iso14229_1.is_positive_response(response):
                        writable_dids_positive.append(did_to_test)
                        positive_count += 1
                        # ポジティブレスポンスは重要なので個別に表示
                        if print_results:
                            print("\033[K", end="", file=stderr)  # 行をクリア
                            print(f"DID 0x{did_to_test:04X}: Positive Response - {list_to_hex_str(response)}")
                    else:
                        if len(response) >= 3:
                            nrc = response[2]
                            # Collect DIDs with incorrect message length for later probing
                            if nrc == NegativeResponseCodes.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT:
                                dids_to_probe_length.append(did_to_test)

                            if nrc not in filter_nrc_set:
                                nrc_name = get_negative_response_code_name(nrc)
                                entry = f"NRC 0x{nrc:02X} ({nrc_name}) - {list_to_hex_str(response)}"
                                if did_to_test not in dids_with_nrc:
                                    dids_with_nrc[did_to_test] = []
                                dids_with_nrc[did_to_test].append((nrc, entry))
                            else:
                                filtered_count += 1

            # Probe DIDs with incorrect message length error to find valid lengths
            if dids_to_probe_length and print_results:
                print("\033[K", file=stderr)  # Clear line
                print("\n--- Length Probing for DIDs with INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT ---")

                for did_to_probe in dids_to_probe_length:
                    print(f"\nProbing lengths for DID 0x{did_to_probe:04X}:")

                    # Test with different data lengths from 1 to 16 bytes
                    valid_lengths = []

                    for length in range(1, 17):
                        # Create test data of specific length (repeated pattern or padded zeros)
                        if len(test_data_bytes) >= length:
                            # Use first 'length' bytes from original test data
                            length_test_data = test_data_bytes[:length]
                        else:
                            # Pad with zeros if original data is shorter than needed length
                            length_test_data = test_data_bytes + [0] * (length - len(test_data_bytes))

                        print(f"  Testing length {length}: {list_to_hex_str(length_test_data)}", end=" -> ")

                        # Try with the new length
                        response = uds_client.write_data_by_identifier(did_to_probe, length_test_data)

                        if response:
                            if Iso14229_1.is_positive_response(response):
                                valid_lengths.append((length, "Positive Response", response))
                                print(f"SUCCESS - Positive Response: {list_to_hex_str(response)}")
                            else:
                                nrc = response[2] if len(response) >= 3 else None
                                nrc_name = get_negative_response_code_name(nrc) if nrc else "Unknown"

                                if nrc != NegativeResponseCodes.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT:
                                    # Different NRC than before - might indicate correct length but other issues
                                    valid_lengths.append((length, f"Different NRC: 0x{nrc:02X} ({nrc_name})", response))
                                    print(f"INTERESTING - Different NRC: 0x{nrc:02X} ({nrc_name})")
                                else:
                                    print(f"FAIL - Still incorrect length: {list_to_hex_str(response)}")
                        else:
                            print("No response (timeout)")

                        # Add small delay between tests
                        time.sleep(0.1)

                    if valid_lengths:
                        print(f"  Valid data lengths for DID 0x{did_to_probe:04X}:")
                        for length, result_type, resp in valid_lengths:
                            print(f"    Length {length}: {result_type} - {list_to_hex_str(resp)}")
                    else:
                        print(f"  No valid data lengths found for DID 0x{did_to_probe:04X}")

            # 最終的な進捗表示をクリア
            if print_results:
                print("\033[K", file=stderr)
                print(f"\nScan completed: {dids_tested} DIDs tested, {positive_count} writable, {filtered_count} filtered")
                print("\n--- Scan Summary ---")
                if writable_dids_positive:
                    print("Writable DIDs (Positive Response):")
                    for did_val in writable_dids_positive:
                        print(f"  0x{did_val:04X}")
                else:
                    print("No DIDs confirmed writable with a positive response for the given test data.")

                # Group consecutive DIDs with same NRC into ranges
                if dids_with_nrc:
                    print("\nDIDs with Negative Responses:")

                    # Convert dictionary to sorted list of (did, nrc, message) tuples
                    all_nrc_entries = []
                    for did_val, entries in dids_with_nrc.items():
                        for nrc, message in entries:
                            all_nrc_entries.append((did_val, nrc, message))
                    all_nrc_entries.sort()

                    # Group consecutive DIDs with same NRC
                    if all_nrc_entries:
                        current_range_start = all_nrc_entries[0][0]
                        current_nrc = all_nrc_entries[0][1]
                        current_message = all_nrc_entries[0][2]

                        for i in range(1, len(all_nrc_entries)):
                            did_val, nrc, message = all_nrc_entries[i]
                            prev_did = all_nrc_entries[i-1][0]

                            # If consecutive DID with same NRC, continue range
                            if did_val == prev_did + 1 and nrc == current_nrc:
                                continue
                            else:
                                # Print the previous range
                                range_end = prev_did
                                if current_range_start == range_end:
                                    print(f"  DID 0x{current_range_start:04X}:")
                                else:
                                    print(f"  DIDs 0x{current_range_start:04X}-0x{range_end:04X}:")

                                # Extract the NRC info from the message
                                nrc_info = current_message.split(" - ")[0]
                                print(f"    {nrc_info}")

                                # Start a new range
                                current_range_start = did_val
                                current_nrc = nrc
                                current_message = message

                        # Print the last range
                        last_did = all_nrc_entries[-1][0]
                        if current_range_start == last_did:
                            print(f"  DID 0x{current_range_start:04X}:")
                        else:
                            print(f"  DIDs 0x{current_range_start:04X}-0x{last_did:04X}:")

                        # Extract the NRC info from the message
                        nrc_info = current_message.split(" - ")[0]
                        print(f"    {nrc_info}")

    return writable_dids_positive, dids_with_nrc

def __discover_writable_dids_wrapper(args):
    """Wrapper for discover_writable_dids functionality"""
    try:
        discover_writable_dids(args.src, args.dst, args.timeout,
                              args.min_did, args.max_did, args.test_data,
                              filter_nrc=args.filter_nrc,
                              print_results=True)
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def perform_request_upload(arb_id_request, arb_id_response, address, length,
                           compression_encryption, address_length_format,
                           outfile, timeout, print_results=True):
    """
    Performs the Request Upload (0x35) sequence:
    1. Request Upload (0x35)
    2. Transfer Data (0x36) repeatedly
    3. Request Transfer Exit (0x37)
    """
    if print_results:
        print(f"Attempting Request Upload (0x35) from address 0x{address:X} for {length} bytes.")
        print(f"  Request ID: 0x{arb_id_request:X}, Response ID: 0x{arb_id_response:X}")
        print(f"  Compression/Encryption: 0x{compression_encryption:02X}, Address/Length Format: 0x{address_length_format:02X}")
        print(f"  Output file: {outfile}")

    # Determine byte sizes from address_length_format
    # High nibble is length of memorySize, low nibble is length of memoryAddress
    addr_len_bytes = address_length_format & 0x0F
    size_len_bytes = (address_length_format >> 4) & 0x0F

    if not (1 <= addr_len_bytes <= 0xF and 1 <= size_len_bytes <= 0xF): # Max 15, practically usually 1-8
        raise ValueError(f"Invalid addressAndLengthFormatIdentifier: 0x{address_length_format:02X}. "
                         f"Parsed address length: {addr_len_bytes} bytes, size length: {size_len_bytes} bytes. "
                         "Each must be between 1 and 15.")

    try:
        address_bytes = address.to_bytes(addr_len_bytes, byteorder='big')
        length_bytes = length.to_bytes(size_len_bytes, byteorder='big')
    except OverflowError as e:
        raise ValueError(f"Error converting address/length to bytes with format 0x{address_length_format:02X}: {e}. "
                         f"Address 0x{address:X} ({addr_len_bytes} bytes), Length {length} ({size_len_bytes} bytes).")

    received_data = bytearray()
    max_block_length = 0

    with IsoTp(arb_id_request=arb_id_request, arb_id_response=arb_id_response) as tp:
        tp.set_filter_single_arbitration_id(arb_id_response)
        with Iso14229_1(tp) as uds:
            if timeout is not None:
                uds.P3_CLIENT = timeout # Apply timeout for UDS responses

            # Step 1: Request Upload (0x35)
            if print_results:
                print("\n--- Step 1: Request Upload (Service 0x35) ---")
            request_data_35 = bytes([ServiceID.REQUEST_UPLOAD, compression_encryption, address_length_format]) + address_bytes + length_bytes
            if print_results:
                print(f"  Sending: {list_to_hex_str(request_data_35)}")

            tp.send_request(list(request_data_35)) # send_request expects a list
            response_35 = uds.receive_response(timeout=uds.P3_CLIENT) # Use configured timeout

            if response_35 is None:
                print("  Error: No response received for Request Upload (Timeout).")
                return False

            if print_results:
                print(f"  Received: {list_to_hex_str(response_35)}")

            if Iso14229_1.is_positive_response(response_35, ServiceID.REQUEST_UPLOAD):
                # Expected positive response: 0x75 <lengthFormatIdentifier> <maxNumberOfBlockLength>
                # lengthFormatIdentifier (1 byte): bits 7-4: length of maxNumberOfBlockLength (e.g., 2 for 2 bytes)
                #                                 bits 3-0: reserved (or sometimes length of address, but 0 for upload confirm)
                # maxNumberOfBlockLength (n bytes): max size of data in TransferData response
                if len(response_35) < 2:
                    print(f"  Error: Positive response for Request Upload is too short: {list_to_hex_str(response_35)}")
                    return False

                lfi = response_35[1]
                len_of_max_block_len_field = (lfi >> 4) & 0x0F # Number of bytes for maxNumberOfBlockLength

                if len(response_35) < 2 + len_of_max_block_len_field:
                    print(f"  Error: Positive response for Request Upload is too short to contain maxNumberOfBlockLength: {list_to_hex_str(response_35)}")
                    print(f"    LFI indicated {len_of_max_block_len_field} bytes for max block length.")
                    return False

                max_block_length_bytes = response_35[2 : 2 + len_of_max_block_len_field]
                max_block_length = int.from_bytes(bytes(max_block_length_bytes), byteorder='big')
                if print_results:
                    print(f"  Request Upload successful. Max block length: {max_block_length} bytes (0x{max_block_length:X})")
                if max_block_length == 0: # Or too small
                    print(f"  Warning: ECU reported max_block_length of {max_block_length}. This might cause issues or indicate no data.")
                    # Allow to proceed, but it might fail or be slow. Some ECUs might send 0 if no data.
            else:
                print("  Error: Negative response or unexpected response for Request Upload.")
                process_negative_response(response_35)
                return False

            # Step 2: Transfer Data (0x36)
            if print_results:
                print("\n--- Step 2: Transfer Data (Service 0x36) ---")
            block_sequence_counter = 0x01
            total_bytes_received = 0

            # Ensure max_block_length is reasonable if it was not set or very small.
            # This is a safeguard, the ECU should dictate this.
            # If max_block_length from ECU is too small, transfers will be slow but should work.
            # If it's 0, it implies no data or an issue.
            if max_block_length <= 0: # If ECU gives 0 or invalid, this loop won't run correctly for actual data
                if length > 0 :
                    print(f"  Warning: max_block_length is {max_block_length}, but {length} bytes are expected. Transfer might not proceed correctly.")
                else: # length is 0, nothing to transfer
                     if print_results:
                        print("  No data to transfer (requested length is 0).")


            with open(outfile, 'wb') as f:
                while total_bytes_received < length:
                    if print_results:
                        progress_pct = (total_bytes_received / length * 100) if length > 0 else 100
                        print(f"\r  Requesting block {block_sequence_counter:02X}. Received {total_bytes_received}/{length} bytes ({progress_pct:.2f}%).", end="")

                    request_data_36 = [ServiceID.TRANSFER_DATA, block_sequence_counter]
                    # No data parameter from client for upload

                    tp.send_request(request_data_36)
                    response_36 = uds.receive_response(timeout=uds.P3_CLIENT)

                    if response_36 is None:
                        print("\n  Error: No response received for Transfer Data (Timeout).")
                        return False # Or attempt retry? For now, fail.

                    # No need to print every block response unless debugging
                    # if print_results:
                    # print(f" Received for block {block_sequence_counter:02X}: {list_to_hex_str(response_36)}")

                    if Iso14229_1.is_positive_response(response_36, ServiceID.TRANSFER_DATA):
                        if len(response_36) < 2:
                            print(f"\n  Error: Positive response for Transfer Data is too short: {list_to_hex_str(response_36)}")
                            return False
                        if response_36[1] != block_sequence_counter:
                            print(f"\n  Error: Block sequence counter mismatch. Expected 0x{block_sequence_counter:02X}, got 0x{response_36[1]:02X}.")
                            return False

                        block_data = bytes(response_36[2:])
                        f.write(block_data)
                        received_data.extend(block_data)
                        total_bytes_received += len(block_data)

                        if len(block_data) == 0 and total_bytes_received < length :
                             print(f"\n  Warning: Received empty data block {block_sequence_counter:02X} but more data is expected. Transfer might be incomplete.")
                             # Decide if this is an error or if the ECU sometimes sends empty blocks before completion.
                             # For now, continue, but this could be a sign of trouble.

                        block_sequence_counter = (block_sequence_counter + 1) % 0x100 #Wraps around 0xFF to 0x00
                        if block_sequence_counter == 0: # Standard says it wraps to 0x00 if it was 0xFF
                            block_sequence_counter = 0 # Some implementations might go 0x01..0xFF then 0x00 then 0x01
                                                       # But UDS spec says "The blockSequenceCounter shall be incremented by 1 for each TransferData request/response message"
                                                       # "The value of the blockSequenceCounter ranges from 0x00 to 0xFF"
                                                       # "The blockSequenceCounter in the first TransferData request message shall be set to 0x01."
                                                       # If it reaches 0xFF, the next is 0x00.

                    else:
                        if print_results: print() # Newline after progress
                        print("  Error: Negative response or unexpected response for Transfer Data.")
                        process_negative_response(response_36)
                        # Check for specific NRCs like 0x24 (requestSequenceError)
                        # if len(response_36) > 2 and response_36[2] == NegativeResponseCodes.REQUEST_SEQUENCE_ERROR:
                        # print("  NRC 0x24 (Request Sequence Error) - possibly tried to read beyond specified size.")
                        return False
            if print_results:
                print(f"\r  Transfer Data complete. Received {total_bytes_received}/{length} bytes.                         ")
                if total_bytes_received != length:
                     print(f"  Warning: Expected {length} bytes, but received {total_bytes_received} bytes.")


            # Step 3: Request Transfer Exit (0x37)
            if print_results:
                print("\n--- Step 3: Request Transfer Exit (Service 0x37) ---")
            request_data_37 = [ServiceID.REQUEST_TRANSFER_EXIT]
            # No parameters for RAMN ECUs as per doc
            if print_results:
                print(f"  Sending: {list_to_hex_str(request_data_37)}")

            tp.send_request(request_data_37)
            response_37 = uds.receive_response(timeout=uds.P3_CLIENT)

            if response_37 is None:
                print("  Error: No response received for Request Transfer Exit (Timeout).")
                return False

            if print_results:
                print(f"  Received: {list_to_hex_str(response_37)}")

            if Iso14229_1.is_positive_response(response_37, ServiceID.REQUEST_TRANSFER_EXIT):
                if print_results:
                    print("  Request Transfer Exit successful.")
            else:
                print("  Error: Negative response or unexpected response for Request Transfer Exit.")
                process_negative_response(response_37)
                return False

            if print_results:
                print(f"\nUpload sequence completed. Data saved to '{outfile}'. Total bytes: {total_bytes_received}")
            return True

def __request_upload_wrapper(args):
    """Wrapper for Request Upload functionality"""
    try:
        perform_request_upload(
            args.src,
            args.dst,
            args.address,
            args.length,
            args.compression_encryption,
            args.address_length_format,
            args.outfile,
            args.timeout
        )
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nRequest Upload interrupted by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def __parse_args(args):
    """Parser for module arguments"""
    parser = argparse.ArgumentParser(
        prog="caringcaribou uds",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Universal Diagnostic Services module for "
                    "CaringCaribou",
        epilog="""Example usage:
  caringcaribou uds discovery
  caringcaribou uds discovery -blacklist 0x123 0x456
  caringcaribou uds discovery -autoblacklist 10
  caringcaribou uds services 0x733 0x633
  caringcaribou uds ecu_reset 1 0x733 0x633
  caringcaribou uds testerpresent 0x733
  caringcaribou uds security_seed 0x3 0x1 0x733 0x633 -r 1 -d 0.5
  caringcaribou uds dump_dids 0x733 0x633
  caringcaribou uds dump_dids 0x733 0x633 --min_did 0x6300 --max_did 0x6fff -t 0.1
  caringcaribou uds read_mem 0x733 0x633 --start_addr 0x0200 --mem_length 0x10000
  caringcaribou uds write_did 0x7E0 0x7E8 0xF190 AABBCCDD
  caringcaribou uds discover_writable_dids 0x7E0 0x7E8 --min_did 0xF100 --max_did 0xF1FF
  caringcaribou uds discover_writable_dids 0x7E0 0x7E8 --test_data 010203 --filter-nrc 0x31 0x33
  caringcaribou uds request_upload 0x7E0 0x7E8 0x08000000 0x100 --outfile memory_dump.bin""")
    subparsers = parser.add_subparsers(dest="module_function")
    subparsers.required = True

    # Parser for diagnostics discovery
    parser_discovery = subparsers.add_parser("discovery")
    parser_discovery.add_argument("-min",
                                  type=parse_int_dec_or_hex, default=None,
                                  help="min arbitration ID "
                                       "to send request for")
    parser_discovery.add_argument("-max",
                                  type=parse_int_dec_or_hex, default=None,
                                  help="max arbitration ID "
                                       "to send request for")
    parser_discovery.add_argument("-b", "--blacklist", metavar="B",
                                  type=parse_int_dec_or_hex, default=[],
                                  nargs="+",
                                  help="arbitration IDs to blacklist "
                                       "responses from")
    parser_discovery.add_argument("-ab", "--autoblacklist", metavar="N",
                                  type=float, default=0,
                                  help="listen for false positives for N seconds "
                                       "and blacklist matching arbitration "
                                       "IDs before running discovery")
    parser_discovery.add_argument("-sv", "--skipverify",
                                  action="store_true",
                                  help="skip verification step (reduces "
                                       "result accuracy)")
    parser_discovery.add_argument("-d", "--delay", metavar="D",
                                  type=float, default=DELAY_DISCOVERY,
                                  help="D seconds delay between messages "
                                       "(default: {0})".format(DELAY_DISCOVERY))
    parser_discovery.set_defaults(func=__uds_discovery_wrapper)

    # Parser for diagnostics service discovery
    parser_info = subparsers.add_parser("services")
    parser_info.add_argument("src",
                             type=parse_int_dec_or_hex,
                             help="arbitration ID to transmit to")
    parser_info.add_argument("dst",
                             type=parse_int_dec_or_hex,
                             help="arbitration ID to listen to")
    parser_info.add_argument("-t", "--timeout", metavar="T",
                             type=float, default=TIMEOUT_SERVICES,
                             help="wait T seconds for response before "
                                  "timeout (default: {0})"
                             .format(TIMEOUT_SERVICES))
    parser_info.set_defaults(func=__service_discovery_wrapper)

    # Parser for diagnostics session control subservice discovery
    parser_sub = subparsers.add_parser("subservices")
    parser_sub.add_argument("dsc", metavar="dtype",
                            type=parse_int_dec_or_hex, default="0x01",
                            help="Diagnostic Session Control Subsession Byte")
    parser_sub.add_argument("service", metavar="stype",
                            type=parse_int_dec_or_hex,
                            help="Service ID")
    parser_sub.add_argument("src",
                            type=parse_int_dec_or_hex,
                            help="arbitration ID to transmit to")
    parser_sub.add_argument("dst",
                            type=parse_int_dec_or_hex,
                            help="arbitration ID to listen to")
    parser_sub.add_argument("-t", "--timeout", metavar="T",
                            type=float, default=TIMEOUT_SUBSERVICES,
                            help="wait T seconds for response before "
                                 "timeout (default: {0})"
                            .format(TIMEOUT_SUBSERVICES))
    parser_sub.set_defaults(func=__sub_discovery_wrapper)

    # Parser for ECU Reset
    parser_ecu_reset = subparsers.add_parser("ecu_reset")
    parser_ecu_reset.add_argument("reset_type", metavar="type",
                                  type=parse_int_dec_or_hex,
                                  help="Reset type: 1=hard, 2=key off/on, "
                                       "3=soft, "
                                       "4=enable rapid power shutdown, "
                                       "5=disable rapid power shutdown")
    parser_ecu_reset.add_argument("src",
                                  type=parse_int_dec_or_hex,
                                  help="arbitration ID to transmit to")
    parser_ecu_reset.add_argument("dst",
                                  type=parse_int_dec_or_hex,
                                  help="arbitration ID to listen to")
    parser_ecu_reset.add_argument("-t", "--timeout",
                                  type=float, metavar="T",
                                  help="wait T seconds for response before "
                                       "timeout")
    parser_ecu_reset.set_defaults(func=__ecu_reset_wrapper)

    # Parser for TesterPresent
    parser_tp = subparsers.add_parser("testerpresent")
    parser_tp.add_argument("src",
                           type=parse_int_dec_or_hex,
                           help="arbitration ID to transmit to")
    parser_tp.add_argument("-d", "--delay", metavar="D",
                           type=float, default=DELAY_TESTER_PRESENT,
                           help="send TesterPresent every D seconds "
                                "(default: {0})".format(DELAY_TESTER_PRESENT))
    parser_tp.add_argument("-dur", "--duration", metavar="S",
                           type=float,
                           help="automatically stop after S seconds")
    parser_tp.add_argument("-spr", action="store_true",
                           help="suppress positive response")
    parser_tp.set_defaults(func=__tester_present_wrapper)

    # Parser for SecuritySeedDump
    parser_secseed = subparsers.add_parser("security_seed")
    parser_secseed.add_argument("sess_type", metavar="stype",
                                type=parse_int_dec_or_hex,
                                help="Session Type: 1=defaultSession "
                                     "2=programmingSession 3=extendedSession "
                                     "4=safetySession [0x40-0x5F]=OEM "
                                     "[0x60-0x7E]=Supplier "
                                     "[0x0, 0x5-0x3F, 0x7F]=ISOSAEReserved")
    parser_secseed.add_argument("sec_level", metavar="level",
                                type=parse_int_dec_or_hex,
                                help="Security level: "
                                     "[0x1-0x41 (odd only)]=OEM "
                                     "0x5F=EOLPyrotechnics "
                                     "[0x61-0x7E]=Supplier "
                                     "[0x0, 0x43-0x5E, 0x7F]=ISOSAEReserved")
    parser_secseed.add_argument("src",
                                type=parse_int_dec_or_hex,
                                help="arbitration ID to transmit to")
    parser_secseed.add_argument("dst",
                                type=parse_int_dec_or_hex,
                                help="arbitration ID to listen to")
    parser_secseed.add_argument("-r", "--reset", metavar="RTYPE",
                                type=parse_int_dec_or_hex,
                                help="Enable reset between security seed "
                                     "requests. Valid RTYPE integers are: "
                                     "1=hardReset, 2=key off/on, 3=softReset, "
                                     "4=enable rapid power shutdown, "
                                     "5=disable rapid power shutdown. "
                                     "(default: None)")
    parser_secseed.add_argument("-d", "--delay", metavar="D",
                                type=float, default=DELAY_SECSEED_RESET,
                                help="Wait D seconds between reset and "
                                     "security seed request. You'll likely "
                                     "need to increase this when using RTYPE: "
                                     "1=hardReset. Does nothing if RTYPE "
                                     "is None. (default: {0})"
                                .format(DELAY_SECSEED_RESET))
    parser_secseed.add_argument("-n", "--num", metavar="NUM", default=0,
                                type=parse_int_dec_or_hex,
                                help="Specify a positive number of security"
                                     " seeds to capture before terminating. "
                                     "A '0' is interpreted as infinity. "
                                     "(default: 0)")
    parser_secseed.set_defaults(func=__security_seed_wrapper)

    # Parser for dump_did
    parser_did = subparsers.add_parser("dump_dids")
    parser_did.add_argument("src",
                            type=parse_int_dec_or_hex,
                            help="arbitration ID to transmit to")
    parser_did.add_argument("dst",
                            type=parse_int_dec_or_hex,
                            help="arbitration ID to listen to")
    parser_did.add_argument("-t", "--timeout",
                            type=float, metavar="T",
                            default=DUMP_DID_TIMEOUT,
                            help="wait T seconds for response before "
                                 "timeout")
    parser_did.add_argument("--min_did",
                            type=parse_int_dec_or_hex,
                            default=DUMP_WRITABLE_DID_MIN,
                            help="minimum device identifier (DID) to read (default: 0x0000)")
    parser_did.add_argument("--max_did",
                            type=parse_int_dec_or_hex,
                            default=DUMP_WRITABLE_DID_MAX,
                            help="maximum device identifier (DID) to read (default: 0xFFFF)")
    parser_did.set_defaults(func=__dump_dids_wrapper)

    # Parser for read_mem
    parser_mem = subparsers.add_parser("read_mem")
    parser_mem.add_argument("src",
                            type=parse_int_dec_or_hex,
                            help="arbitration ID to transmit to")
    parser_mem.add_argument("dst",
                            type=parse_int_dec_or_hex,
                            help="arbitration ID to listen to")
    parser_mem.add_argument("-t", "--timeout",
                            type=float, metavar="T",
                            default=DUMP_DID_TIMEOUT,
                            help="wait T seconds for response before "
                                 "timeout")
    parser_mem.add_argument("--start_addr",
                            type=parse_int_dec_or_hex,
                            default=MEM_START_ADDR,
                            help=f"starting address (default: {MEM_START_ADDR})")
    parser_mem.add_argument("--mem_length",
                            type=parse_int_dec_or_hex,
                            default=MEM_LEN,
                            help=f"number of bytes to read (default: {MEM_LEN})")
    parser_mem.add_argument("--mem_size",
                            type=parse_int_dec_or_hex,
                            default=MEM_SIZE,
                            help=f"numbers of bytes to return per request (default: {MEM_SIZE})")
    parser_mem.add_argument("--address_byte_size",
                            type=parse_int_dec_or_hex,
                            default=ADDR_BYTE_SIZE,
                            help=f"numbers of bytes of the address (default: {ADDR_BYTE_SIZE})")
    parser_mem.add_argument("--memory_length_byte_size",
                            type=parse_int_dec_or_hex,
                            default=MEM_LEN_BYTE_SIZE,
                            help=f"numbers of bytes of the memory length parameter (default: {MEM_LEN_BYTE_SIZE})")
    parser_mem.add_argument("--outfile",
                            help="filename to write output to")
    parser_mem.set_defaults(func=__read_mem_wrapper)

    # Write Data By Identifier (write_did)
    write_did_parser = subparsers.add_parser("write_did")
    write_did_parser.add_argument("src", help="arbitration ID to transmit to", type=parse_int_dec_or_hex)
    write_did_parser.add_argument("dst", help="arbitration ID to listen to", type=parse_int_dec_or_hex)
    write_did_parser.add_argument("did", help="Data Identifier (2 bytes hex, e.g., 0x1234)", type=lambda x: int(x, 16))
    write_did_parser.add_argument("data", help="Data to write (hex bytes separated by dots, e.g., AA.BB.CC)", type=str)
    write_did_parser.add_argument("-t", "--timeout", help="wait T seconds for response before timeout", type=float, default=DUMP_DID_TIMEOUT)
    write_did_parser.set_defaults(func=__write_did_wrapper)

    write_did_parser.set_defaults(func=__write_did_wrapper)

    # Parser for discover_writable_dids
    parser_discover_write_did = subparsers.add_parser("discover_writable_dids")
    parser_discover_write_did.add_argument("src", type=parse_int_dec_or_hex,
                                          help="Arbitration ID to transmit to")
    parser_discover_write_did.add_argument("dst", type=parse_int_dec_or_hex,
                                          help="Arbitration ID to listen to")
    parser_discover_write_did.add_argument("--test_data", type=str,
                                          default=DEFAULT_TEST_DATA_HEX,
                                          help="Hex string of test data to attempt writing (e.g., '00' or 'AA.BB', "
                                               f"default: '{DEFAULT_TEST_DATA_HEX}')")
    parser_discover_write_did.add_argument("--min_did", type=parse_int_dec_or_hex,
                                          default=DUMP_WRITABLE_DID_MIN,
                                          help="Minimum DID to scan "
                                               f"(default: 0x{DUMP_WRITABLE_DID_MIN:04X})")
    parser_discover_write_did.add_argument("--max_did", type=parse_int_dec_or_hex,
                                          default=DUMP_WRITABLE_DID_MAX,
                                          help="Maximum DID to scan "
                                               f"(default: 0x{DUMP_WRITABLE_DID_MAX:04X})")
    parser_discover_write_did.add_argument("-t", "--timeout", type=float,
                                          default=DUMP_WRITABLE_DID_TIMEOUT,
                                          help="Wait T seconds for response before timeout "
                                               f"(default: {DUMP_WRITABLE_DID_TIMEOUT})")
    parser_discover_write_did.add_argument("--filter-nrc", type=parse_int_dec_or_hex, nargs="+",
                                          help="Filter out specific NRC codes from results, common values: "
                                               "0x31 (REQUEST_OUT_OF_RANGE), 0x33 (SECURITY_ACCESS_DENIED)")
    parser_discover_write_did.set_defaults(func=__discover_writable_dids_wrapper)

    # Parser for Request Upload (0x35)
    parser_request_upload = subparsers.add_parser("request_upload", help="Request data upload from ECU (e.g., dump RAM/Flash).")
    parser_request_upload.add_argument("src", type=parse_int_dec_or_hex,
                                       help="Arbitration ID to transmit to (client ID).")
    parser_request_upload.add_argument("dst", type=parse_int_dec_or_hex,
                                       help="Arbitration ID to listen to (server/ECU ID).")
    parser_request_upload.add_argument("address", type=parse_int_dec_or_hex,
                                       help="Memory address to start upload from (e.g., 0x08000000).")
    parser_request_upload.add_argument("length", type=parse_int_dec_or_hex,
                                       help="Number of bytes to upload (e.g., 0x100 for 256 bytes).")
    parser_request_upload.add_argument("--outfile", type=str, required=True,
                                       help="File to save the uploaded data.")
    parser_request_upload.add_argument("--compression_encryption", type=parse_int_dec_or_hex,
                                       default=DEFAULT_COMPRESSION_ENCRYPTION,
                                       help="Compression and encryption method byte "
                                            f"(default: 0x{DEFAULT_COMPRESSION_ENCRYPTION:02X} for none).")
    parser_request_upload.add_argument("--address_length_format", type=parse_int_dec_or_hex,
                                       default=DEFAULT_ADDRESS_LENGTH_FORMAT,
                                       help="Format byte for address and length fields "
                                            f"(default: 0x{DEFAULT_ADDRESS_LENGTH_FORMAT:02X} for 4-byte address, 4-byte size). "
                                            "High nibble=size length, Low nibble=address length.")
    parser_request_upload.add_argument("-t", "--timeout", type=float,
                                       default=DEFAULT_REQUEST_UPLOAD_TIMEOUT,
                                       help="Timeout in seconds for each UDS step "
                                            f"(default: {DEFAULT_REQUEST_UPLOAD_TIMEOUT}s).")
    parser_request_upload.set_defaults(func=__request_upload_wrapper)


    # Parser for auto
    parser_auto = subparsers.add_parser("auto")
    parser_auto.add_argument("-min",
                             type=parse_int_dec_or_hex, default=None,
                             help="min arbitration ID "
                                  "to send request for")
    parser_auto.add_argument("-max",
                             type=parse_int_dec_or_hex, default=None,
                             help="max arbitration ID "
                                  "to send request for")
    parser_auto.add_argument("-b", "--blacklist", metavar="B",
                             type=parse_int_dec_or_hex, default=[],
                             nargs="+",
                             help="arbitration IDs to blacklist "
                                  "responses from")
    parser_auto.add_argument("-ab", "--autoblacklist", metavar="N",
                             type=float, default=0,
                             help="listen for false positives for N seconds "
                                  "and blacklist matching arbitration "
                                  "IDs before running discovery")
    parser_auto.add_argument("-sv", "--skipverify",
                             action="store_true",
                             help="skip verification step (reduces "
                                  "result accuracy)")
    parser_auto.add_argument("-d", "--delay", metavar="D",
                             type=float, default=DELAY_DISCOVERY,
                             help="D seconds delay between messages "
                                  "(default: {0})".format(DELAY_DISCOVERY))
    parser_auto.add_argument("-t", "--timeout", metavar="T",
                             type=float, default=TIMEOUT_SERVICES,
                             help="wait T seconds for response before "
                                  "timeout (default: {0})"
                             .format(TIMEOUT_SERVICES))
    parser_auto.add_argument("--min_did",
                             type=parse_int_dec_or_hex,
                             default=DUMP_DID_MIN,
                             help="minimum device identifier (DID) to read (default: 0x0000)")
    parser_auto.add_argument("--max_did",
                             type=parse_int_dec_or_hex,
                             default=DUMP_DID_MAX,
                             help="maximum device identifier (DID) to read (default: 0xFFFF)")
    parser_auto.set_defaults(func=__auto_wrapper)

    args = parser.parse_args(args)
    return args


def module_main(arg_list):
    """Module main wrapper"""
    try:
        args = __parse_args(arg_list)
        args.func(args)
    except KeyboardInterrupt:
        print("\n\nTerminated by user")
    except Exception as e:
        print(f"\nAn unexpected error occurred in module_main: {e}")