"""
Flow-level feature helpers extracted from data_process/dataset_generation.py.
Only the functions used by standalone inference are kept; heavy dependencies
(scapy, flowcontainer) are imported lazily so that packet-mode users do not
need them installed.
"""

import binascii


def _cut(obj, sec):
    result = [obj[i:i + sec] for i in range(0, len(obj), sec)]
    try:
        remanent_count = len(result[0]) % 4
    except Exception:
        remanent_count = 0
    if remanent_count != 0:
        result = [obj[i:i + sec + remanent_count] for i in range(0, len(obj), sec + remanent_count)]
    return result


def bigram_generation(packet_datagram, packet_len=64, flag=True):
    result = ""
    generated_datagram = _cut(packet_datagram, 1)
    token_count = 0
    for sub_string_index in range(len(generated_datagram)):
        if sub_string_index != (len(generated_datagram) - 1):
            token_count += 1
            if token_count > packet_len:
                break
            merge_word_bigram = generated_datagram[sub_string_index] + generated_datagram[sub_string_index + 1]
        else:
            break
        result += merge_word_bigram
        result += " "
    return result


def get_feature_packet(label_pcap, payload_len):
    import scapy.all as scapy

    feature_data = []
    packets = scapy.rdpcap(label_pcap)
    packet_data_string = ""

    for packet in packets:
        packet_data = packet.copy()
        data = binascii.hexlify(bytes(packet_data))
        packet_string = data.decode()
        new_packet_string = packet_string[76:]
        packet_data_string += bigram_generation(new_packet_string, packet_len=payload_len, flag=True)
        break

    feature_data.append(packet_data_string)
    return feature_data


def get_feature_flow(label_pcap, payload_len, payload_pac):
    import scapy.all as scapy
    from flowcontainer.extractor import extract

    feature_data = []
    packets = scapy.rdpcap(label_pcap)
    packet_count = 0
    flow_data_string = ""

    feature_result = extract(
        label_pcap,
        filter="tcp",
        extension=["tls.record.content_type", "tls.record.opaque_type", "tls.handshake.type"],
    )
    if len(feature_result) == 0:
        feature_result = extract(label_pcap, filter="udp")
        if len(feature_result) == 0:
            return -1
        extract_keys = list(feature_result.keys())[0]
        if len(feature_result[label_pcap, extract_keys[1], extract_keys[2]].ip_lengths) < 3:
            print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
            return -1
    elif len(packets) < 3:
        print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
        return -1

    try:
        if len(feature_result[label_pcap, "tcp", "0"].ip_lengths) < 3:
            print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
            return -1
    except Exception:
        for key in feature_result.keys():
            if len(feature_result[key].ip_lengths) < 3:
                print("preprocess flow %s but this flow has less than 3 packets." % label_pcap)
                return -1

    if not feature_result:
        return -1

    for packet in packets:
        packet_count += 1
        if packet_count == payload_pac:
            packet_data = packet.copy()
            data = binascii.hexlify(bytes(packet_data))
            packet_string = data.decode()[76:]
            flow_data_string += bigram_generation(packet_string, packet_len=payload_len, flag=True)
            break
        else:
            packet_data = packet.copy()
            data = binascii.hexlify(bytes(packet_data))
            packet_string = data.decode()[76:]
            flow_data_string += bigram_generation(packet_string, packet_len=payload_len, flag=True)

    feature_data.append(flow_data_string)
    return feature_data
