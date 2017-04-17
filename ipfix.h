/*_
 * Copyright (c) 2017 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _IPFIX_H
#define _IPFIX_H

#include <stdio.h>
#include <stdint.h>

struct ipfix_header {
    uint16_t version;           /* == 10 */
    uint16_t length;            /* in bytes */
    uint32_t timestamp;
    uint32_t flowseq;           /* FlowSequence */
    uint32_t obs_dom_id;        /* Observation Domain Id */
} __attribute__ ((packed));

struct ipfix_set_header {
    uint16_t id;
    uint16_t length;
} __attribute__ ((packed));

struct ipfix_template_header {
    uint16_t template_id;
    uint16_t field_count;
};

struct ipfix_template_field {
    uint16_t type;
    uint16_t length;
};

/* https://www.iana.org/assignments/ipfix/ipfix.xhtml */
enum ipfix_element_id {
    octetDeltaCount = 1,
    packetDeltaCount = 2,
    deltaFlowCount = 3,
    protocolIdentifier = 4,
    ipClassOfService = 5,
    tcpControlBits = 6,
    sourceTransportPort = 7,
    sourceIPv4Address = 8,
    sourceIPv4PrefixLength = 9,
    ingressInterface = 10,
    destinationTransportPort = 11,
    destinationIPv4Address = 12,
    destinationIPv4PrefixLength = 13,
    egressInterface = 14,
    ipNextHopIPv4Address = 15,
    bgpSourceAsNumber = 16,
    bgpDestinationAsNumber = 17,
    bgpNextHopIPv4Address = 18,
    postMCastPacketDeltaCount = 19,
    postMCastOctetDeltaCount = 20,
    flowEndSysUpTime = 21,
    flowStartSysUpTime = 22,
    postOctetDeltaCount = 23,
    postPacketDeltaCount = 24,
    minimumIpTotalLength = 25,
    maximumIpTotalLength = 26,
    sourceIPv6Address = 27,
    destinationIPv6Address = 28,
    sourceIPv6PrefixLength = 29,
    destinationIPv6PrefixLength = 30,
    flowLabelIPv6 = 31,
    icmpTypeCodeIPv4 = 32,
    igmpType = 33,
    samplingInterval = 34,
    samplingAlgorithm = 35,
    flowActiveTimeout = 36,
    flowIdleTimeout = 37,
    engineType = 38,
    engineId = 39,
    exportedOctetTotalCount = 40,
    exportedMessageTotalCount = 41,
    exportedFlowRecordTotalCount = 42,
    ipv4RouterSc = 43,
    sourceIPv4Prefix = 44,
    destinationIPv4Prefix = 45,
    mplsTopLabelType = 46,
    mplsTopLabelIPv4Address = 47,
    samplerId = 48,
    samplerMode = 49,
    samplerRandomInterval = 50,
    classId = 51,
    minimumTTL = 52,
    maximumTTL = 53,
    fragmentIdentification = 54,
    postIpClassOfService = 55,
    sourceMacAddress = 56,
    postDestinationMacAddress = 57,
    vlanId = 58,
    postVlanId = 59,
    ipVersion = 60,
    flowDirection = 61,
    ipNextHopIPv6Address = 62,
    bgpNextHopIPv6Address = 63,
    ipv6ExtensionHeaders = 64,
    mplsTopLabelStackSection = 70,
    mplsLabelStackSection2 = 71,
    mplsLabelStackSection3 = 72,
    mplsLabelStackSection4 = 73,
    mplsLabelStackSection5 = 74,
    mplsLabelStackSection6 = 75,
    mplsLabelStackSection7 = 76,
    mplsLabelStackSection8 = 77,
    mplsLabelStackSection9 = 78,
    mplsLabelStackSection10 = 79,
    destinationMacAddress = 80,
    postSourceMacAddress = 81,
    interfaceName = 82,
    interfaceDescription = 83,
    samplerName = 84,
    octetTotalCount = 85,
    packetTotalCount = 86,
    flagsAndSamplerId = 87,
    fragmentOffset = 88,
    forwardingStatus = 89,
    mplsVpnRouteDistinguisher = 90,
    mplsTopLabelPrefixLength = 91,
    srcTrafficIndex = 92,
    dstTrafficIndex = 93,
    applicationDescription = 94,
    applicationId = 95,
    applicationName = 96,
    postIpDiffServCodePoint = 98,
    multicastReplicationFactor = 99,
    className = 100,
    classificationEngineId = 101,
    layer2packetSectionOffset = 102,
    layer2packetSectionSize = 103,
    layer2packetSectionData = 104,
    bgpNextAdjacentAsNumber = 128,
    bgpPrevAdjacentAsNumber = 129,
    exporterIPv4Address = 130,
    exporterIPv6Address = 131,
    droppedOctetDeltaCount = 132,
    droppedPacketDeltaCount = 133,
    droppedOctetTotalCount = 134,
    droppedPacketTotalCount = 135,
    flowEndReason = 136,
    commonPropertiesId = 137,
    observationPointId = 138,
    icmpTypeCodeIPv6 = 139,
    mplsTopLabelIPv6Address = 140,
    lineCardId = 141,
    portId = 142,
    meteringProcessId = 143,
    exportingProcessId = 144,
    templateId = 145,
    wlanChannelId = 146,
    wlanSSID = 147,
    flowId = 148,
    observationDomainId = 149,
    flowStartSeconds = 150,
    flowEndSeconds = 151,
    flowStartMilliseconds = 152,
    flowEndMilliseconds = 153,
    flowStartMicroseconds = 154,
    flowEndMicroseconds = 155,
    flowStartNanoseconds = 156,
    flowEndNanoseconds = 157,
    flowStartDeltaMicroseconds = 158,
    flowEndDeltaMicroseconds = 159,
    systemInitTimeMilliseconds = 160,
    flowDurationMilliseconds = 161,
    flowDurationMicroseconds = 162,
    observedFlowTotalCount = 163,
    ignoredPacketTotalCount = 164,
    ignoredOctetTotalCount = 165,
    notSentFlowTotalCount = 166,
    notSentPacketTotalCount = 167,
    notSentOctetTotalCount = 168,
    destinationIPv6Prefix = 169,
    sourceIPv6Prefix = 170,
    postOctetTotalCount = 171,
    postPacketTotalCount = 172,
    flowKeyIndicator = 173,
    postMCastPacketTotalCount = 174,
    postMCastOctetTotalCount = 175,
    icmpTypeIPv4 = 176,
    icmpCodeIPv4 = 177,
    icmpTypeIPv6 = 178,
    icmpCodeIPv6 = 179,
    udpSourcePort = 180,
    udpDestinationPort = 181,
    tcpSourcePort = 182,
    tcpDestinationPort = 183,
    tcpSequenceNumber = 184,
    tcpAcknowledgementNumber = 185,
    tcpWindowSize = 186,
    tcpUrgentPointer = 187,
    tcpHeaderLength = 188,
    ipHeaderLength = 189,
    totalLengthIPv4 = 190,
    payloadLengthIPv6 = 191,
    ipTTL = 192,
    nextHeaderIPv6 = 193,
    mplsPayloadLength = 194,
    ipDiffServCodePoint = 195,
    ipPrecedence = 196,
    fragmentFlags = 197,
    octetDeltaSumOfSquares = 198,
    octetTotalSumOfSquares = 199,
    mplsTopLabelTTL = 200,
    mplsLabelStackLength = 201,
    mplsLabelStackDepth = 202,
    mplsTopLabelExp = 203,
    ipPayloadLength = 204,
    udpMessageLength = 205,
    isMulticast = 206,
    ipv4IHL = 207,
    ipv4Options = 208,
    tcpOptions = 209,
    paddingOctets = 210,
    collectorIPv4Address = 211,
    collectorIPv6Address = 212,
    exportInterface = 213,
    exportProtocolVersion = 214,
    exportTransportProtocol = 215,
    collectorTransportPort = 216,
    exporterTransportPort = 217,
};

enum ipfix_flow_selector_algorithm {
    systematicCountBasedSampling = 1,
    systematicTimeBasedSampling = 2,
    randomNOutOfNSampling = 3,
    uniformProbabilisticSampling = 4,
    propertyMatchFiltering = 5,
    hashBasedFilteringUsingBOB = 6,
    hashBasedFilteringUsingIPSX = 7,
    hashBasedFilteringUsingCRC = 8,
    flowStateDependentIntermediateFlowSelectionProcess = 9,
};

enum ipfix_set_id {
    templateSet = 2,
    optionsTemplateSet = 3,
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* _IPFIX_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
