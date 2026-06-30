"""
amf_ue_ngap_id.py — O-RAN multidomain DDoS proposal.

Decodes the "amf_ue_ngap_id" field FlexRIC's xApps print for each UE in a
KPM indication back into the real ns-3 IMSI that identifies it.

Confirmed against real source (mmwave-LENA-oran fork, contrib/oran-interface/
model/kpm-indication.cc and src/mmwave/model/mmwave-enb-net-device.cc):

  - MmWaveEnbNetDevice::GetImsiString(imsi) (mmwave-enb-net-device.cc:~905)
    zero-pads the IMSI to a fixed 5-character decimal string, e.g. IMSI 1
    -> "00001", IMSI 42 -> "00042".
  - That string is passed to MeasurementItemList's constructor
    (mmwave-enb-net-device.cc:1129/2034 call sites), which wraps it in an
    OctetString verbatim (kpm-indication.cc: MeasurementItemList::
    MeasurementItemList(std::string id) -> m_id = Create<OctetString>(id,
    id.length())) -- i.e. the OCTET STRING's bytes are just the string's
    raw ASCII characters, 5 bytes, not a binary-encoded integer.
  - KpmIndicationMessage::FillUeID (kpm-indication.cc:1085-1087) sets
    amf_UE_NGAP_ID via:
      asn_ulong2INTEGER(&gnb_asn->amf_UE_NGAP_ID,
        static_cast<unsigned long>(
          KpmIndicationHeader::octet_string_to_int_64(ueIndication->GetId())))
    where octet_string_to_int_64 (kpm-indication.cc:194-202) does a plain
    `memcpy(&x, asn.buf, asn.size)` into a uint64_t initialized to 0 --
    i.e. it reinterprets those same 5 ASCII bytes as a little-endian
    uint64 (x86_64 is little-endian), not a real 3GPP AMF-UE-NGAP-ID.

    (There's a second, unused code path in the same file,
    FillKpmIndicationMessageFormat3 at kpm-indication.cc:1034, that sets
    amf_UE_NGAP_ID to `rand() % 112358132134` -- a real dead/dummy
    function, not the one actually invoked when building indications from
    live measurements. Looking only at xapp_kpm_moni's *printed* values
    without reading both call sites would have wrongly suggested the
    field is unrecoverable noise.)

Verified end to end against two real observed values from this session's
own test run (test_oran_e2_logging.cc, 2 UEs): amf_ue_ngap_id 211261861936
decodes to IMSI 1, and 215556829232 decodes to IMSI 2 -- matching ns-3's
own sequential IMSI assignment for those two UEs exactly.
"""

IMSI_STRING_WIDTH = 5


def amf_ue_ngap_id_to_imsi(amf_ue_ngap_id: int) -> int:
    """
    Reverses FillUeID's encoding: take the low IMSI_STRING_WIDTH bytes,
    decode as ASCII digits, parse as an int.

    Raises ValueError if amf_ue_ngap_id doesn't decode to IMSI_STRING_WIDTH
    ASCII digits -- e.g. if it actually came from the dead rand()-based
    code path above, or from a differently-configured agent.
    """
    raw = amf_ue_ngap_id.to_bytes(IMSI_STRING_WIDTH, byteorder="little")
    digits = raw.decode("ascii")
    if not digits.isdigit():
        raise ValueError(
            f"amf_ue_ngap_id {amf_ue_ngap_id} does not decode to "
            f"{IMSI_STRING_WIDTH} ASCII digits (got {digits!r}) -- not a "
            f"real IMSI-derived value from FillUeID's encoding"
        )
    return int(digits)
