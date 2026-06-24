/*
 * test_oran_e2_logging.cc — O-RAN multidomain DDoS proposal.
 *
 * Minimal smoke test, NOT the attack scenario — built to answer one
 * question before writing scenario-zero-oran.cc for real: does
 * mmwave-LENA-oran's native E2/KPM reporting (EnableE2FileLogging,
 * confirmed DL-only) coexist cleanly with our own per-UE UPLINK byte
 * trace (the same Ipv4L3Protocol::Tx technique used in the earlier
 * LTE-based scenario-zero-ddos.cc), and does the real E2Termination
 * actually connect to a live FlexRIC nearRT-RIC (replacing
 * emu_agent_gnb from the smoke test in the previous step) without
 * blocking the simulation.
 *
 * Topology: 1 LTE eNB + 1 mmWave gNB (co-located) + N UEs as
 * McUeNetDevice (multi-connectivity — this fork's UE device needs
 * both an LTE and an mmWave leg; E2ModeLte=false below just means the
 * LTE side doesn't ALSO send its own E2 reports, not that the LTE eNB
 * can be omitted). Mirrors scratch/scenario-zero.cc's verified
 * topology-construction calls (MmWaveHelper, MmWavePointToPointEpcHelper,
 * InstallLteEnbDevice/InstallEnbDevice/InstallMcUeDevice, AddX2Interface,
 * AttachToClosestEnb) almost verbatim — only trimmed down and stripped
 * of that scenario's mobility/mode-switching complexity.
 *
 * Run alongside a live FlexRIC nearRT-RIC (already validated standalone
 * in the previous step):
 *   Terminal A: cd ~/flexric && ./build/examples/ric/nearRT-RIC
 *   Terminal B: this binary
 *
 * Expect, if everything works:
 *   - Terminal A logs an E2 SETUP-REQUEST from a NEW E2 node (this
 *     ns-3 process), distinct from emu_agent_gnb.
 *   - du-cell-<nrCellId>.txt appears in the cwd with real per-UE DL
 *     KPM rows (RRU.PrbUsedDl.UEID, DRB.UEThpDl.UEID, ...).
 *   - ue_ul_traffic.csv (ours) appears with non-zero ul_thr_mbps for
 *     whichever UE the OnOff UL application is attached to.
 *
 * Several call signatures below (pathloss/channel condition model type
 * strings, AddX2Interface/AttachToClosestEnb argument order, the
 * UE default-route pattern) are copied from real source already
 * fetched and confirmed in this session — except the UE default-route
 * lines, which follow the standard ns-3 LTE/mmWave EPC convention
 * (GetUeDefaultGatewayAddress) and haven't been re-confirmed
 * specifically against this fork's MmWavePointToPointEpcHelper; check
 * that one against the installed tree if it doesn't compile.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/mmwave-helper.h"
#include "ns3/mmwave-point-to-point-epc-helper.h"
#include "ns3/mc-ue-net-device.h"

#include <fstream>
#include <map>

using namespace ns3;
using namespace ns3::mmwave;

NS_LOG_COMPONENT_DEFINE("TestOranE2Logging");

// ---------------------------------------------------------------------------
// Our own per-UE UPLINK byte tracker — mmwave-LENA-oran's native E2/KPM
// reporting is DL-only (confirmed: ulPrbUsage is a literal 0/TODO in
// BuildRicIndicationMessageDu), so this is the UL-side counterpart,
// independent of E2 entirely.
// ---------------------------------------------------------------------------

class UplinkTracker
{
public:
  UplinkTracker(std::string csvPath, Time period) : m_period(period)
  {
    m_csv.open(csvPath, std::ios::out | std::ios::trunc);
    m_csv << "timestamp,imsi,ul_bytes,ul_thr_mbps\n";
  }

  void TrackUe(Ptr<Node> ueNode, uint64_t imsi) { m_imsiByNodeId[ueNode->GetId()] = imsi; }

  void ConnectTrace()
  {
    Config::ConnectWithoutContext("/NodeList/*/$ns3::Ipv4L3Protocol/Tx",
                                   MakeCallback(&UplinkTracker::OnTx, this));
  }

  void Start() { Simulator::Schedule(m_period, &UplinkTracker::Tick, this); }

private:
  void OnTx(Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t interface)
  {
    Ptr<Node> node = ipv4->GetObject<Node>();
    if (node)
      {
        m_bytesByNodeId[node->GetId()] += packet->GetSize();
      }
  }

  void Tick()
  {
    double now = Simulator::Now().GetSeconds();
    double periodS = m_period.GetSeconds();

    for (auto &kv : m_imsiByNodeId)
      {
        uint32_t nodeId = kv.first;
        uint64_t imsi = kv.second;
        uint64_t bytes = m_bytesByNodeId[nodeId];
        m_bytesByNodeId[nodeId] = 0;

        double thrMbps = (bytes * 8.0 / periodS) / 1e6;
        m_csv << now << "," << imsi << "," << bytes << "," << thrMbps << "\n";
      }

    m_csv.flush();
    Simulator::Schedule(m_period, &UplinkTracker::Tick, this);
  }

  std::ofstream m_csv;
  Time m_period;
  std::map<uint32_t, uint64_t> m_imsiByNodeId;
  std::map<uint32_t, uint64_t> m_bytesByNodeId;
};

int
main(int argc, char *argv[])
{
  // A live SCTP session to FlexRIC needs to stay up long enough, in
  // REAL wall-clock time, for an xApp started by hand in another
  // terminal to connect and subscribe. ns-3's default simulator
  // implementation advances simulated time as fast as the CPU allows
  // (the whole simTime window can complete in well under a real
  // second) -- RealtimeSimulatorImpl paces simulated time 1:1 against
  // the wall clock instead, the standard ns-3 mechanism for any
  // scenario that talks to a real external process mid-run.
  GlobalValue::Bind("SimulatorImplementationType",
                     StringValue("ns3::RealtimeSimulatorImpl"));

  double simTime = 10.0;
  uint32_t nUe = 2;
  std::string ricAddr = "127.0.0.1";
  uint16_t ricPort = 36421;

  CommandLine cmd;
  cmd.AddValue("simTime", "Simulation duration (s)", simTime);
  cmd.AddValue("nUe", "Number of UEs", nUe);
  cmd.AddValue("ricAddr", "FlexRIC nearRT-RIC address", ricAddr);
  cmd.AddValue("ricPort", "FlexRIC nearRT-RIC E2 port", ricPort);
  cmd.Parse(argc, argv);

  // --- E2/KPM config — confirmed attribute names/types from
  // mmwave-helper.cc (helper-level) and mmwave-enb-net-device.cc
  // (device-level) ---
  Config::SetDefault("ns3::MmWaveHelper::E2ModeNr", BooleanValue(true));
  Config::SetDefault("ns3::MmWaveHelper::E2ModeLte", BooleanValue(false));
  Config::SetDefault("ns3::MmWaveHelper::E2TermIp", StringValue(ricAddr));
  Config::SetDefault("ns3::MmWaveHelper::E2Port", UintegerValue(ricPort));
  Config::SetDefault("ns3::MmWaveEnbNetDevice::E2Periodicity", DoubleValue(0.1));
  Config::SetDefault("ns3::MmWaveEnbNetDevice::KPM_E2functionID", DoubleValue(2));
  Config::SetDefault("ns3::MmWaveEnbNetDevice::RC_E2functionID", DoubleValue(3));
  // false, not true: confirmed SetE2Termination() only calls
  // RegisterKpmCallbackToE2Sm/RegisterSmCallbackToE2Sm/
  // RegisterCallbackFunctionToE2Sm when m_forceE2FileLogging is
  // false -- the two modes are mutually exclusive in this codebase.
  // With it true (the first two test runs), the E2 SETUP-REQUEST went
  // out with zero registered RAN functions, crashing FlexRIC's
  // nearRT-RIC. This run trades the CSV output for a real, subscribable
  // KPM function -- verify against a real xApp (xapp_kpm_moni) instead.
  Config::SetDefault("ns3::MmWaveEnbNetDevice::EnableE2FileLogging", BooleanValue(false));

  // --- Topology — mirrors scratch/scenario-zero.cc's verified calls ---
  Ptr<MmWaveHelper> mmwaveHelper = CreateObject<MmWaveHelper>();
  mmwaveHelper->SetPathlossModelType("ns3::ThreeGppUmiStreetCanyonPropagationLossModel");
  mmwaveHelper->SetChannelConditionModelType("ns3::ThreeGppUmiStreetCanyonChannelConditionModel");

  Ptr<MmWavePointToPointEpcHelper> epcHelper = CreateObject<MmWavePointToPointEpcHelper>();
  mmwaveHelper->SetEpcHelper(epcHelper);

  Ptr<Node> pgw = epcHelper->GetPgwNode();

  NodeContainer remoteHostContainer;
  remoteHostContainer.Create(1);
  Ptr<Node> remoteHost = remoteHostContainer.Get(0);
  InternetStackHelper internet;
  internet.Install(remoteHostContainer);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("10Gb/s"));
  p2p.SetChannelAttribute("Delay", StringValue("10ms"));
  NetDeviceContainer internetDevices = p2p.Install(pgw, remoteHost);

  Ipv4AddressHelper ipv4h;
  ipv4h.SetBase("1.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);
  Ipv4Address remoteHostAddr = internetIpIfaces.GetAddress(1);

  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> remoteHostStaticRouting =
    ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
  remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

  NodeContainer lteEnbNodes;
  lteEnbNodes.Create(1);
  NodeContainer mmWaveEnbNodes;
  mmWaveEnbNodes.Create(1);
  NodeContainer ueNodes;
  ueNodes.Create(nUe);

  MobilityHelper mobility;
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(lteEnbNodes);
  mobility.Install(mmWaveEnbNodes);
  mobility.Install(ueNodes);

  for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
      ueNodes.Get(i)->GetObject<MobilityModel>()->SetPosition(Vector(10.0 + i * 5.0, 0.0, 1.5));
    }

  NetDeviceContainer lteEnbDevs = mmwaveHelper->InstallLteEnbDevice(lteEnbNodes);
  NetDeviceContainer mmWaveEnbDevs = mmwaveHelper->InstallEnbDevice(mmWaveEnbNodes);
  NetDeviceContainer mcUeDevs = mmwaveHelper->InstallMcUeDevice(ueNodes);

  internet.Install(ueNodes);
  Ipv4InterfaceContainer ueIpIface =
    epcHelper->AssignUeIpv4Address(NetDeviceContainer(mcUeDevs));

  // Standard ns-3 LTE/mmWave EPC default-route pattern — verify against
  // the installed tree if MmWavePointToPointEpcHelper doesn't expose
  // GetUeDefaultGatewayAddress() under that exact name.
  for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
      Ptr<Ipv4StaticRouting> ueStaticRouting =
        ipv4RoutingHelper.GetStaticRouting(ueNodes.Get(i)->GetObject<Ipv4>());
      ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

  mmwaveHelper->AddX2Interface(lteEnbNodes, mmWaveEnbNodes);
  mmwaveHelper->AttachToClosestEnb(mcUeDevs, mmWaveEnbDevs, lteEnbDevs);

  // Also confirmed missing: EnableE2PdcpTraces()/EnableE2RlcTraces()
  // get called internally, but the DU/PHY side (E2DuCalculator reuses
  // m_phyStats, an MmWavePhyTrace) is never wired to real trace
  // sources unless EnableDlPhyTrace()/EnableEnbSchedTrace() are called
  // explicitly.
  mmwaveHelper->EnableDlPhyTrace();
  mmwaveHelper->EnableEnbSchedTrace();

  // Do NOT call e2term->Start() ourselves: confirmed
  // MmWaveEnbNetDevice::UpdateConfig() (called from DoInitialize())
  // already does `if (!m_forceE2FileLogging) Simulator::Schedule
  // (MicroSeconds(0), &E2Termination::Start, m_e2term)`. Calling it a
  // second time here caused a duplicate SCTP bind on the same source
  // port ("Cannot assign requested address") and crashed ns-3 with
  // SIGSEGV in the previous run. Just confirm the attribute exists,
  // for visibility.
  for (uint32_t i = 0; i < mmWaveEnbDevs.GetN(); ++i)
    {
      PointerValue ptr;
      mmWaveEnbDevs.Get(i)->GetAttribute("E2Termination", ptr);
      Ptr<E2Termination> e2term = ptr.Get<E2Termination>();
      std::cout << "[test_oran_e2_logging] gNB device " << i << " E2Termination attribute "
                << (e2term ? "present (device will auto-start it)" : "MISSING") << std::endl;
    }

  // --- Our own UL tracker ---
  UplinkTracker ulTracker("ue_ul_traffic.csv", MilliSeconds(500));
  for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
      Ptr<McUeNetDevice> ueDev = DynamicCast<McUeNetDevice>(mcUeDevs.Get(i));
      ulTracker.TrackUe(ueNodes.Get(i), ueDev->GetImsi());
    }
  ulTracker.ConnectTrace();
  ulTracker.Start();

  // --- Minimal traffic, both directions, just to get non-zero stats ---
  uint16_t dlPort = 5000;
  uint16_t ulPort = 5001;
  ApplicationContainer serverApps, clientApps;

  for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
      OnOffHelper dl("ns3::UdpSocketFactory", InetSocketAddress(ueIpIface.GetAddress(i), dlPort));
      dl.SetAttribute("DataRate", StringValue("5Mbps"));
      dl.SetAttribute("PacketSize", UintegerValue(512));
      ApplicationContainer dlApp = dl.Install(remoteHost);
      dlApp.Start(Seconds(1.0));
      dlApp.Stop(Seconds(simTime));
      clientApps.Add(dlApp);

      OnOffHelper ul("ns3::UdpSocketFactory", InetSocketAddress(remoteHostAddr, ulPort));
      ul.SetAttribute("DataRate", StringValue("5Mbps"));
      ul.SetAttribute("PacketSize", UintegerValue(512));
      ApplicationContainer ulApp = ul.Install(ueNodes.Get(i));
      ulApp.Start(Seconds(1.0));
      ulApp.Stop(Seconds(simTime));
      clientApps.Add(ulApp);
    }

  PacketSinkHelper dlSink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), dlPort));
  for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
      serverApps.Add(dlSink.Install(ueNodes.Get(i)));
    }
  PacketSinkHelper ulSink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), ulPort));
  serverApps.Add(ulSink.Install(remoteHost));

  serverApps.Start(Seconds(0.5));
  serverApps.Stop(Seconds(simTime));

  std::cout << "[test_oran_e2_logging] running " << simTime << "s with " << nUe
            << " UEs, E2 target " << ricAddr << ":" << ricPort << std::endl;

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();

  std::cout << "[test_oran_e2_logging] done -- check du-cell-*.txt (native DL KPM) "
            << "and ue_ul_traffic.csv (our UL tracker) in the cwd" << std::endl;

  return 0;
}
