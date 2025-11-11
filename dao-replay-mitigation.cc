/* dao-replay-mitigation.cc
 * Deterministic replay demo for DAO replay mitigation with metrics.
 *
 * Sensors send DAOs; Sensor 0 is compromised and replays its own DAOs.
 * The root applies freshness checks (seq + timestamp + burst filters).
 * The root records metrics (total/accepted/rejected DAOs, inter-arrival delays)
 * and writes a CSV `dao_metrics.csv` plus a console summary at the end.
 *
 * Compatible with ns-3.45 (use ./ns3 build/run).
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv6-address-helper.h"
#include "ns3/ipv6-static-routing-helper.h"
#include "ns3/point-to-point-module.h"
#include "ns3/global-route-manager.h"

#include <map>
#include <sstream>
#include <vector>
#include <fstream>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DaoReplayMitigation");

// ---------------------- Payload helpers ----------------------------------
struct DaoPayload { uint32_t seq; uint64_t tsSeconds; uint64_t tsNano; };

std::string SerializeDao(const DaoPayload &p) {
  std::ostringstream oss;
  oss << "DAO:" << p.seq << ":" << p.tsSeconds << ":" << p.tsNano;
  return oss.str();
}

bool DeserializeDao(const std::string &s, DaoPayload &out) {
  std::istringstream iss(s);
  std::string tag, seqs, secs, nanos;
  if (!std::getline(iss, tag, ':') || tag != "DAO") return false;
  if (!std::getline(iss, seqs, ':') || !std::getline(iss, secs, ':') || !std::getline(iss, nanos, ':'))
    return false;
  try {
    out.seq = std::stoul(seqs);
    out.tsSeconds = std::stoull(secs);
    out.tsNano = std::stoull(nanos);
  } catch (...) { return false; }
  return true;
}

// Forward-declare attacker for optional deterministic snoop (not used here)
class DaoAttackerApp;
static DaoAttackerApp* g_attackerApp = nullptr; // used in other variants; unused in this file

// ---------------------- DaoSenderApp (sensor) --------------------------------
class DaoSenderApp : public Application {
public:
  DaoSenderApp() : m_socket(0), m_peer(), m_mirror(), m_seq(1), m_interval(Seconds(10)) {}
  virtual ~DaoSenderApp() { m_socket = 0; }

  void Setup(Address rootAddr, Address mirrorAddr, uint32_t startSeq, Time interval) {
    m_peer = rootAddr; m_mirror = mirrorAddr; m_seq = startSeq; m_interval = interval;
  }

private:
  virtual void StartApplication() override {
    if (!m_socket) {
      m_socket = Socket::CreateSocket(GetNode(), TypeId::LookupByName("ns3::UdpSocketFactory"));
      m_socket->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));
    }
    // randomized initial offset
    m_sendEvent = Simulator::Schedule(Seconds(1.0 + (double)rand() / RAND_MAX), &DaoSenderApp::SendDao, this);
  }

  virtual void StopApplication() override {
    if (m_sendEvent.IsPending()) Simulator::Cancel(m_sendEvent);
    if (m_socket) {
      m_socket->Close();
    }
  }

  void SendDao() {
    Time now = Simulator::Now();
    DaoPayload p;
    p.seq = m_seq++;
    p.tsSeconds = (uint64_t) now.GetSeconds();
    p.tsNano = (uint64_t) now.GetNanoSeconds();

    std::string payload = SerializeDao(p);
    Ptr<Packet> packet = Create<Packet>((const uint8_t*)payload.c_str(), payload.size());

    // Send to primary (root)
    m_socket->SendTo(packet, 0, m_peer);

    // Also send an identical copy to secondary (attacker) if set (UDP mirror)
    if (m_mirror != Address()) {
      Ptr<Packet> copyPkt = Create<Packet>((const uint8_t*)payload.c_str(), payload.size());
      m_socket->SendTo(copyPkt, 0, m_mirror);
    }

    NS_LOG_INFO("Sensor " << GetNode()->GetId() << " sent DAO seq=" << p.seq << " at t=" << now.GetSeconds());

    m_sendEvent = Simulator::Schedule(m_interval, &DaoSenderApp::SendDao, this);
  }

  Ptr<Socket> m_socket;
  EventId m_sendEvent;
  Address m_peer;
  Address m_mirror;
  uint32_t m_seq;
  Time m_interval;
};

// ---------------------- DaoAttackerApp (Compromised Sensor 0) -----------------------------------
class DaoAttackerApp : public Application {
public:
  DaoAttackerApp()
    : m_socket(0), m_listen(), m_peer(), m_payload(), m_replayCount(100), m_remaining(0), m_gap(Seconds(0.01)) {}
  virtual ~DaoAttackerApp() { m_socket = 0; }

  void Setup(Address listen, Address forward, uint32_t count, Time gap) {
    m_listen = listen; m_peer = forward; m_replayCount = count; m_gap = gap;
  }

private:
  virtual void StartApplication() override {
    if (!m_socket) {
      m_socket = Socket::CreateSocket(GetNode(), TypeId::LookupByName("ns3::UdpSocketFactory"));
      m_socket->Bind(m_listen);
      m_socket->SetRecvCallback(MakeCallback(&DaoAttackerApp::Capture, this));
    }
  }

  virtual void StopApplication() override {
    if (m_socket) {
      m_socket->Close();
    }
    if (m_replayEvent.IsPending()) Simulator::Cancel(m_replayEvent);
  }

  void Capture(Ptr<Socket> s) {
    Address from; Ptr<Packet> pkt;
    while ((pkt = s->RecvFrom(from))) {
      uint32_t len = pkt->GetSize();
      std::vector<uint8_t> buf(len);
      pkt->CopyData(buf.data(), len);
      std::string payload((char*)buf.data(), len);
      if (m_payload.empty()) {
        m_payload = payload;
        m_remaining = m_replayCount;
        // schedule a small delay before starting replay storm
        m_replayEvent = Simulator::Schedule(Seconds(0.05), &DaoAttackerApp::ReplayOnce, this);
        NS_LOG_WARN("Attacker (Sensor 0) captured DAO; starting replay storm...");
      }
    }
  }

  void ReplayOnce() {
    if (m_remaining == 0) return;

    // Use a temporary send socket so we don't conflict with the receive socket binding.
    Ptr<Socket> sendSocket = Socket::CreateSocket(GetNode(), TypeId::LookupByName("ns3::UdpSocketFactory"));
    sendSocket->Bind(Inet6SocketAddress(Ipv6Address::GetAny(), 0));

    Ptr<Packet> pkt = Create<Packet>((uint8_t*)m_payload.c_str(), m_payload.size());
    sendSocket->SendTo(pkt, 0, m_peer);
    sendSocket->Close();

    NS_LOG_WARN("Attacker (Sensor 0) replayed captured DAO, remaining=" << --m_remaining);
    if (m_remaining > 0) {
      m_replayEvent = Simulator::Schedule(m_gap, &DaoAttackerApp::ReplayOnce, this);
    }
  }

  Ptr<Socket> m_socket;
  Address m_listen;
  Address m_peer;
  std::string m_payload;
  uint32_t m_replayCount;
  uint32_t m_remaining;
  Time m_gap;
  EventId m_replayEvent;
};

// ---------------------- DaoRootReceiverApp (with metrics) -------------------------------
class DaoRootReceiverApp : public Application {
public:
  DaoRootReceiverApp()
    : m_socket(0),
      m_listen(),
      m_thresh(Seconds(0.2)),
      m_totalDaos(0),
      m_acceptedDaos(0),
      m_rejectedDaos(0)
  {}

  virtual ~DaoRootReceiverApp() {
    // Print and persist metrics when the application object is destroyed (after Simulator::Destroy)
    // Avoid dividing by zero when no data exists
    double avgDelay = 0.0;
    uint64_t sampleCount = 0;
    for (auto &kv : m_interArrivals) {
      for (double d : kv.second) {
        avgDelay += d;
        ++sampleCount;
      }
    }
    if (sampleCount > 0) avgDelay /= (double)sampleCount;

    double rejectRatio = 0.0;
    if (m_totalDaos > 0) rejectRatio = (double)m_rejectedDaos * 100.0 / (double)m_totalDaos;

    // Append to CSV (create if missing)
    std::ofstream out("dao_metrics.csv", std::ios::app);
    if (out.is_open()) {
      // Write a simple header if file is empty — best-effort (no atomic check for simplicity)
      // We will always append a record row.
      out << m_totalDaos << "," << m_acceptedDaos << "," << m_rejectedDaos << "," << std::fixed << std::setprecision(2) << rejectRatio << "," << avgDelay << "\n";
      out.close();
    }

    // Console summary
    std::cout << std::endl;
    std::cout << "========== DAO Replay Mitigation Metrics ==========" << std::endl;
    std::cout << "Total DAOs received: " << m_totalDaos << std::endl;
    std::cout << "Accepted DAOs:       " << m_acceptedDaos << std::endl;
    std::cout << "Rejected DAOs:       " << m_rejectedDaos << std::endl;
    std::cout << "Replay rejection %:  " << std::fixed << std::setprecision(2) << rejectRatio << std::endl;
    std::cout << "Average inter-arrival delay (s): " << avgDelay << std::endl;
    std::cout << "===================================================" << std::endl;
  }

  void Setup(Address listen, Time threshold) {
    m_listen = listen;
    m_thresh = threshold;
  }

private:
  virtual void StartApplication() override {
    if (!m_socket) {
      m_socket = Socket::CreateSocket(GetNode(), TypeId::LookupByName("ns3::UdpSocketFactory"));
      m_socket->Bind(m_listen);
      m_socket->SetRecvCallback(MakeCallback(&DaoRootReceiverApp::HandleRead, this));
    }
  }

  virtual void StopApplication() override {
    if (m_socket) m_socket->Close();
  }

  void HandleRead(Ptr<Socket> s) {
    Address from; Ptr<Packet> pkt;
    while ((pkt = s->RecvFrom(from))) {
      uint32_t len = pkt->GetSize();
      std::vector<uint8_t> buf(len);
      pkt->CopyData(buf.data(), len);
      std::string data((char*)buf.data(), len);

      DaoPayload p;
      if (!DeserializeDao(data, p)) {
        NS_LOG_ERROR("Root: malformed DAO payload");
        continue;
      }

      Ipv6Address sender = Inet6SocketAddress::ConvertFrom(from).GetIpv6();
      Time now = Simulator::Now();

      // Metrics: inter-arrival per-sender
      ++m_totalDaos;
      if (m_prevArrival.count(sender) > 0) {
        double delta = (now - m_prevArrival[sender]).GetSeconds();
        m_interArrivals[sender].push_back(delta);
      }
      m_prevArrival[sender] = now;

      bool accept = CheckFresh(sender, p, now);
      if (accept) {
        ++m_acceptedDaos;
        NS_LOG_INFO("Root: ACCEPT DAO from " << sender << " seq=" << p.seq);
      } else {
        ++m_rejectedDaos;
        NS_LOG_WARN("Root: REJECT DAO from " << sender << " seq=" << p.seq << " (replay detected)");
      }
    }
  }

  // Anti-replay logic (sequence + timestamp + burst window)
  bool CheckFresh(const Ipv6Address &sender, const DaoPayload &p, Time arrivalTime) {
    Time origTs = Seconds(p.tsSeconds) + NanoSeconds(p.tsNano);

    if (m_lastSeq.count(sender) > 0) {
      uint32_t lastSeq = m_lastSeq[sender];
      Time lastOrig = m_lastOrig[sender];
      Time lastArrival = m_lastArrival[sender];

      if (p.seq < lastSeq) {
        // Old sequence — replay or stale
        NS_LOG_DEBUG("Reject: seq < lastSeq");
        return false;
      }

      if (p.seq == lastSeq) {
        // Same sequence — could be duplicate or replay
        if (origTs == lastOrig) {
          NS_LOG_DEBUG("Reject: same seq and identical origTs");
          return false;
        }
        if (arrivalTime - lastArrival < m_thresh) {
          NS_LOG_DEBUG("Reject: arrival too fast after last (burst)");
          return false;
        }
      }

      if (origTs < lastOrig) {
        NS_LOG_DEBUG("Reject: origTs older than lastOrig");
        return false;
      }
    }

    // Accept and update state
    m_lastSeq[sender] = p.seq;
    m_lastOrig[sender] = origTs;
    m_lastArrival[sender] = arrivalTime;
    return true;
  }

  Ptr<Socket> m_socket;
  Address m_listen;
  Time m_thresh;

  // Metrics
  uint32_t m_totalDaos;
  uint32_t m_acceptedDaos;
  uint32_t m_rejectedDaos;
  std::map<Ipv6Address, Time> m_prevArrival;
  std::map<Ipv6Address, std::vector<double>> m_interArrivals;

  // Anti-replay state
  std::map<Ipv6Address, uint32_t> m_lastSeq;
  std::map<Ipv6Address, Time> m_lastOrig;
  std::map<Ipv6Address, Time> m_lastArrival;
};

// ---------------------- main ---------------------------------------------
int main(int argc, char *argv[]) {
  CommandLine cmd;
  uint32_t nSensors = 3;
  bool enableAttacker = true;
  double simTime = 25.0;
  cmd.AddValue("nSensors", "Number of sensors (excluding root)", nSensors);
  cmd.AddValue("enableAttacker", "Enable attacker (Sensor 0)", enableAttacker);
  cmd.AddValue("simTime", "Simulation time (s)", simTime);
  cmd.Parse(argc, argv);

  // nodes: sensors (0..nSensors-1) + root (nSensors)
  NodeContainer nodes;
  nodes.Create(nSensors + 1);
  Ptr<Node> root = nodes.Get(nSensors);     // root node
  Ptr<Node> attackerNode = nodes.Get(0);    // attacker resides on sensor 0

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("5ms"));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv6AddressHelper ipv6;
  std::vector<Ipv6InterfaceContainer> ifs;
  for (uint32_t i = 0; i < nSensors; ++i) {
    NodeContainer link;
    link.Add(nodes.Get(i));
    link.Add(root);
    NetDeviceContainer dev = p2p.Install(link);
    std::ostringstream subnet;
    subnet << "2001:db8:0:" << i << "::";
    ipv6.SetBase(Ipv6Address(subnet.str().c_str()), Ipv6Prefix(64));
    Ipv6InterfaceContainer ipc = ipv6.Assign(dev);
    ipc.SetForwarding(0, true);
    ipc.SetDefaultRouteInAllNodes(0);
    ifs.push_back(ipc);
  }

  Ipv6Address rootAddr = ifs[0].GetAddress(1, 1);
  Ipv6Address sensor0Addr = ifs[0].GetAddress(0, 1); // sensor 0 IP
  uint16_t rootPort = 12345;
  uint16_t mirrorPort = 54321;

  NS_LOG_INFO("Root addr=" << rootAddr << " Sensor0 addr=" << sensor0Addr);

  // Install root receiver
  Ptr<DaoRootReceiverApp> rootApp = CreateObject<DaoRootReceiverApp>();
  rootApp->Setup(Inet6SocketAddress(rootAddr, rootPort), Seconds(0.2)); // 0.2s threshold
  root->AddApplication(rootApp);
  rootApp->SetStartTime(Seconds(0.5));
  rootApp->SetStopTime(Seconds(simTime));

  // Install sensor sender apps
  for (uint32_t i = 0; i < nSensors; ++i) {
    Ptr<DaoSenderApp> sender = CreateObject<DaoSenderApp>();
    Address mirror = Address();
    if (i == 0) {
      // sensor 0 mirrors to its own mirror port (attacker listens here)
      mirror = Inet6SocketAddress(sensor0Addr, mirrorPort);
    }
    sender->Setup(Inet6SocketAddress(rootAddr, rootPort), mirror, 1 + i * 100, Seconds(10.0 + i));
    nodes.Get(i)->AddApplication(sender);
    sender->SetStartTime(Seconds(2.0 + i));
    sender->SetStopTime(Seconds(simTime));
  }

  // Attacker app on sensor 0 (listens on mirror port and replays to root)
  if (enableAttacker) {
    Ptr<DaoAttackerApp> atk = CreateObject<DaoAttackerApp>();
    atk->Setup(Inet6SocketAddress(sensor0Addr, mirrorPort), Inet6SocketAddress(rootAddr, rootPort), 100, Seconds(0.01));
    attackerNode->AddApplication(atk);
    atk->SetStartTime(Seconds(3.0));
    atk->SetStopTime(Seconds(simTime));
  }

  // Build simple routing (global)
  GlobalRouteManager::BuildGlobalRoutingDatabase();
  GlobalRouteManager::InitializeRoutes();

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();
  return 0;
}

