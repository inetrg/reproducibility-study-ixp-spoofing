#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <queue>
#include <utility>
#include <vector>

#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"

#include "caf/all.hpp"
#include "caf/io/all.hpp"

#include <boost/iostreams/filter/bzip2.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <fstream>

#include "customer_cone/client/client.hpp"
#include "customer_cone/sample.hpp"
#include "customer_cone/server/server.hpp"
#include "customer_cone/utils/string.hpp"

using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::vector;

using namespace caf;
using namespace caf::io;

using namespace customer_cone;
using namespace client;
using namespace utils::str;

namespace {

class config : public actor_system_config {

public:
  u_int16_t port = 1234;
  std::string hostname = "127.0.0.1";
  std::string input_path = "";
  std::string output_path = "";
  std::string pattern = "";
  std::string prefixes = "";
  std::string bgp_relations = "";
  std::string caida_relations = "";
  std::string asn_mac_mapping = "";
  uint32_t skip_asn = 0;
  uint32_t num_worker = 4;
  string mode;
  bool read_prefixes = false;
  bool read_relations = false;
  bool check = false;
  bool allow_transitive_p2p = false;

  config() {
    add_message_type<classification_type>("classification_type");
    add_message_type<std::pair<uint64_t, classification_type>>(
      "classification_pair");
    opt_group{custom_options_, "global"}
      .add(port, "port, P", "set port (default 1234)")
      .add(hostname, "hostname, H", "set hostname (default 127.0.0.1)")
      .add(input_path, "input_path, i", "path to sflow files")
      .add(output_path, "output_path, o", "output path")
      .add(prefixes, "prefixes,p", "prefixes as gzip file")
      .add(bgp_relations, "bgp_relations, b", "as relations as gzip file")
      .add(caida_relations, "caida_relations,c", "import CAIDA as relations as bzip file ")
      .add(pattern, "pattern,s", R"(search pattern like "2019-04-01-.*\.pcap")")
      .add(skip_asn, "skip_asn", "skip relations import with given ASN")
      .add(asn_mac_mapping, "ass_mac_mapping,M",
           "asn to mac mapping as file asn; mac1,mac2\\n")
      .add(read_prefixes, "read_prefixes, F", R"(except lines like "'9.9.9.9,10\n" in client_stdin mode)")
      .add(read_relations, "read_relations, R",
           R"(except "c2p,1,2\n" or "p2p,1,2\n" in client_stdin mode)")
        .add(check, "check,C",
             R"(except lines like "9.9.9.9,1\n" in client_stdin mode)")
      .add(allow_transitive_p2p, "allow_transitive_p2p,T",
           "set transitive_p2p (default false)")
      .add(mode, "mode,m",
           R"(one of "server", "client" or "client_stdin")")
    .add(num_worker, "num_worker,w",
         "Number of worker (default 4)");
  }
};

// -- SERVER -------------------------------------------------------------------
void run_server(actor_system& sys, const config& cfg) {
  {
    scoped_actor self{sys};
    auto cc = sys.spawn(customer_cone::server::server_behav);
    auto port
      = sys.middleman().publish(cc, cfg.port, cfg.hostname.c_str(), true);
    if (port)
      cout << "server is running in caf mode on port "
           << std::to_string(port.value()) << endl;
    else {
      std::cout << "can`t  connect to server" << std::endl;
      exit(1);
    }
  }
  sys.await_all_actors_done();
  cout << "press any key to exit" << std::endl;
  getc(stdin);
}

// -- CLIENT -------------------------------------------------------------------
void run_client(actor_system& sys, const config& cfg) {
  if (((cfg.input_path.empty() || cfg.output_path.empty()
        || cfg.pattern.empty())
       && (cfg.prefixes.empty() && cfg.bgp_relations.empty()
           && cfg.caida_relations.empty()))
      || ((cfg.prefixes.empty() && cfg.bgp_relations.empty()
           && cfg.caida_relations.empty())
          && (cfg.input_path.empty() || cfg.output_path.empty()
              || cfg.pattern.empty()))) {
    cout << "you must start the program with -i <path to your sflow files> "
         << "-o <output path> -s <search pattern> or -prefixes "
         << "<path to 20190301-prefixes.gz> or -b <path relations.gz> or "
         << "-c <path relations>" << endl;
    exit(1);
  }

  auto server = sys.middleman().remote_actor(cfg.hostname, cfg.port);
  if (!server) {
    std::cout << "can`t  connect to server" << std::endl;
    exit(1);
  }
  std::cout << "Connected to " << cfg.hostname << ":" << cfg.port << "\n"
            << std::endl;
  {
    scoped_actor self{sys};

    if (!cfg.prefixes.empty()) {
      std::ifstream file(cfg.prefixes,
                         std::ios_base::in | std::ios_base::binary);
      boost::iostreams::filtering_istream in;
      in.push(boost::iostreams::gzip_decompressor());
      in.push(file);
      vector<string> prefixes;
      vector<string> s_line;
      uint32_t asn;
      char* end;
      for (std::string str; std::getline(in, str);) {
        s_line = split(str, ':');
        trim(s_line[0]);
        asn = static_cast<uint32_t>(std::strtol(s_line[0].c_str(), &end, 10));
        prefixes = split(split(str, ' ')[1], ',');
        for (auto p : prefixes) {
          trim(p);
          self
            ->request(*server, infinite, server::add_prefix_atom::value, p, asn)
            .receive(
              [&](bool r) {
                if (!r)
                  aout(self) << p << " not added for " << asn << endl;
              },
              [&](error& err) {
                aout(self) << self->system().render(err) << endl;
              });
        }
      }
    } else if (!cfg.bgp_relations.empty()) {
      std::ifstream file(cfg.bgp_relations,
                         std::ios_base::in | std::ios_base::binary);
      boost::iostreams::filtering_istream in;
      in.push(boost::iostreams::gzip_decompressor());
      in.push(file);
      vector<string> bgp_relations;
      vector<string> s_line;
      uint32_t p;
      uint32_t c;
      char* end;
      for (std::string str; std::getline(in, str);) {
        s_line = split(str, ' ');
        trim(s_line[0]);
        trim(s_line[1]);
        p = static_cast<uint32_t>(std::strtol(s_line[0].c_str(), &end, 10));
        c = static_cast<uint32_t>(std::strtol(s_line[1].c_str(), &end, 10));
        if (cfg.skip_asn > 0 && (cfg.skip_asn == c || cfg.skip_asn == p))
          continue;
        self->request(*server, infinite, server::add_c2p_atom::value, c, p)
          .receive(
            [&](bool r) {
              if (!r)
                aout(self) << c << " c2p " << p << " not added" << endl;
            },
            [&](error& err) {
              aout(self) << self->system().render(err) << endl;
            });
      }
    } else if (!cfg.caida_relations.empty()) {
      vector<string> bgp_relations;
      vector<string> s_line;
      uint32_t p;
      uint32_t c;
      char* end;

      std::ifstream file(cfg.caida_relations,
                         std::ios_base::in | std::ios_base::binary);

      boost::iostreams::filtering_istream in;

      in.push(boost::iostreams::bzip2_decompressor());
      in.push(file);

      for (string str; getline(in, str);) {
        if (str.find('#') != string::npos) {
          continue;
        }
        s_line = split(str, '|');
        trim(s_line[0]);
        trim(s_line[1]);
        p = static_cast<uint32_t>(std::strtol(s_line[0].c_str(), &end, 10));
        c = static_cast<uint32_t>(std::strtol(s_line[1].c_str(), &end, 10));
        if (cfg.skip_asn > 0 && (cfg.skip_asn == c || cfg.skip_asn == p))
          continue;
        if (s_line[2] == "-1") {
          self->request(*server, infinite, server::add_c2p_atom::value, c, p)
            .receive(
              [&](bool r) {
                if (!r)
                  aout(self) << c << " c2p " << p << " not added" << endl;
              },
              [&](error& err) {
                aout(self) << self->system().render(err) << endl;
              });
        } else if (s_line[2] == "0") {
          self->request(*server, infinite, server::add_p2p_atom::value, c, p)
            .receive(
              [&](bool r) {
                if (!r) {
                  aout(self) << c << " p2p " << p << " not added" << endl;
                }
              },
              [&](error& err) {
                aout(self) << self->system().render(err) << endl;
              });
        }
      }

      // Cleanup
      file.close();
    } else if (!(cfg.input_path.empty() || cfg.output_path.empty()
                 || cfg.pattern.empty())
               || cfg.asn_mac_mapping.empty()) {

      auto c = sys.spawn(client_behav, *server, cfg.input_path, cfg.output_path,
                         cfg.pattern, cfg.asn_mac_mapping, cfg.num_worker);

      self->send(c, collect_sflow_files_atom::value);
    }
  }

  sys.await_all_actors_done();
} // namespace

// -- Client-read-from-stdin
// -------------------------------------------------------------------
void run_client_stdin(actor_system& sys, const config& cfg) {
  auto server = sys.middleman().remote_actor(cfg.hostname, cfg.port);
  if (!server) {
    std::cout << "can`t  connect to server" << std::endl;
    exit(1);
  }
  std::cout << "Connected to " << cfg.hostname << ":" << cfg.port << "\n"
            << std::endl;
  {
    scoped_actor self{sys};

    vector<string> s_line;
    uint32_t asn;
    char* end;
    uint32_t p;
    uint32_t c;

    for (std::string line; std::getline(std::cin, line);) {
      if (line.empty()) {
        break;
      } else if (line == "\n") {
        continue;
      }
      line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
      s_line = split(line, ',');
      if (cfg.read_prefixes) {
        // 9.9.9.0/24,9
        trim(s_line[0]);
        trim(s_line[1]);
        asn = static_cast<uint32_t>(std::strtol(s_line[1].c_str(), &end, 10));
        self
          ->request(*server, infinite, server::add_prefix_atom::value,
                    s_line[0], asn)
          .receive(
            [&](bool r) {
              if (!r)
                aout(self) << s_line[0] << " not added for" << asn << endl;
            },
            [&](error& err) {
              aout(self) << self->system().render(err) << endl;
            });
      } else if (cfg.read_relations) {
        // c2p,1,2\n or p2p,1,2\\n
        trim(s_line[0]);
        trim(s_line[1]);
        trim(s_line[2]);
        c = static_cast<uint32_t>(std::strtol(s_line[1].c_str(), &end, 10));
        p = static_cast<uint32_t>(std::strtol(s_line[2].c_str(), &end, 10));
        if (cfg.skip_asn > 0 && (cfg.skip_asn == c || cfg.skip_asn == p))
          continue;
        if (s_line[0] == "c2p") {
          self->request(*server, infinite, server::add_c2p_atom::value, c, p)
            .receive(
              [&](bool r) {
                if (!r)
                  aout(self) << c << " c2p " << p << " not added" << endl;
              },
              [&](error& err) {
                aout(self) << self->system().render(err) << endl;
              });
        } else if (s_line[0] == "p2p") {
          self->request(*server, infinite, server::add_p2p_atom::value, c, p)
            .receive(
              [&](bool r) {
                if (!r) {
                  aout(self) << c << " p2p " << p << " not added" << endl;
                }
              },
              [&](error& err) {
                aout(self) << self->system().render(err) << endl;
              });
        }
      } else if (cfg.check) {
        // 9.9.9.9,1
        trim(s_line[0]);
        trim(s_line[1]);
        asn = static_cast<uint32_t>(std::strtol(s_line[1].c_str(), &end, 10));
        self
          ->request(*server, infinite, server::ip_in_cone_atom::value,
                    s_line[0], asn)
          .receive(
            [&](classification_type r) {
              aout(self) << line << ":" << to_string(r) << endl;
            },
            [&](error& err) {
              aout(self) << self->system().render(err) << endl;
            });
      }
    }
  }

  sys.await_all_actors_done();
}
// -- MAIN
// ---------------------------------------------------------------------
void caf_main(actor_system& sys, const config& cfg) {
  using map_t = std::map<string, void (*)(actor_system&, const config&)>;
  map_t modes{
    {"server", run_server},
    {"client", run_client},
    {"client_stdin", run_client_stdin},
  };
  auto i = modes.find(cfg.mode);
  if (i != modes.end())
    (i->second)(sys, cfg);
  else
    cerr << "*** invalid mode specified" << endl;
}

} // namespace
CAF_MAIN(io::middleman)
