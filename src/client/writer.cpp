#include <fstream>
#include <iostream>

#include "customer_cone/client/writer.hpp"
#include "customer_cone/sample.hpp"

using namespace std;
using caf::expected;

namespace customer_cone {
namespace client {
writer::writer(const string& path, const string& f_name) {
  auto tmp = f_name;
  if (f_name.substr(f_name.find_last_of('.') + 1) != "gz") {
    tmp = f_name + ".gz";
  }

  file = gzopen((path + "/" + tmp).c_str(), "wb");
}
writer::~writer() {
  gzclose(file);
}

void writer::sample_to_disk(const shared_ptr<sample>& sample) {
  gzprintf(file, sample->line_rep().c_str());
}
} // namespace client
} // namespace customer_cone