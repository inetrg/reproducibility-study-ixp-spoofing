#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/range/iterator_range_core.hpp>

using std::regex;
using std::regex_match;
using std::set;
using std::string;
using std::vector;

using namespace boost;
using namespace boost::filesystem;

namespace {
void get_files_recursive(set<string>& files, const string& path_str,
                         const regex& reg) {

  path p{path_str};
  if (exists(p)) {
    if (is_regular_file(p) && regex_search(p.filename().string(), reg)) {
      files.insert(p.string());
    } else if (is_directory(p)) {
      for (const auto& x : make_iterator_range(directory_iterator(p), {})) {
        if (is_directory(x))
          get_files_recursive(files, x.path().string(), reg);
        else if (is_regular_file(x)
                 && regex_search(x.path().filename().string(), reg))
          files.insert(x.path().string());
      }
    }
  }
}
} // namespace

namespace customer_cone {
namespace utils {
namespace filesystem {

vector<string> get_files(const string& path_str, const string& pattern) {
  set<string> files;
  regex reg{pattern};

  get_files_recursive(files, path_str, reg);

  return vector<string>(files.begin(), files.end());
}

} // namespace filesystem
} // namespace utils
} // namespace customer_cone